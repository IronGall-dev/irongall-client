package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/protocol"
)

// hexID is a message id as the server names it: the lowercase hex SHA-256 of
// the ciphertext. An id that is not one never touches a file name.
var hexID = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

// Delivery is a message that passed every check.
type Delivery struct {
	ID       string // the server's id for it
	Envelope *protocol.Envelope
	// Plaintext is the envelope exactly as decrypted, as kept in inbox/.
	Plaintext []byte
}

// Refusal is a message that failed a check. It was quarantined, never
// delivered, and acked so that it leaves the server. It never blocks its
// claimed sender: a forgery may be the operator framing them.
type Refusal struct {
	ID     string
	Reason string
}

// Result is what one Receive did.
type Result struct {
	Delivered []Delivery
	// Duplicates are re-encrypted retries of messages already delivered:
	// acked, not delivered again.
	Duplicates []string
	Refused    []Refusal
	// PollAfter is the server's poll interval, in seconds.
	PollAfter int
}

// Receive drains the box: every page, every message. Each message is judged
// by one gate (see [Box.judge]); only one that passes every check is
// delivered, to inbox/ and the Result. Refused mail goes to quarantine/. Both
// are acked. A transient error stops the drain and leaves the rest for the
// next one. One consumer per box: a second concurrent Receive is refused.
func (b *Box) Receive(ctx context.Context) (*Result, error) {
	l, err := b.lock()
	if err != nil {
		return nil, err
	}
	res, err := b.drain(ctx)
	if e := l.release(); err == nil {
		err = e
	}
	if e := b.Prune(); err == nil {
		err = e
	}
	return res, err
}

func (b *Box) drain(ctx context.Context) (*Result, error) {
	res := &Result{}
	if err := b.pruneSeen(); err != nil {
		return nil, err
	}
	etag, _ := os.ReadFile(b.path("etag"))
	cursor := ""
	for first := true; ; first = false {
		hdr := http.Header{}
		path := b.boxPath("/messages")
		if first && len(etag) > 0 {
			hdr.Set("If-None-Match", string(etag))
		}
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		var list protocol.MessageList
		resp, err := b.owner(ctx, http.MethodGet, path, hdr, &list)
		if err != nil {
			return res, err
		}
		if resp.StatusCode == http.StatusNotModified {
			return res, nil
		}
		res.PollAfter = list.PollAfter
		if first {
			// Kept only for an empty box, so a 304 can never hide mail
			// this client has not handled.
			if t := resp.Header.Get("ETag"); list.Count == 0 && t != "" {
				if err := writeFile(b.path("etag"), []byte(t)); err != nil {
					return res, err
				}
			} else if err := removeIfExists(b.path("etag")); err != nil {
				return res, err
			}
		}
		for _, m := range list.Messages {
			if !hexID.MatchString(m.ID) {
				continue
			}
			if err := b.receiveOne(ctx, m.ID, res); err != nil {
				return res, err
			}
		}
		if list.NextCursor == nil || *list.NextCursor == "" {
			return res, nil
		}
		cursor = *list.NextCursor
	}
}

// receiveOne judges one message unless its id was already handled, stores
// the verdict, and acks it. An error is transient: the message stays on the
// server for the next drain.
func (b *Box) receiveOne(ctx context.Context, id string, res *Result) error {
	handled, err := b.seenHash(id)
	if err != nil {
		return err
	}
	if !handled {
		var m protocol.Message
		_, err := b.owner(ctx, http.MethodGet, b.boxPath("/messages/"+id), nil, &m)
		if Code(err) == protocol.CodeNoSuchMessage {
			return nil // already gone
		}
		if err != nil {
			return err
		}
		if err := b.fetchSenderIdentity(ctx, m.From); err != nil {
			return err
		}
		d, dup, why := b.judge(&m)
		switch {
		case why != "":
			raw, err := json.Marshal(m)
			if err != nil {
				return err
			}
			if err := writeFile(b.path("quarantine", id+".json"), raw); err != nil {
				return err
			}
			res.Refused = append(res.Refused, Refusal{ID: id, Reason: why})
		case dup:
			res.Duplicates = append(res.Duplicates, id)
		default:
			// Stored before it is recorded as seen, and both before the
			// ack: a crash in between delivers it again, never loses it.
			if err := writeFile(b.path("inbox", id+".json"), d.Plaintext); err != nil {
				return err
			}
			if err := b.recordSeen(m.Ciphertext, d.Envelope); err != nil {
				return err
			}
			d.ID = id
			res.Delivered = append(res.Delivered, *d)
		}
	}
	_, err = b.owner(ctx, http.MethodDelete, b.boxPath("/messages/"+id), nil, nil)
	if Code(err) == protocol.CodeNoSuchMessage {
		return nil
	}
	return err
}

// fetchSenderIdentity fetches the claimed sender's identity at first contact,
// so judge can pin it. A sender that is not an address is left to judge.
func (b *Box) fetchSenderIdentity(ctx context.Context, from string) error {
	a, err := protocol.ParseAddress(from)
	if err != nil {
		return nil
	}
	if exists(b.path("peers", a.String(), "identity.doc")) {
		return nil
	}
	var ir json.RawMessage
	if _, err := b.call(ctx, http.MethodGet, "/v1/"+a.String()+"/identity", nil, nil, &ir); err != nil {
		if c := Code(err); c == protocol.CodeNoSuchMailbox || c == protocol.CodeRevoked {
			return nil // judge refuses: nothing to pin
		}
		return err
	}
	if err := os.MkdirAll(b.path("peers", a.String()), 0o700); err != nil {
		return err
	}
	// The response as served, as the recipe keeps it; judge pins from it.
	return writeFile(b.path("peers", a.String(), "identity.json"), ir)
}

// judge runs every check on one message, in this order, and returns the
// delivery only if all of them pass; otherwise why says which failed.
//
//  1. The sender is an address.
//  2. Its identity: the pin, or at first contact the served identity,
//     hash-checked against the address and then pinned.
//  3. The signature, by that identity, in this box's message namespace.
//  4. Decryption with every retained prekey.
//  5. The envelope: version 1, from is the verified signer, to is this box.
//  6. Freshness: sent_at no older than 8 days.
//  7. Replay: the locally computed ciphertext hash is not in the seen-set.
//  8. Retry: (from, msg_id) is not in the seen-set. A match is a duplicate.
func (b *Box) judge(m *protocol.Message) (d *Delivery, dup bool, why string) {
	from, err := protocol.ParseAddress(m.From)
	if err != nil {
		return nil, false, "the sender is not an address"
	}
	var ir protocol.IdentityResponse
	if j, err := os.ReadFile(b.path("peers", from.String(), "identity.json")); err == nil {
		_ = json.Unmarshal(j, &ir) // unreadable is unpinnable: pin refuses
	}
	id, err := b.pin(from, ir.Identity)
	if err != nil {
		return nil, false, reason(err)
	}
	me := b.id.Address()
	if err := protocol.Verify(id, m.Ciphertext, m.Signature, protocol.MessageNamespace(me)); err != nil {
		return nil, false, fmt.Sprintf("the signature does not verify for %s", from)
	}
	ids, err := b.prekeyIdentities()
	if err != nil {
		return nil, false, reason(err)
	}
	r, err := age.Decrypt(bytes.NewReader(m.Ciphertext), ids...)
	if err != nil {
		return nil, false, "it does not decrypt with this box's prekeys"
	}
	p, err := io.ReadAll(io.LimitReader(r, maxResponse))
	if err != nil {
		return nil, false, "it does not decrypt with this box's prekeys"
	}
	env, err := protocol.OpenEnvelope(p, from, me, b.now())
	if err != nil {
		return nil, false, err.Error()
	}
	h := sha256.Sum256(m.Ciphertext)
	seen, err := b.seenHash(hex.EncodeToString(h[:]))
	if err != nil {
		return nil, false, reason(err)
	}
	if seen {
		return nil, false, "replay: this ciphertext was already received"
	}
	again, err := b.seenMsgID(from, env.MsgID)
	if err != nil {
		return nil, false, reason(err)
	}
	if again {
		return nil, true, ""
	}
	return &Delivery{Envelope: env, Plaintext: p}, false, ""
}

func reason(err error) string {
	var r *RefusedError
	if errors.As(err, &r) {
		return r.Reason
	}
	return err.Error()
}

// The seen-set: one line per accepted message, "<ciphertext hash> <sent_at,
// unix seconds> <from> <msg_id>", kept until sent_at + 8 days, so the replay
// check and the freshness check cover the same 8 days.

func (b *Box) seenLines() ([][]string, error) {
	f, err := os.Open(b.path("seen"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	var lines [][]string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if fields := strings.Fields(s.Text()); len(fields) == 4 {
			lines = append(lines, fields)
		}
	}
	return lines, s.Err()
}

func (b *Box) seenHash(h string) (bool, error) {
	lines, err := b.seenLines()
	for _, l := range lines {
		if l[0] == h {
			return true, err
		}
	}
	return false, err
}

func (b *Box) seenMsgID(from protocol.Address, msgID string) (bool, error) {
	lines, err := b.seenLines()
	for _, l := range lines {
		if l[2] == from.String() && l[3] == msgID {
			return true, err
		}
	}
	return false, err
}

func (b *Box) recordSeen(ciphertext []byte, env *protocol.Envelope) error {
	h := sha256.Sum256(ciphertext)
	f, err := os.OpenFile(b.path("seen"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%x %d %s %s\n", h, env.SentAt.Unix(), env.From, env.MsgID); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error wins
		return err
	}
	return f.Close()
}

func (b *Box) pruneSeen() error {
	lines, err := b.seenLines()
	if err != nil || lines == nil {
		return err
	}
	cutoff := b.now().Add(-protocol.TTL).Unix()
	var out bytes.Buffer
	for _, l := range lines {
		if sa, err := strconv.ParseInt(l[1], 10, 64); err == nil && sa >= cutoff {
			out.WriteString(strings.Join(l, " ") + "\n")
		}
	}
	return writeFile(b.path("seen"), out.Bytes())
}
