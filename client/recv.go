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
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// hexID is a message id as the server names it: the lowercase hex SHA-256 of
// the ciphertext. An id that is not one never touches a file name.
var hexID = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

// Delivery is a message that passed every check.
type Delivery struct {
	ID       string // the SHA-256 of its ciphertext, as computed here
	Envelope *protocol.Envelope
	// Line is the envelope as ONE line of JSON, built by this client from the
	// checked fields (the identity document dropped), as kept in inbox/.
	// Print or pass on this, never Plaintext, whose bytes the sender chose.
	Line []byte
	// Plaintext is the envelope's line exactly as the sender signed it, and
	// Signature the signature block that verified over it: together they
	// show anyone that this sender wrote this to this box. The client keeps
	// neither on disk.
	Plaintext []byte
	Signature []byte
}

// Refusal is a message that failed a check. It was quarantined, never
// delivered, and acked so that it leaves the server. It never blocks its
// claimed sender: a forgery may be the operator framing them.
type Refusal struct {
	ID string
	// Code says which check failed: one of this package's Refused codes or
	// protocol's. Reason says it in this client's own words, which never
	// quote the message.
	Code   string
	Reason string
}

// Result is what one Receive did.
type Result struct {
	Delivered []Delivery
	// Duplicates are re-encrypted retries of messages already delivered:
	// acked, not delivered again.
	Duplicates []string
	Refused    []Refusal
	// More reports that the drain stopped at one of its limits (see
	// maxDrainMessages), or because the server paced it: the rest is still
	// on the server for the next Receive.
	More bool
	// Paced is how long the server asked the box to wait before taking out
	// more, when it paced the drain (a 429 with Retry-After); zero otherwise.
	Paced time.Duration
	// PollAfter is the server's poll interval, in seconds.
	PollAfter int
	// Renewed is the prekey this Receive published, the current one being
	// more than a day old; nil if none was due.
	Renewed *protocol.Prekey
	// RenewErr is why a due renewal failed. The drain went ahead, and a
	// later Receive tries again, at most hourly.
	RenewErr error
}

// Receive drains the box: every page, every message. Each message is judged
// by one gate (see [Box.judge]); only one that passes every check is
// delivered, to inbox/ and the Result. Refused mail goes to quarantine/. Both
// are acked. A transient error stops the drain and leaves the rest for the
// next one. One consumer per box: a second concurrent Receive is refused.
//
// First it renews the prekey if the current one is more than a day old, so
// a box received at least monthly never lapses. A drain that empties the box
// then deletes the retired prekeys no mail can still need (see
// [Box.dropRetired]): all but the newest.
func (b *Box) Receive(ctx context.Context) (*Result, error) {
	l, err := b.lock()
	if err != nil {
		return nil, err
	}
	began := b.now()
	renewed, renewErr := b.renewIfDue(ctx)
	res, err := b.drain(ctx)
	if res == nil {
		res = &Result{}
	}
	res.Renewed, res.RenewErr = renewed, renewErr
	// Only a drain that emptied the box may delete retired prekeys.
	if err == nil && !res.More {
		err = b.dropRetired(began)
	}
	if e := l.release(); err == nil {
		err = e
	}
	if e := b.Prune(); err == nil {
		err = e
	}
	return res, err
}

// A drain is bounded, so that a server which lists mail without end, or
// serves answers as large as it may, costs one Receive a known amount of
// time and disk at most. A drain that reaches a limit stops there: what is
// left stays on the server for the next Receive.
var (
	maxDrainMessages = 1000     // messages handled in one drain
	maxDrainBytes    = 64 << 20 // of ciphertext fetched in one drain
	maxDrainPages    = 100      // list pages followed in one drain
)

func (b *Box) drain(ctx context.Context) (*Result, error) {
	res := &Result{}
	if err := b.pruneSeen(); err != nil {
		return nil, err
	}
	// The senders this drain has asked the server about: one lookup each.
	asked := newLookups()
	etag, _ := os.ReadFile(b.path("etag"))
	cursor := ""
	messages, fetched := 0, 0
	for page := 0; ; page++ {
		if page == maxDrainPages {
			res.More = true
			return res, nil
		}
		first := page == 0
		hdr := http.Header{}
		path := b.boxPath("/messages")
		if first && len(etag) > 0 {
			hdr.Set("If-None-Match", string(etag))
		}
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		var list protocol.MessageList
		resp, err := b.owner(ctx, http.MethodGet, path, nil, hdr, &list)
		if err != nil {
			// A server that says this box is revoked is asked to show it.
			return res, b.proved(ctx, b.id.Address(), err, asked)
		}
		if resp.StatusCode == http.StatusNotModified {
			return res, nil
		}
		res.PollAfter = min(list.PollAfter, maxWaitSeconds)
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
			if messages == maxDrainMessages || fetched >= maxDrainBytes {
				res.More = true
				return res, nil
			}
			n, err := b.receiveOne(ctx, m.ID, res, asked)
			// A server that paces how much a box takes out stops the drain
			// as a drain's own limits do: what is left waits on the server.
			var paced *APIError
			if errors.As(err, &paced) && paced.Problem.Code == protocol.CodeRateLimited && paced.RetryAfter > 0 {
				res.More, res.Paced = true, paced.RetryAfter
				return res, nil
			}
			if err != nil {
				return res, err
			}
			messages++
			fetched += n
		}
		if list.NextCursor == nil || *list.NextCursor == "" {
			return res, nil
		}
		cursor = *list.NextCursor
	}
}

// receiveOne judges one message unless its id was already handled, stores
// the verdict, and acks it, and returns the bytes of ciphertext it fetched.
// An error is transient, or a fault of this box (an unreadable key, a full
// disk): the message stays on the server for the next drain, never judged by
// a box that cannot judge it.
//
// Files are named by the SHA-256 of the ciphertext as computed here, never by
// the server's id; a message whose id is not that hash is refused.
func (b *Box) receiveOne(ctx context.Context, id string, res *Result, asked *lookups) (fetched int, err error) {
	handled, err := b.seenHash(id)
	if err != nil {
		return 0, err
	}
	if !handled {
		var m protocol.Message
		_, err := b.owner(ctx, http.MethodGet, b.boxPath("/messages/"+id), nil, nil, &m)
		if Code(err) == protocol.CodeNoSuchMessage {
			return 0, nil // already gone
		}
		if err != nil {
			return 0, err
		}
		fetched = len(m.Ciphertext)
		h := sha256.Sum256(m.Ciphertext)
		local := hex.EncodeToString(h[:])
		d, dup, why, err := b.judge(ctx, &m, asked)
		if err != nil {
			return fetched, err
		}
		if why == nil && local != id {
			d, dup, why = nil, false, &Refusal{Code: RefusedID, Reason: "the server's id for it is not the SHA-256 of its ciphertext"}
		}
		switch {
		case why != nil:
			raw, err := json.Marshal(m)
			if err != nil {
				return fetched, err
			}
			// The message as served, and beside it why it was refused: the
			// reason is this client's words, so it is safe to show.
			if err := writeFile(b.path("quarantine", local+".json"), raw); err != nil {
				return fetched, err
			}
			if err := writeFile(b.path("quarantine", local+".reason"), []byte(why.Code+": "+why.Reason+"\n")); err != nil {
				return fetched, err
			}
			why.ID = local
			res.Refused = append(res.Refused, *why)
		case dup:
			res.Duplicates = append(res.Duplicates, local)
		default:
			// Stored before it is recorded as seen, and both, on disk,
			// before the ack: a crash or power loss in between delivers it
			// again, never loses it.
			if err := writeFile(b.path("inbox", local+".json"), d.Line); err != nil {
				return fetched, err
			}
			if err := b.recordSeen(m.Ciphertext, d.Envelope); err != nil {
				return fetched, err
			}
			d.ID = local
			res.Delivered = append(res.Delivered, *d)
		}
	}
	_, err = b.owner(ctx, http.MethodDelete, b.boxPath("/messages/"+id), nil, nil, nil)
	if Code(err) == protocol.CodeNoSuchMessage {
		return fetched, nil
	}
	return fetched, err
}

// judge runs every check on one message, in this order, and returns the
// delivery only if all of them pass; otherwise why says which failed, in a
// code and in this client's own words. An error is this box's own fault, not
// the message's: no verdict.
//
//  1. Decryption with every retained prekey.
//  2. What came out is an envelope line and then a signature block.
//  3. The line carries the sender's identity document, and its from is that
//     document's hash.
//  4. The signature over the line as decrypted, in this box's message
//     namespace, by a working key that identity certified.
//  5. The envelope: version 1, to is this box.
//  6. Freshness: sent_at no older than protocol.TTL (33 days).
//  7. The server's from for it is the sender that was verified.
//  8. Revocation: this box holds no revocation of the sender. The server is
//     asked for one, once for each sender in a drain. A revocation that
//     verifies refuses the message and every later one, whenever they were
//     signed. A server that says it holds none has answered. No answer is an
//     error: the message stays on the server for the next drain. The same
//     answer carries the sender's revocation of its certificates, if it has
//     one: mail signed under a revoked certificate is refused the same way,
//     and the address goes on. Each revocation server the box lists is
//     asked after its own, and can only add: a record it shows is kept, and
//     no answer from it changes nothing.
//  9. Replay: the locally computed ciphertext hash is not in the seen-set.
//  10. Retry: (from, msg_id) is not in the seen-set. A match is a duplicate.
//
// Checks 2 to 6 are protocol.OpenSigned's. Who the sender is, is never asked
// of the server: the message carries what proves it. The one thing asked is
// whether a revocation of that sender exists, and the answer proves itself.
// The sender's identity is pinned only once all of that has passed.
func (b *Box) judge(ctx context.Context, m *protocol.Message, asked *lookups) (d *Delivery, dup bool, why *Refusal, err error) {
	refused := func(code, reason string) (*Delivery, bool, *Refusal, error) {
		return nil, false, &Refusal{Code: code, Reason: reason}, nil
	}
	ids, err := b.prekeyIdentities()
	if err != nil {
		return nil, false, nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(m.Ciphertext), ids...)
	if err != nil {
		return refused(RefusedDecrypt, "it does not decrypt with this box's prekeys")
	}
	p, err := io.ReadAll(io.LimitReader(r, maxResponse))
	if err != nil {
		return refused(RefusedDecrypt, "it does not decrypt with this box's prekeys")
	}
	signed, err := protocol.OpenSigned(p, b.id.Address(), b.now())
	if err != nil {
		var e *protocol.EnvelopeError
		if errors.As(err, &e) {
			return refused(e.Code, e.Why)
		}
		return nil, false, nil, err
	}
	from, env := signed.Sender.Address(), signed.Envelope
	// The server says who posted it, from the pass the post carried. It is
	// held to the sender the signature proved.
	if m.From != from.String() {
		return refused(protocol.RefusedAttribution, "the server lists it as from another box than the one that signed it")
	}
	gone, err := b.revoked(from)
	if err == nil && !gone && !asked.answered[from] {
		if gone, err = b.lookupRevocation(ctx, from, asked); err == nil {
			asked.answered[from] = true
		}
	}
	if err != nil {
		return nil, false, nil, fmt.Errorf("whether its sender is revoked could not be asked, so the message stays on the server: %w", err)
	}
	if gone {
		return refused(RefusedRevoked, "its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed")
	}
	certs, err := b.revokedCerts(from)
	if err != nil {
		return nil, false, nil, err
	}
	if certs != nil && certs.Revokes(signed.Certificate.Serial()) {
		return refused(RefusedCertificate, "it is signed under a certificate its sender's identity has revoked: nothing signed under it is taken, whenever it was signed")
	}
	h := sha256.Sum256(m.Ciphertext)
	seen, err := b.seenHash(hex.EncodeToString(h[:]))
	if err != nil {
		return nil, false, nil, err
	}
	if seen {
		return refused(RefusedReplay, "replay: this ciphertext was already received")
	}
	if err := b.pin(signed.Sender); err != nil {
		return nil, false, nil, err
	}
	again, err := b.seenMsgID(from, env.MsgID)
	if err != nil {
		return nil, false, nil, err
	}
	if again {
		return nil, true, nil, nil
	}
	shown := *env
	shown.Identity = nil
	line, err := shown.Marshal()
	if err != nil {
		return nil, false, nil, err
	}
	return &Delivery{Envelope: env, Line: []byte(lineBreaks.Replace(string(line))), Plaintext: signed.Line, Signature: signed.Signature}, false, nil, nil
}

// lineBreaks escapes the characters other than LF that some readers end a
// line at (Python's str.splitlines, Node's readline): a body can carry them
// raw inside a JSON string, the only place JSON allows them, so escaping
// them keeps one message one line with the same value.
var lineBreaks = strings.NewReplacer("\u0085", `\u0085`, " ", ` `, " ", ` `)

// The seen-set: one line per accepted message, "<ciphertext hash> <sent_at,
// unix seconds> <from> <msg_id>", kept until sent_at + protocol.TTL, so the
// replay check and the freshness check cover the same window.

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
	_, err := os.Stat(b.path("seen"))
	created := errors.Is(err, fs.ErrNotExist)
	f, err := os.OpenFile(b.path("seen"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%x %d %s %s\n", h, env.SentAt.Unix(), env.From, env.MsgID); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error wins
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck,gosec // the sync error wins
		return err
	}
	if err := f.Close(); err != nil || !created {
		return err
	}
	// A new file is durable only once its directory entry is.
	return syncDir(b.dir)
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
