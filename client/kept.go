package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dromas-dev/dromas-client/protocol"
)

// IsID reports whether s is a message's id as this mailbox names it: the
// SHA-256 of its ciphertext, as 64 lowercase hex. Each file inbox/, held/ and
// refused/ keep is named by one.
func IsID(s string) bool { return hexID.MatchString(s) }

// InboxMessage returns the message inbox/<id>.json keeps, as Receive
// delivered it but for Plaintext and Signature, which the mailbox never kept:
// its checked fields, as recv printed them ([Mailbox.keptLine]). An id that is
// not one is refused before any file is read.
func (b *Mailbox) InboxMessage(ctx context.Context, id string) (Delivery, error) {
	if !IsID(id) {
		return Delivery{}, errors.New("not a message's id: 64 lowercase hex, as recv prints it")
	}
	return reading(ctx, b, func() (Delivery, error) { return b.inboxMessage(id) })
}

// inboxMessage is InboxMessage, read under the reading or command that holds
// the mailbox, of an id it has checked.
func (b *Mailbox) inboxMessage(id string) (Delivery, error) {
	data, err := os.ReadFile(b.path("inbox", id+".json")) //nolint:gosec // a path inside the mailbox's own directory, named by 64 hex
	if errors.Is(err, fs.ErrNotExist) {
		return Delivery{}, fmt.Errorf("inbox/ holds no message %s", id)
	}
	if err != nil {
		return Delivery{}, err
	}
	l, _, env, ok := b.keptLine(data)
	if !ok {
		return Delivery{}, fmt.Errorf("inbox/%s.json is not the line recv keeps: it was cut short, or written since by something else", id)
	}
	return Delivery{ID: id, Envelope: env, Line: l}, nil
}

// Inbox returns the messages inbox/ keeps, oldest first by sent_at (within a
// second as [Mailbox.keptMessages] orders it), each as
// [Mailbox.InboxMessage] returns it: what recv delivered and nobody has pruned
// since. A file that is not the line recv keeps is left out, as
// [Mailbox.InboxMessage] refuses it. It reads only inbox/, once the mailbox's
// format is this client's, and calls no server.
func (b *Mailbox) Inbox(ctx context.Context) ([]Delivery, error) {
	return reading(ctx, b, b.inbox)
}

// inbox is Inbox, read under the reading or command that holds the mailbox.
func (b *Mailbox) inbox() ([]Delivery, error) {
	ms, err := b.keptMessages("inbox")
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(ms))
	for _, m := range ms {
		out = append(out, Delivery{ID: m.ID, Envelope: m.Env, Line: m.Line})
	}
	return out, nil
}

// keptLine reads a file inbox/ or held/ keeps as the line recv wrote: one
// that reads back as the record of a message to this mailbox
// ([protocol.OpenEnvelopeRecord], which reads no clock) and is, byte for
// byte, the line recv writes of that record (keptLineOf). A file cut short,
// as a recv stopped midway can leave one, with more in it, members recv
// never writes, or the same members written another way, is none: whoever
// last wrote the file is not known here, and only recv's own line is
// printed (#298).
func (b *Mailbox) keptLine(data []byte) (line []byte, from protocol.Address, env *protocol.Envelope, ok bool) {
	if len(data) == 0 || data[0] != '{' || bytes.ContainsAny(data, "\r\n") {
		return nil, from, nil, false
	}
	var f struct {
		From string `json:"from"`
	}
	if protocol.Unmarshal(data, &f) != nil {
		return nil, from, nil, false
	}
	from, err := protocol.ParseAddress(f.From)
	if err != nil {
		return nil, from, nil, false
	}
	env, err = protocol.OpenEnvelopeRecord(data, from, b.id.Address())
	if err != nil {
		return nil, from, nil, false
	}
	if want, err := keptLineOf(env); err != nil || !bytes.Equal(want, data) {
		return nil, from, nil, false
	}
	return data, from, env, true
}

// keptRefusal is a refused message as refused/<id>.json keeps it: the
// message as served, whole, for whoever looks into who sent what: its id
// and times as its list entry gives them, and the ciphertext its fetch
// answered, in base64. A from a list entry carries is kept nowhere: no
// reader reads it (PROTOCOL.md §11.11). Each of the server's strings is in
// the clear only when it has its form (an id is 64 lowercase hex, a time is
// one protocol.ParseTime reads), and is otherwise kept as <name>_b64, the
// string as served in base64. So nothing the server chose is readable at a
// glance, and nothing is lost. Its size is the ciphertext's, which the fetch
// was held to. Why it was refused, and what the checks found, are the mailbox's
// state's (refusedRecord), which only this client writes (#280).
type keptRefusal struct {
	ID            string         `json:"id,omitempty"`
	IDB64         string         `json:"id_b64,omitempty"`
	ReceivedAt    string         `json:"received_at,omitempty"`
	ReceivedAtB64 string         `json:"received_at_b64,omitempty"`
	ExpiresAt     string         `json:"expires_at,omitempty"`
	ExpiresAtB64  string         `json:"expires_at_b64,omitempty"`
	Ciphertext    protocol.Bytes `json:"ciphertext"`
}

// refusedRecord is what the mailbox's state keeps of a refused message, by
// its id, beside the message refused/ keeps: the code it was refused for,
// why, in this client's words, and what the checks established when they
// judged it.
type refusedRecord struct {
	Code   string        `json:"code"`
	Reason string        `json:"reason"`
	Judged *keptFindings `json:"judged,omitempty"`
}

// keptFindings is what this client's checks established about a refused
// message (protocol.Findings), so that its owner can judge it once its key is
// gone: when it was judged, by this machine's clock; who signed it, or only
// the identity it carries when the signature does not verify or the mailbox
// holds a revocation of that address or one that covers its signer (#265);
// and, with who signed it, the certificate's serial and dates where a working
// key signed it, and the envelope's sent_at and msg_id. Each is a value this client checked the form of.
type keptFindings struct {
	At                string `json:"at"`
	SignedBy          string `json:"signed_by,omitempty"`
	ClaimsIdentity    string `json:"claims_identity,omitempty"`
	CertificateSerial uint64 `json:"certificate_serial,omitempty"`
	CertificateBegan  string `json:"certificate_began,omitempty"`
	CertificateEnds   string `json:"certificate_ends,omitempty"`
	SentAt            string `json:"sent_at,omitempty"`
	MsgID             string `json:"msg_id,omitempty"`
}

func stamp(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

func newKeptFindings(f *protocol.Findings) *keptFindings {
	if f == nil {
		return nil
	}
	k := &keptFindings{At: stamp(f.At)}
	switch {
	case f.Identity != nil && f.Signed:
		k.SignedBy = f.Identity.String()
		// A certificate's serial and dates only where there is one: the
		// identity's own signature has neither.
		if f.Rank > 0 {
			k.CertificateSerial = f.Rank
			k.CertificateBegan, k.CertificateEnds = stamp(f.Began), stamp(f.Ends)
		}
		if !f.SentAt.IsZero() {
			k.SentAt = stamp(f.SentAt)
		}
		k.MsgID = f.MsgID
	case f.Identity != nil:
		k.ClaimsIdentity = f.Identity.String()
	}
	return k
}

// keepRefused keeps a refused message: refused/<id>.json, the message as
// served (keptRefusal), written and synced first, then why it was refused and
// what its checks found, in the mailbox's state.
func (b *Mailbox) keepRefused(id string, m *protocol.MessageInfo, ct []byte, why *Refusal) error {
	raw, err := servedRefusal(m, ct)
	if err != nil {
		return err
	}
	if err := writeFile(b.path("refused", id+".json"), raw); err != nil {
		return err
	}
	step("refusal written")
	rec, err := json.Marshal(refusedRecord{Code: why.Code, Reason: why.Reason, Judged: newKeptFindings(why.Findings)})
	if err != nil {
		return err
	}
	if err := b.update(func(s store) error { return s.put(bucketRefused, id, rec) }); err != nil {
		return err
	}
	step("refusal kept")
	return nil
}

func servedRefusal(m *protocol.MessageInfo, ct []byte) ([]byte, error) {
	k := keptRefusal{Ciphertext: ct}
	for _, f := range []struct {
		served       string
		plain, coded *string
		ok           bool
	}{
		{m.ID, &k.ID, &k.IDB64, IsID(m.ID)},
		{m.ReceivedAt, &k.ReceivedAt, &k.ReceivedAtB64, isTime(m.ReceivedAt)},
		{m.ExpiresAt, &k.ExpiresAt, &k.ExpiresAtB64, isTime(m.ExpiresAt)},
	} {
		switch {
		case f.served == "":
		case f.ok:
			*f.plain = f.served
		default:
			*f.coded = base64.StdEncoding.EncodeToString([]byte(f.served))
		}
	}
	return json.Marshal(k)
}

func isTime(s string) bool { _, err := protocol.ParseTime(s); return err == nil }

func isAddress(s string) bool { _, err := protocol.ParseAddress(s); return err == nil }

// RefusedMessage is a refused message in refused/, in this client's words:
// its id, the code it was refused for and why, the time the server gave,
// and what this client's checks established about it when it judged it
// (keptFindings), each only when it has its form. Nothing else of
// what the server or the sender wrote is in it.
type RefusedMessage struct {
	ID                string `json:"id"`
	Code              string `json:"code"`
	Reason            string `json:"detail,omitempty"`
	ReceivedAt        string `json:"received_at,omitempty"`
	JudgedAt          string `json:"judged_at,omitempty"`
	SignedBy          string `json:"signed_by,omitempty"`
	ClaimsIdentity    string `json:"claims_identity,omitempty"`
	CertificateSerial uint64 `json:"certificate_serial,omitempty"`
	CertificateBegan  string `json:"certificate_began,omitempty"`
	CertificateEnds   string `json:"certificate_ends,omitempty"`
	SentAt            string `json:"sent_at,omitempty"`
	MsgID             string `json:"msg_id,omitempty"`
}

// RefusedMessages lists refused/, by id: each message it keeps, with what the
// mailbox's state keeps of why it was refused. A message with no record there,
// or one this client did not write, has the code "unknown" and nothing from
// it. Each value is held to its form again as it is read.
func (b *Mailbox) RefusedMessages(ctx context.Context) ([]RefusedMessage, error) {
	return reading(ctx, b, b.refusedMessages)
}

// refusedMessages is RefusedMessages inside a command or a reading.
func (b *Mailbox) refusedMessages() ([]RefusedMessage, error) {
	names, err := filepath.Glob(b.path("refused", "*.json"))
	if err != nil {
		return nil, err
	}
	var qs []RefusedMessage
	err = b.view(func(s store) error {
		for _, name := range names {
			id := strings.TrimSuffix(filepath.Base(name), ".json")
			if !IsID(id) {
				continue
			}
			q := RefusedMessage{ID: id}
			var kept struct {
				ReceivedAt any `json:"received_at"`
			}
			if data, err := os.ReadFile(name); err == nil && protocol.Unmarshal(data, &kept) == nil { //nolint:gosec // a path inside the mailbox's own directory
				if str, ok := kept.ReceivedAt.(string); ok && isTime(str) {
					q.ReceivedAt = str
				}
			}
			rec := refusedRecordOf(s, id)
			q.Code, q.Reason = rec.Code, rec.Reason
			if j := rec.Judged; j != nil {
				for _, v := range []struct {
					kept string
					dst  *string
					ok   func(string) bool
				}{
					{j.At, &q.JudgedAt, isTime},
					{j.SignedBy, &q.SignedBy, isAddress},
					{j.ClaimsIdentity, &q.ClaimsIdentity, isAddress},
					{j.CertificateBegan, &q.CertificateBegan, isTime},
					{j.CertificateEnds, &q.CertificateEnds, isTime},
					{j.SentAt, &q.SentAt, isTime},
					{j.MsgID, &q.MsgID, protocol.IsMsgID},
				} {
					if v.ok(v.kept) {
						*v.dst = v.kept
					}
				}
				if n := j.CertificateSerial; n >= 1 && n <= protocol.MaxSerial {
					q.CertificateSerial = n
				}
			}
			qs = append(qs, q)
		}
		return nil
	})
	return qs, err
}

// refusedRecordOf is what the mailbox's state keeps of refused message id: its
// code, "unknown" when it keeps none or one not of a code's form, and the
// words after it, which this client wrote, given only as one line of
// printable text.
func refusedRecordOf(s store, id string) refusedRecord {
	var rec refusedRecord
	if raw := s.get(bucketRefused, id); raw == nil || protocol.Unmarshal(raw, &rec) != nil || !codeGrammar.MatchString(rec.Code) {
		return refusedRecord{Code: "unknown"}
	}
	if w := rec.Reason; len(w) > 500 || !utf8.ValidString(w) || strings.ContainsFunc(w, func(r rune) bool { return r < 0x20 || r == 0x7f || escaped(r) }) {
		rec.Reason = ""
	}
	return rec
}

// RemoveRefused deletes refused messages from refused/, each with what
// the mailbox's state keeps of it, and returns the ids it deleted; with no ids it
// deletes them all.
// An id that is not one, or that refused/ does not hold, is refused
// before anything is deleted.
//
// It holds the mailbox's lock from start to end ([Mailbox.hold]), as every command
// that writes the mailbox does.
func (b *Mailbox) RemoveRefused(ctx context.Context, ids []string) ([]string, error) {
	return lockedFinished(ctx, b, func() ([]string, error) {
		if len(ids) == 0 {
			qs, err := b.refusedMessages()
			if err != nil {
				return nil, err
			}
			for _, q := range qs {
				ids = append(ids, q.ID)
			}
		}
		for _, id := range ids {
			if !IsID(id) {
				return nil, errors.New("not a message's id: 64 lowercase hex, as dromas refused list prints it")
			}
			if _, err := os.Stat(b.path("refused", id+".json")); err != nil {
				return nil, fmt.Errorf("refused/ holds no message %s: nothing is deleted", id)
			}
		}
		var gone []string
		for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
			if err := os.Remove(b.path("refused", id+".json")); err != nil {
				return gone, err
			}
			if err := b.update(func(s store) error { return s.del(bucketRefused, id) }); err != nil {
				return gone, err
			}
			gone = append(gone, id)
		}
		return gone, nil
	})
}
