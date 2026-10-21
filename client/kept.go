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

	"github.com/IronGall-dev/irongall-client/protocol"
)

// IsID reports whether s is a message's id as this box names it: the
// SHA-256 of its ciphertext, as 64 lowercase hex. Each file inbox/, held/ and
// quarantine/ keep is named by one.
func IsID(s string) bool { return hexID.MatchString(s) }

// InboxLine returns the line inbox/<id>.json keeps: the message's checked
// fields, as recv printed them ([Box.keptLine]). An id that is not one is
// refused before any file is read.
func (b *Box) InboxLine(id string) ([]byte, error) {
	if !IsID(id) {
		return nil, errors.New("not a message's id: 64 lowercase hex, as recv prints it")
	}
	data, err := os.ReadFile(b.path("inbox", id+".json")) //nolint:gosec // a path inside the box's own directory, named by 64 hex
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inbox/ holds no message %s", id)
	}
	if err != nil {
		return nil, err
	}
	l, _, _, ok := b.keptLine(data)
	if !ok {
		return nil, fmt.Errorf("inbox/%s.json is not the line recv keeps: it was cut short, or written since by something else", id)
	}
	return l, nil
}

// keptLine reads a file inbox/ or held/ keeps as the line recv wrote: one
// that reads back as the record of a message to this box
// ([protocol.OpenEnvelopeRecord], which reads no clock) and is, byte for
// byte, the line recv writes of that record (keptLineOf). A file cut short,
// as a recv stopped midway can leave one, with more in it, members recv
// never writes, or the same members written another way, is none: whoever
// last wrote the file is not known here, and only recv's own line is
// printed (#298).
func (b *Box) keptLine(data []byte) (line []byte, from protocol.Address, env *protocol.Envelope, ok bool) {
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

// keptRefusal is a refused message as quarantine/<id>.json keeps it: the
// message as served, whole, for whoever looks into who sent what: the
// members of its list entry, and the ciphertext its fetch answered, in
// base64. Each of the server's strings is in the clear only when it has its
// form (an id or an address is 64 lowercase hex, a time is one
// protocol.ParseTime reads), and is otherwise kept as <name>_b64, the string
// as served in base64. So nothing the server chose is readable at a glance,
// and nothing is lost. Its size is the ciphertext's, which the fetch was
// held to. Why it was refused, and what the checks found, are the box's
// state's (quarantineRecord), which only this client writes (#280).
type keptRefusal struct {
	ID            string         `json:"id,omitempty"`
	IDB64         string         `json:"id_b64,omitempty"`
	From          string         `json:"from,omitempty"`
	FromB64       string         `json:"from_b64,omitempty"`
	ReceivedAt    string         `json:"received_at,omitempty"`
	ReceivedAtB64 string         `json:"received_at_b64,omitempty"`
	ExpiresAt     string         `json:"expires_at,omitempty"`
	ExpiresAtB64  string         `json:"expires_at_b64,omitempty"`
	Ciphertext    protocol.Bytes `json:"ciphertext"`
}

// quarantineRecord is what the box's state keeps of a refused message, by
// its id, beside the message quarantine/ keeps: the code it was refused for,
// why, in this client's words, and what the checks established when they
// judged it.
type quarantineRecord struct {
	Code   string        `json:"code"`
	Reason string        `json:"reason"`
	Judged *keptFindings `json:"judged,omitempty"`
}

// keptFindings is what this client's checks established about a refused
// message (protocol.Findings), so that its owner can judge it once its key is
// gone: when it was judged, by this machine's clock; who signed it, or only
// the identity it carries when the signature does not verify; and, when it
// does, the certificate's serial and dates and the envelope's sent_at and
// msg_id. Each is a value this client checked the form of.
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
		k.CertificateSerial = f.Serial
		k.CertificateBegan, k.CertificateEnds = stamp(f.Began), stamp(f.Ends)
		if !f.SentAt.IsZero() {
			k.SentAt = stamp(f.SentAt)
		}
		k.MsgID = f.MsgID
	case f.Identity != nil:
		k.ClaimsIdentity = f.Identity.String()
	}
	return k
}

// keepRefused keeps a refused message: quarantine/<id>.json, the message as
// served (keptRefusal), written and synced first, then why it was refused and
// what its checks found, in the box's state.
func (b *Box) keepRefused(id string, m *protocol.MessageInfo, ct []byte, why *Refusal) error {
	raw, err := servedRefusal(m, ct)
	if err != nil {
		return err
	}
	if err := writeFile(b.path("quarantine", id+".json"), raw); err != nil {
		return err
	}
	rec, err := json.Marshal(quarantineRecord{Code: why.Code, Reason: why.Reason, Judged: newKeptFindings(why.Findings)})
	if err != nil {
		return err
	}
	return b.update(func(s store) error { return s.put(bucketQuarantine, id, rec) })
}

func servedRefusal(m *protocol.MessageInfo, ct []byte) ([]byte, error) {
	k := keptRefusal{Ciphertext: ct}
	for _, f := range []struct {
		served       string
		plain, coded *string
		ok           bool
	}{
		{m.ID, &k.ID, &k.IDB64, IsID(m.ID)},
		{m.From, &k.From, &k.FromB64, IsID(m.From)},
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

// Quarantined is a refused message in quarantine/, in this client's words:
// its id, the code it was refused for and why, the sender and the time the
// server gave, and what this client's checks established about it when it
// judged it (keptFindings), each only when it has its form. Nothing else of
// what the server or the sender wrote is in it.
type Quarantined struct {
	ID                string `json:"id"`
	Code              string `json:"code"`
	Reason            string `json:"reason,omitempty"`
	From              string `json:"from,omitempty"`
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

// Quarantined lists quarantine/, by id: each message it keeps, with what the
// box's state keeps of why it was refused. A message with no record there,
// or one this client did not write, has the code "unknown" and nothing from
// it. Each value is held to its form again as it is read.
func (b *Box) Quarantined() ([]Quarantined, error) {
	names, err := filepath.Glob(b.path("quarantine", "*.json"))
	if err != nil {
		return nil, err
	}
	var qs []Quarantined
	err = b.view(func(s store) error {
		for _, name := range names {
			id := strings.TrimSuffix(filepath.Base(name), ".json")
			if !IsID(id) {
				continue
			}
			q := Quarantined{ID: id}
			var kept struct {
				From       any `json:"from"`
				ReceivedAt any `json:"received_at"`
			}
			if data, err := os.ReadFile(name); err == nil && protocol.Unmarshal(data, &kept) == nil { //nolint:gosec // a path inside the box's own directory
				for _, v := range []struct {
					kept any
					dst  *string
					ok   func(string) bool
				}{{kept.From, &q.From, IsID}, {kept.ReceivedAt, &q.ReceivedAt, isTime}} {
					if str, ok := v.kept.(string); ok && v.ok(str) {
						*v.dst = str
					}
				}
			}
			rec := quarantineOf(s, id)
			q.Code, q.Reason = rec.Code, rec.Reason
			if j := rec.Judged; j != nil {
				for _, v := range []struct {
					kept string
					dst  *string
					ok   func(string) bool
				}{
					{j.At, &q.JudgedAt, isTime},
					{j.SignedBy, &q.SignedBy, IsID},
					{j.ClaimsIdentity, &q.ClaimsIdentity, IsID},
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

// quarantineOf is what the box's state keeps of refused message id: its
// code, "unknown" when it keeps none or one not of a code's form, and the
// words after it, which this client wrote, given only as one line of
// printable text.
func quarantineOf(s store, id string) quarantineRecord {
	var rec quarantineRecord
	if raw := s.get(bucketQuarantine, id); raw == nil || protocol.Unmarshal(raw, &rec) != nil || !codeGrammar.MatchString(rec.Code) {
		return quarantineRecord{Code: "unknown"}
	}
	if w := rec.Reason; len(w) > 500 || !utf8.ValidString(w) || strings.ContainsFunc(w, func(r rune) bool { return r < 0x20 || r == 0x7f || escaped(r) }) {
		rec.Reason = ""
	}
	return rec
}

// RemoveQuarantined deletes refused messages from quarantine/, each with what
// the box's state keeps of it, and returns the ids it deleted; with no ids it
// deletes them all.
// An id that is not one, or that quarantine/ does not hold, is refused
// before anything is deleted.
//
// It holds the box's lock from start to end ([Box.hold]), as every command
// that writes the box does.
func (b *Box) RemoveQuarantined(ctx context.Context, ids []string) ([]string, error) {
	return lockedFinished(ctx, b, func() ([]string, error) {
		if len(ids) == 0 {
			qs, err := b.Quarantined()
			if err != nil {
				return nil, err
			}
			for _, q := range qs {
				ids = append(ids, q.ID)
			}
		}
		for _, id := range ids {
			if !IsID(id) {
				return nil, errors.New("not a message's id: 64 lowercase hex, as irongall quarantine list prints it")
			}
			if _, err := os.Stat(b.path("quarantine", id+".json")); err != nil {
				return nil, fmt.Errorf("quarantine/ holds no message %s: nothing is deleted", id)
			}
		}
		var gone []string
		for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
			if err := os.Remove(b.path("quarantine", id+".json")); err != nil {
				return gone, err
			}
			if err := b.update(func(s store) error { return s.del(bucketQuarantine, id) }); err != nil {
				return gone, err
			}
			gone = append(gone, id)
		}
		return gone, nil
	})
}
