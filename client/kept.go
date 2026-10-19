package client

import (
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
// fields, as recv printed them. An id that is not one is refused before any
// file is read.
func (b *Box) InboxLine(id string) ([]byte, error) {
	if !IsID(id) {
		return nil, errors.New("not a message's id: 64 lowercase hex, as recv prints it")
	}
	l, err := os.ReadFile(b.path("inbox", id+".json")) //nolint:gosec // a path inside the box's own directory, named by 64 hex
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inbox/ holds no message %s", id)
	}
	return l, err
}

// keptRefusal is a refused message as quarantine/<id>.json keeps it: the
// message as served, whole, for whoever looks into who sent what: the
// members of its list entry, and the ciphertext its fetch answered, in
// base64. Each of the server's strings is in the clear only when it has its
// form (an id or an address is 64 lowercase hex, a time is one
// protocol.ParseTime reads), and is otherwise kept as <name>_b64, the string
// as served in base64. So nothing the server chose is readable at a glance,
// and nothing is lost. Its size is the ciphertext's, which the fetch was
// held to. irongall.sh's ig_kept keeps the same.
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
	Judged        *keptFindings  `json:"judged,omitempty"`
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

func keepRefused(m *protocol.MessageInfo, ct []byte, f *protocol.Findings) ([]byte, error) {
	k := keptRefusal{Ciphertext: ct, Judged: newKeptFindings(f)}
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

// Quarantined lists quarantine/, by id. A file is read whichever form it was
// kept in, and each value is held to its form again as it is read.
func (b *Box) Quarantined() ([]Quarantined, error) {
	names, err := filepath.Glob(b.path("quarantine", "*.json"))
	if err != nil {
		return nil, err
	}
	var qs []Quarantined
	for _, name := range names {
		id := strings.TrimSuffix(filepath.Base(name), ".json")
		if !IsID(id) {
			continue
		}
		q := Quarantined{ID: id}
		q.Code, q.Reason = b.quarantineReason(id)
		var kept struct {
			From       any `json:"from"`
			ReceivedAt any `json:"received_at"`
			Judged     struct {
				At                any `json:"at"`
				SignedBy          any `json:"signed_by"`
				ClaimsIdentity    any `json:"claims_identity"`
				CertificateSerial any `json:"certificate_serial"`
				CertificateBegan  any `json:"certificate_began"`
				CertificateEnds   any `json:"certificate_ends"`
				SentAt            any `json:"sent_at"`
				MsgID             any `json:"msg_id"`
			} `json:"judged"`
		}
		if data, err := os.ReadFile(name); err == nil && json.Unmarshal(data, &kept) == nil { //nolint:gosec // a path inside the box's own directory
			j := kept.Judged
			for _, v := range []struct {
				kept any
				dst  *string
				ok   func(string) bool
			}{
				{kept.From, &q.From, IsID},
				{kept.ReceivedAt, &q.ReceivedAt, isTime},
				{j.At, &q.JudgedAt, isTime},
				{j.SignedBy, &q.SignedBy, IsID},
				{j.ClaimsIdentity, &q.ClaimsIdentity, IsID},
				{j.CertificateBegan, &q.CertificateBegan, isTime},
				{j.CertificateEnds, &q.CertificateEnds, isTime},
				{j.SentAt, &q.SentAt, isTime},
				{j.MsgID, &q.MsgID, protocol.IsMsgID},
			} {
				if s, ok := v.kept.(string); ok && v.ok(s) {
					*v.dst = s
				}
			}
			if n, ok := j.CertificateSerial.(float64); ok && n >= 1 && n <= protocol.MaxSerial && n == float64(uint64(n)) {
				q.CertificateSerial = uint64(n)
			}
		}
		qs = append(qs, q)
	}
	return qs, nil
}

// quarantineReason is the code a refused message's .reason file starts
// with, "unknown" when it does not start with one, and the words after it,
// which a client wrote: given only as one line of printable text.
func (b *Box) quarantineReason(id string) (code, reason string) {
	data, err := os.ReadFile(b.path("quarantine", id+".reason")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return "unknown", ""
	}
	c, words, ok := strings.Cut(strings.TrimSuffix(string(data), "\n"), ": ")
	if !ok || !codeGrammar.MatchString(c) {
		return "unknown", ""
	}
	if len(words) > 500 || !utf8.ValidString(words) || strings.ContainsFunc(words, func(r rune) bool { return r < 0x20 || r == 0x7f || escaped(r) }) {
		words = ""
	}
	return c, words
}

// RemoveQuarantined deletes refused messages from quarantine/, each with its
// .reason, and returns the ids it deleted; with no ids it deletes them all.
// An id that is not one, or that quarantine/ does not hold, is refused
// before anything is deleted.
//
// It holds the box's lock from start to end ([Box.hold]), as every command
// that writes the box does.
func (b *Box) RemoveQuarantined(ctx context.Context, ids []string) ([]string, error) {
	return locked(ctx, b, func() ([]string, error) {
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
			if err := os.Remove(b.path("quarantine", id+".reason")); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return gone, err
			}
			gone = append(gone, id)
		}
		return gone, nil
	})
}
