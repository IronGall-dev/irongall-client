package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	// EnvelopeVersion is the envelope's "v". It changes only for a breaking
	// change, and a receiver rejects a version it does not know.
	EnvelopeVersion = 1
	// TTL is how long the server keeps unacked mail: 7 days promised, 8 kept.
	// Every 8-day window derives from it: the recipient's sent_at window, the
	// replay set, and a retired prekey's deletion time.
	TTL = 8 * 24 * time.Hour
)

// msgIDGrammar is the receiver's check on msg_id: 36 characters of lowercase
// hex and hyphens, as the stock recipe checks it.
var msgIDGrammar = regexp.MustCompile(`\A[0-9a-f-]{36}\z`)

// Envelope is a message's plaintext: what is encrypted to the recipient's
// prekey. The server never sees it.
type Envelope struct {
	From   Address
	To     Address
	SentAt time.Time // to the second, UTC
	// MsgID is a random UUID (version 4), made once per logical message and
	// kept on every re-encryption, so a retry is never acted on twice.
	MsgID string
	// Body is the message: a JSON string, or the JSON value the recipient's
	// profile schema describes.
	Body json.RawMessage

	Subject    string // optional
	InReplyTo  string // optional: the msg_id replied to
	Supersedes string // optional: a msg_id of the same sender this replaces
	Pad        string // optional, ignored: padding to hide the length
}

// wireEnvelope is the JSON form, in the field order the stock recipe writes.
type wireEnvelope struct {
	V          json.Number     `json:"v"`
	From       Address         `json:"from"`
	To         Address         `json:"to"`
	SentAt     string          `json:"sent_at"`
	MsgID      string          `json:"msg_id"`
	Body       json.RawMessage `json:"body"`
	Subject    string          `json:"subject,omitempty"`
	InReplyTo  string          `json:"in_reply_to,omitempty"`
	Supersedes string          `json:"supersedes,omitempty"`
	Pad        string          `json:"pad,omitempty"`
}

// NewEnvelope returns an envelope from one box to another with a string body,
// sent now, with a fresh msg_id.
func NewEnvelope(from, to Address, body string, now time.Time) (*Envelope, error) {
	b, err := marshalCompact(body)
	if err != nil {
		return nil, err
	}
	id, err := NewMsgID()
	if err != nil {
		return nil, err
	}
	return &Envelope{From: from, To: to, SentAt: now.UTC().Truncate(time.Second), MsgID: id, Body: b}, nil
}

// Marshal returns the envelope as compact UTF-8 JSON with no HTML escaping,
// the form to encrypt.
func (e *Envelope) Marshal() ([]byte, error) {
	if e.Body == nil {
		return nil, errors.New("an envelope needs a body")
	}
	return marshalCompact(wireEnvelope{
		V:          json.Number("1"),
		From:       e.From,
		To:         e.To,
		SentAt:     e.SentAt.UTC().Format(TimeLayout),
		MsgID:      e.MsgID,
		Body:       e.Body,
		Subject:    e.Subject,
		InReplyTo:  e.InReplyTo,
		Supersedes: e.Supersedes,
		Pad:        e.Pad,
	})
}

// OpenEnvelope parses a decrypted envelope and checks it, in this order: it is
// version 1; its from is the VERIFIED signer and its to is this box (a
// mismatch means someone re-signed another sender's ciphertext as their own);
// it has a body and a msg_id; and sent_at is no older than TTL at now.
//
// The caller has already verified the signature and decrypted. Replay and
// duplicate checks need the caller's seen-set and are the caller's.
func OpenEnvelope(plaintext []byte, signer, me Address, now time.Time) (*Envelope, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &fields); err != nil {
		return nil, errors.New("the envelope is not a JSON object")
	}
	if _, ok := fields["body"]; !ok {
		return nil, errors.New("the envelope has no body")
	}
	var w wireEnvelope
	d := json.NewDecoder(bytes.NewReader(plaintext))
	d.UseNumber()
	if err := d.Decode(&w); err != nil {
		return nil, fmt.Errorf("the envelope is malformed: %v", err)
	}
	if v, err := w.V.Float64(); err != nil || v != EnvelopeVersion {
		return nil, fmt.Errorf("unknown envelope version %q", w.V)
	}
	if w.From != signer || w.To != me {
		return nil, errors.New("the inner from/to do not match the signer and this box (re-attribution)")
	}
	if !msgIDGrammar.MatchString(w.MsgID) {
		return nil, errors.New("the envelope has no valid msg_id")
	}
	sentAt, err := ParseTime(w.SentAt)
	if err != nil {
		return nil, fmt.Errorf("sent_at: %v", err)
	}
	if sentAt.Before(now.Add(-TTL)) {
		return nil, errors.New("sent_at is older than 8 days")
	}
	return &Envelope{
		From:       w.From,
		To:         w.To,
		SentAt:     sentAt,
		MsgID:      w.MsgID,
		Body:       w.Body,
		Subject:    w.Subject,
		InReplyTo:  w.InReplyTo,
		Supersedes: w.Supersedes,
		Pad:        w.Pad,
	}, nil
}

// NewMsgID returns a random UUID, version 4 (RFC 9562 §5.4), in lowercase.
func NewMsgID() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6] = u[6]&0x0f | 0x40 // version 4
	u[8] = u[8]&0x3f | 0x80 // variant 10
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// marshalCompact is json.Marshal without HTML escaping and without the
// encoder's trailing newline.
func marshalCompact(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
