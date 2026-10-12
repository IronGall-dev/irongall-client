package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	// EnvelopeVersion is the envelope's "v". It changes only for a breaking
	// change, and a receiver rejects a version it does not know.
	EnvelopeVersion = 1
	// TTL is how long the server keeps unacked mail: 33 days, a prekey's
	// longest life, so a box that checks in at least monthly loses neither new
	// mail nor held mail. Every window of mail's age derives from it: the
	// recipient's sent_at window, the replay set, the sender's outbox, and the
	// latest a retired prekey can still be needed.
	TTL = 33 * 24 * time.Hour
)

// msgIDGrammar is the receiver's check on msg_id: 36 characters of lowercase
// hex and hyphens, as the stock recipe checks it.
var msgIDGrammar = regexp.MustCompile(`\A[0-9a-f-]{36}\z`)

// IsMsgID reports whether s has the form of a msg_id, as a receiver checks
// one: what a sender may put in in_reply_to and supersedes.
func IsMsgID(s string) bool { return msgIDGrammar.MatchString(s) }

// The checks an envelope can fail, as codes: a closed set, so that whoever
// reads a refusal reads words this code chose.
const (
	RefusedEnvelope    = "bad_envelope" // not UTF-8 JSON, one object with no key twice, version 1, with a body, a msg_id and a sent_at
	RefusedAttribution = "reattributed" // its from is not the verified signer, or its to is not this box
	RefusedStale       = "stale"        // its sent_at is older than TTL
)

// EnvelopeError is the check an envelope failed: one of the codes above and
// fixed words. It never quotes the envelope, whose text its sender chose: a
// refusal is read by whoever runs the client, and that may be a model.
type EnvelopeError struct{ Code, Why string }

func (e *EnvelopeError) Error() string { return e.Why }

func badEnvelope(why string) error { return &EnvelopeError{RefusedEnvelope, why} }

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
	V          json.Number     `json:"v"` // written as a number; read only as one
	From       Address         `json:"from"`
	To         Address         `json:"to"`
	SentAt     string          `json:"sent_at"`
	MsgID      string          `json:"msg_id"`
	Body       json.RawMessage `json:"body"`
	Subject    string          `json:"subject,omitempty"`
	InReplyTo  string          `json:"in_reply_to,omitempty"`
	Supersedes string          `json:"supersedes,omitempty"`
	Pad        *string         `json:"pad,omitempty"` // a pointer: a pad of no filler is still a member
}

// NewEnvelope returns an envelope from one box to another with a string body,
// sent now, with a fresh msg_id.
func NewEnvelope(from, to Address, body string, now time.Time) (*Envelope, error) {
	if !utf8.ValidString(body) {
		return nil, errors.New("the body is not UTF-8 text: JSON carries text only, and would replace the bad bytes")
	}
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
	if e.Pad == "" {
		return e.marshal(nil)
	}
	return e.marshal(&e.Pad)
}

// marshal is Marshal with the pad member as given: nil for none, and a
// pointer to the empty string for the member with no filler.
func (e *Envelope) marshal(pad *string) ([]byte, error) {
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
		Pad:        pad,
	})
}

// OpenEnvelope parses a decrypted envelope and checks it, in this order: it is
// UTF-8 JSON, one object with no key twice; it is version 1, as a JSON number;
// its from is the VERIFIED signer and its to is this box (a mismatch means
// someone re-signed another sender's ciphertext as their own); it has a body
// and a msg_id; and sent_at is no older than TTL at now.
//
// Keys match exactly, as in jq and every other strict reader: "BODY" is an
// unknown key, ignored, never the body. No key twice, so no two readers can
// take different values from the envelope's fields. The body itself is the
// verified sender's own JSON, passed on as it is.
//
// The caller has already verified the signature and decrypted. Replay and
// duplicate checks need the caller's seen-set and are the caller's.
func OpenEnvelope(plaintext []byte, signer, me Address, now time.Time) (*Envelope, error) {
	if !utf8.Valid(plaintext) {
		return nil, badEnvelope("the envelope is not UTF-8")
	}
	fields, err := objectFields(plaintext)
	if err != nil {
		return nil, err
	}
	if _, ok := fields["body"]; !ok {
		return nil, badEnvelope("the envelope has no body")
	}
	var w wireEnvelope
	for key, dst := range map[string]any{
		"from": &w.From, "to": &w.To, "sent_at": &w.SentAt, "msg_id": &w.MsgID,
		"subject": &w.Subject, "in_reply_to": &w.InReplyTo, "supersedes": &w.Supersedes, "pad": &w.Pad,
	} {
		if raw, ok := fields[key]; ok {
			if err := json.Unmarshal(raw, dst); err != nil {
				return nil, badEnvelope("the envelope is malformed: its " + key + " is not what that field holds")
			}
		}
	}
	w.Body = fields["body"]
	// The raw value: a JSON string keeps its quotes, and is no number.
	if f, err := json.Number(fields["v"]).Float64(); err != nil || f != EnvelopeVersion {
		return nil, badEnvelope("unknown envelope version: v is the JSON number 1")
	}
	if w.From != signer || w.To != me {
		return nil, &EnvelopeError{RefusedAttribution, "the inner from/to do not match the signer and this box (re-attribution)"}
	}
	if !msgIDGrammar.MatchString(w.MsgID) {
		return nil, badEnvelope("the envelope has no valid msg_id")
	}
	sentAt, err := ParseTime(w.SentAt)
	if err != nil {
		return nil, badEnvelope("the envelope's sent_at is not a UTC timestamp to the second, YYYY-MM-DDTHH:MM:SSZ")
	}
	if sentAt.Before(now.Add(-TTL)) {
		return nil, &EnvelopeError{RefusedStale, fmt.Sprintf("sent_at is older than %d days", TTL/(24*time.Hour))}
	}
	e := &Envelope{
		From:       w.From,
		To:         w.To,
		SentAt:     sentAt,
		MsgID:      w.MsgID,
		Body:       w.Body,
		Subject:    w.Subject,
		InReplyTo:  w.InReplyTo,
		Supersedes: w.Supersedes,
	}
	if w.Pad != nil {
		e.Pad = *w.Pad
	}
	return e, nil
}

// objectFields reads a JSON object's members by their exact keys. A key that
// appears twice, or anything after the object, is an error.
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	notObject := badEnvelope("the envelope is not one JSON object")
	d := json.NewDecoder(bytes.NewReader(data))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, notObject
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, notObject
		}
		key, _ := t.(string)
		if _, dup := fields[key]; dup {
			return nil, badEnvelope("the envelope has a key twice")
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, notObject
		}
		fields[key] = v
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, notObject
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, notObject
	}
	return fields, nil
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
