package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	// EnvelopeVersion is the envelope's "v". It changes only for a breaking
	// change, and a receiver rejects a version it does not know.
	EnvelopeVersion = 1
	// TTL is how old a message may be, counted from its sent_at, which its
	// sender dates afresh at every post: 33 days, a prekey's longest life, so
	// a box that checks in at least monthly loses neither new mail nor held
	// mail. Every window of mail's age derives from it: the recipient's
	// sent_at window, how long a server keeps mail (Retention), the replay
	// set (SeenFor), how long the sender's outbox posts an entry, and the
	// latest a retired prekey can still be needed.
	TTL = 33 * 24 * time.Hour
	// PostTime is the room the maker of a time-limited thing leaves for a
	// post's own time, beside MaxSkew: what comes between the post's dating
	// and the server's receipt that no pass bounds, its seal and the second
	// the dating truncates. The request itself is bounded by its pass, which
	// a server takes only from a clock less than PassLifetime behind its own.
	PostTime = 2 * time.Minute
	// Retention is how long a server keeps a message after it received it:
	// the TTL less MaxSkew, the hour whoever makes a time-limited thing
	// leaves, and less PostTime (PROTOCOL.md §0, §7). A post's sent_at is
	// its sender's clock at the post, which a server takes from up to
	// MaxSkew apart from its own, so a reader whose clock a server takes
	// refuses as stale no message the server still serves.
	Retention = TTL - MaxSkew - PostTime
	// SeenFor is how long a reader keeps a message in its replay set,
	// counted from the message's sent_at: the TTL in which a retry of it may
	// still be posted, dated afresh, since an outbox posts an entry until it
	// was written TTL ago; the TTL that retry is fresh for; and MaxSkew, so a
	// clock that steps back by as much as two clocks a server takes are apart
	// reopens nothing (PROTOCOL.md §5 check 9). A step further back is the
	// floor's (client: seen-floor).
	SeenFor = 2*TTL + MaxSkew
)

// msgIDGrammar is a msg_id's one form: a UUID as RFC 9562 §4 writes one, its
// 4, 2, 2, 2 and 6 octets in hex with hyphens between, of any version, and in
// lowercase only, so one value has one text, as an address does.
var msgIDGrammar = regexp.MustCompile(`\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z`)

// IsMsgID reports whether s has the form of a msg_id, as a receiver checks
// one: what a sender may put in in_reply_to and supersedes.
func IsMsgID(s string) bool { return msgIDGrammar.MatchString(s) }

// The checks an envelope can fail, as codes: a closed set, so that whoever
// reads a refusal reads words this code chose.
const (
	RefusedMessage     = "bad_message"          // what was decrypted is not an envelope line and then a signature block
	RefusedEnvelope    = "bad_envelope"         // not UTF-8 JSON, one object with no key twice, version 1, with a body, a msg_id and a sent_at
	RefusedIdentity    = "bad_identity"         // the envelope carries no identity document, or one that breaks its format or its key checks
	RefusedKeyType     = "unsupported_key_type" // the sender's identity is a well-formed document of a key type this client does not verify
	RefusedSignature   = "bad_signature"        // not signed for this box by a working key the sender's identity certified, under a certificate valid now
	RefusedAttribution = "reattributed"         // its from is not the address of the identity that signed it, or its to is not this box
	RefusedStale       = "stale"                // its sent_at is older than TTL
	RefusedFuture      = "future"               // its sent_at is more than MaxSkew ahead of the reader's clock
)

// EnvelopeError is the check an envelope failed: one of the codes above and
// fixed words. It never quotes the envelope, whose text its sender chose: a
// refusal is read by whoever runs the client, and that may be a model.
type EnvelopeError struct{ Code, Why string }

func (e *EnvelopeError) Error() string { return e.Why }

func badEnvelope(why string) error { return &EnvelopeError{RefusedEnvelope, why} }

// Envelope is a message: one line of JSON, which the sender's working key
// signs. It is encrypted to the recipient's prekey with that signature after
// it (signed.go), so the server sees neither.
type Envelope struct {
	From   Address
	To     Address
	SentAt time.Time // to the second, UTC
	// MsgID is a random UUID (version 4), made once per logical message and
	// kept on every re-encryption, so a retry is never acted on twice.
	MsgID string
	// Body is the message: a JSON string, or any JSON value the sender sent
	// as one (PROTOCOL.md §4.2).
	Body json.RawMessage

	Subject    string // optional
	InReplyTo  string // optional: the msg_id replied to
	Supersedes string // optional: a msg_id of the same sender this replaces

	// Identity is the sender's identity document, exactly as hashed: it is
	// how a recipient checks a sender it has never met without asking the
	// server. From is its hash. A signed envelope always carries it; the line
	// a client delivers is built without it.
	Identity []byte
}

// wireEnvelope is the JSON form. No reader depends on the order of its
// members; they are written in the order PROTOCOL.md §4.2 lists them.
type wireEnvelope struct {
	V          json.Number     `json:"v"` // written as a number; read only as one
	From       Address         `json:"from"`
	To         Address         `json:"to"`
	SentAt     string          `json:"sent_at"`
	MsgID      string          `json:"msg_id"`
	Identity   Bytes           `json:"identity,omitempty"`
	Body       json.RawMessage `json:"body"`
	Subject    string          `json:"subject,omitempty"`
	InReplyTo  string          `json:"in_reply_to,omitempty"`
	Supersedes string          `json:"supersedes,omitempty"`
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
	return newEnvelope(from, to, b, now)
}

// NewJSONEnvelope returns an envelope whose body is a JSON value, given as a
// JSON text: an object, an array, a number, true, false, null, or a string,
// which is the body NewEnvelope makes of that string's text. The body is held
// to the rules its reader holds it to inside the envelope (PROTOCOL.md §0b,
// §5 check 3), and refused whole when it breaks one, never repaired: one JSON
// value and nothing after it, in UTF-8, with no name twice in any object,
// nested at most MaxDepth − 1 deep, no noncharacter, and no number past
// binary64. It is sent compact,
// its members in the order given and its strings and numbers as written, but
// that the line escapes U+2028 and U+2029, as encoding/json does in every
// string for JavaScript (RFC 8259 §12), which an envelope never is: the same
// value, and a reader verifies the line as it decrypted it (PROTOCOL.md
// §4.4). The script's jq writes them raw.
func NewJSONEnvelope(from, to Address, body []byte, now time.Time) (*Envelope, error) {
	if why := checkText(body, false, MaxDepth-1); why != "" {
		return nil, fmt.Errorf("the body is not a JSON value its reader takes (PROTOCOL.md §0b): %s", why)
	}
	v := jsontext.Value(bytes.Clone(body))
	if err := v.Compact(); err != nil {
		return nil, err
	}
	return newEnvelope(from, to, v, now)
}

func newEnvelope(from, to Address, body json.RawMessage, now time.Time) (*Envelope, error) {
	id, err := NewMsgID()
	if err != nil {
		return nil, err
	}
	return &Envelope{From: from, To: to, SentAt: now.UTC().Truncate(time.Second), MsgID: id, Body: body}, nil
}

// Marshal returns the envelope as compact UTF-8 JSON with no HTML escaping
// and no line feed after it.
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
		Identity:   e.Identity,
		Body:       e.Body,
		Subject:    e.Subject,
		InReplyTo:  e.InReplyTo,
		Supersedes: e.Supersedes,
	})
}

// Line returns the envelope as the one line that is signed and sent: Marshal,
// then a line feed. Compact JSON holds no line feed of its own, since JSON
// escapes one inside a string.
func (e *Envelope) Line() ([]byte, error) {
	if len(e.Identity) == 0 {
		return nil, errors.New("an envelope to sign carries its sender's identity document")
	}
	p, err := e.Marshal()
	if err != nil {
		return nil, err
	}
	return append(p, '\n'), nil
}

// OpenEnvelope parses an envelope and checks it, in this order: it is UTF-8
// JSON, one object with no key twice; it has a body, and every member it
// reads is of its type (from and to are addresses, 64 lowercase hex); it is
// version 1, an integer written as one; its from is the VERIFIED signer and
// its to is this box (a signature holds for one recipient, so a mismatch is a
// message passed on to a box it was not written to, or one whose from names a
// box that did not sign it); it has a msg_id; and sent_at is no older than TTL
// at now, and no more than MaxSkew ahead of it. A null member is one left out
// (PROTOCOL.md §0b), but for the body, whose null is a value.
//
// Keys match exactly, as in jq and every other strict reader: "BODY" is an
// unknown key, ignored, never the body. No key twice, so no two readers can
// take different values from the envelope's fields. The body itself is the
// verified sender's own JSON, passed on as it is.
//
// The caller has verified the signature over these same bytes (OpenSigned
// does both). Replay and duplicate checks need the caller's seen-set and are
// the caller's.
func OpenEnvelope(plaintext []byte, signer, me Address, now time.Time) (*Envelope, error) {
	e, err := OpenEnvelopeRecord(plaintext, signer, me)
	if err != nil {
		return nil, err
	}
	if e.SentAt.Before(now.Add(-TTL)) {
		return nil, &EnvelopeError{RefusedStale, fmt.Sprintf("sent_at is older than %d days", TTL/(24*time.Hour))}
	}
	if e.SentAt.After(now.Add(MaxSkew)) {
		return nil, &EnvelopeError{RefusedFuture, fmt.Sprintf("sent_at is more than %d minutes ahead of this machine's clock", MaxSkew/time.Minute)}
	}
	return e, nil
}

// OpenEnvelopeRecord checks an envelope as OpenEnvelope does, but for its
// sent_at, which it only parses: no clock is read. It is how a box reads back
// an envelope it made itself, in its outbox or its sent/ record, whose age is
// its own to judge. Nobody judging another box's mail uses it.
func OpenEnvelopeRecord(plaintext []byte, signer, me Address) (*Envelope, error) {
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
		"subject": &w.Subject, "in_reply_to": &w.InReplyTo, "supersedes": &w.Supersedes, "identity": &w.Identity,
	} {
		if raw, ok := fields[key]; ok {
			if err := jsonv2.Unmarshal(raw, dst); err != nil {
				return nil, badEnvelope("the envelope is malformed: its " + key + " is not what that field holds")
			}
		}
	}
	w.Body = fields["body"]
	// v is an integer member, read as every one is (PROTOCOL.md §0b): digits
	// alone, so 1.0 and 1e0 are no version.
	var v uint64
	if err := jsonv2.Unmarshal(fields["v"], &v, jsonv2.WithUnmarshalers(integers)); err != nil || v != EnvelopeVersion {
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
	e := &Envelope{
		From:       w.From,
		To:         w.To,
		SentAt:     sentAt,
		MsgID:      w.MsgID,
		Body:       w.Body,
		Subject:    w.Subject,
		InReplyTo:  w.InReplyTo,
		Supersedes: w.Supersedes,
		Identity:   w.Identity,
	}
	return e, nil
}

// objectFields reads an envelope's members by their exact names, once it is
// a JSON text as the protocol reads one (Unmarshal): one object, UTF-8, no
// name twice in any object in it, nested at most MaxDepth deep. A member is
// left as its raw JSON for the caller to read.
func objectFields(data []byte) (map[string]json.RawMessage, error) {
	switch why := checkJSON(data); why {
	case "":
	case whyTwice:
		return nil, badEnvelope("the envelope has a key twice")
	default:
		return nil, badEnvelope("the envelope is not one JSON object as the protocol reads one: " + why)
	}
	var fields map[string]json.RawMessage
	if err := jsonv2.Unmarshal(data, &fields); err != nil {
		return nil, badEnvelope("the envelope is not one JSON object")
	}
	return fields, nil
}

func utf8Valid(b []byte) bool { return utf8.Valid(b) }

// unmarshalString reads a JSON string, and nothing else, into dst. JSON null
// is the same as leaving the member out (PROTOCOL.md §0b): dst is left as it
// is.
func unmarshalString(raw json.RawMessage, dst *string) error {
	if string(raw) == "null" {
		return nil
	}
	if len(raw) == 0 || raw[0] != '"' {
		return errors.New("not a JSON string")
	}
	return jsonv2.Unmarshal(raw, dst)
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
