package protocol

import (
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The API's JSON bodies. Every byte field is standard base64 of the exact
// file bytes, as in Google Pub/Sub's data and AWS KMS's CiphertextBlob, but a
// message's ciphertext, which is the body itself on a send and on a fetch.
// Addresses and message ids travel as strings, so a client can refuse one bad
// entry without losing the rest of a response.

// ErrNotBase64 is returned when a byte field is not standard base64.
var ErrNotBase64 = errors.New("a byte field is not standard base64 of the exact bytes, in its one encoding")

// Bytes is a byte field: standard base64 on the wire, in its one encoding
// (RFC 4648 §3): padded, with nothing outside the alphabet, a line break
// included, and the unused bits of its last character zero. So a field has
// one text, and no two readers decode it two ways.
type Bytes []byte

// MarshalJSON implements [json.Marshaler].
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

// UnmarshalJSON implements [json.Unmarshaler]. JSON null leaves the field
// unset; anything but a string of base64 in its one encoding is
// [ErrNotBase64]. The string is the one encoding when encoding what it
// decodes to gives it back.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := jsonv2.Unmarshal(data, &s); err != nil {
		return ErrNotBase64
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(v) != s {
		return ErrNotBase64
	}
	*b = v
	return nil
}

// AnySender is the one entry of a declaration of sender key types that is no
// key type's name: the box does not say which types its client verifies, and
// a server makes no check for it.
const AnySender = "any"

// AcceptsSender reports whether a box that declared the sender key types
// declared takes mail from a box whose identity is of type t, as far as the
// declaration says: IdentityEd25519 always, whatever was declared; any type
// if it declared AnySender; otherwise only a type it listed. A box that
// declared nothing takes IdentityEd25519 only (PROTOCOL.md §7).
func AcceptsSender(declared []string, t string) bool {
	return t == IdentityEd25519 || slices.Contains(declared, t) || slices.Contains(declared, AnySender)
}

// RegisterRequest is the body of PUT /v1/<address>: the identity document, and
// the first prekey statement with the signature over it of a working key the
// identity certified. The call carries a pass under that certificate.
type RegisterRequest struct {
	Identity        Bytes `json:"identity"`
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
	// SenderKeyTypes declares the identity key types the box's client
	// verifies: the senders the box takes mail from (AcceptsSender). It is
	// not signed, and it stands until the box's next prekey replaces it.
	SenderKeyTypes []string `json:"sender_key_types,omitempty"`
}

// PrekeyRequest is the body of PUT /v1/<address>/prekey: a new prekey
// statement, signed by a working key the identity certified. The call carries
// a pass under that certificate, which is how a box moves to a new one.
type PrekeyRequest struct {
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
	// SenderKeyTypes is the declaration that comes with this prekey, in
	// place of the one before: none, if it is left out.
	SenderKeyTypes []string `json:"sender_key_types,omitempty"`
}

// BoxResponse is GET /v1/<address>, the one read of a box: everything a
// sender needs before it posts (PROTOCOL.md §11.8). None of it is trusted
// until checked: the document against the address, the signature's
// certificate against the document, the statement against the certificate,
// and the revocation of certificates against the identity. A revoked
// address is answered 410 revoked with its record instead (Problem.Record).
type BoxResponse struct {
	Identity        Bytes `json:"identity"`
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
	// SenderKeyTypes is what the box declared with that prekey, on the
	// server's word: nothing signs it. A server that misstates it can only
	// stop a message, which it can do without it.
	SenderKeyTypes []string `json:"sender_key_types,omitempty"`
	// RevokedCertificates and RevokedCertificatesSignature are the
	// identity's revocation of its certificates that the server holds, as a
	// record carries them (Revocations).
	RevokedCertificates          Bytes `json:"revoked_certificates,omitempty"`
	RevokedCertificatesSignature Bytes `json:"revoked_certificates_signature,omitempty"`
}

// Record is the revocation record that what b carries makes, or nil when it
// carries no revocation of certificates.
func (b *BoxResponse) Record() *Revocations {
	if len(b.RevokedCertificates) == 0 && len(b.RevokedCertificatesSignature) == 0 {
		return nil
	}
	return &Revocations{Identity: b.Identity, RevokedCertificates: b.RevokedCertificates, RevokedCertificatesSignature: b.RevokedCertificatesSignature}
}

// CiphertextContentType is the media type of a message's ciphertext, the
// body of a send and of a fetch: the age file's exact bytes.
const CiphertextContentType = "application/octet-stream"

// MaxCiphertext is the most bytes a message's ciphertext may be, in a send and
// in a fetch (PROTOCOL.md §11.10): every reader takes one of any size up to it,
// and a server's caps on a ciphertext are at most it. It is a whole number of
// its own padding blocks (PaddedSize), so a message that fits it bare fits it
// padded. A larger one is a new version of the protocol (§14).
const MaxCiphertext = 16 << 20

// SendQuery is the query of POST /v1/<recipient>/messages, whose body is an
// age file encrypted to the recipient's prekey. The sender is the box whose
// pass the call carries. The message's signature is inside the file, so the
// server is handed none.
type SendQuery struct {
	// PrekeySerial is the serial of the prekey encrypted to. When the box
	// has a newer one the server answers stale_prekey, and the sender
	// encrypts the same signed envelope again.
	PrekeySerial uint64
	// CertificateSerial is the serial of the certificate that prekey's
	// statement is signed under. A prekey is named by the two together: a
	// box's statements are ordered by certificate first, so a prekey serial
	// can come again under a later certificate.
	CertificateSerial uint64
}

// The names of a send's query parameters.
const (
	PrekeySerialParam      = "prekey_serial"
	CertificateSerialParam = "certificate_serial"
)

// Encode writes q as a query, without its "?".
func (q SendQuery) Encode() string {
	return PrekeySerialParam + "=" + strconv.FormatUint(q.PrekeySerial, 10) + "&" + CertificateSerialParam + "=" + strconv.FormatUint(q.CertificateSerial, 10)
}

// ErrQuery is returned for a query a server refuses: a parameter it does not
// know, one given twice, or a value not of its form.
var ErrQuery = errors.New("the query does not read as this call's")

// QueryError is an ErrQuery that names the parameter at fault, which a 400
// carries in member (PROTOCOL.md §11.2).
type QueryError struct{ Param string }

func (e *QueryError) Error() string { return fmt.Sprintf("%v: %s", ErrQuery, e.Param) }

// Unwrap returns ErrQuery.
func (e *QueryError) Unwrap() error { return ErrQuery }

// ParseSendQuery reads a send's query as a server reads it: each serial
// once, written as a statement writes one (a decimal integer from 1 to
// MaxSerial, with no leading zero), and no other parameter.
func ParseSendQuery(raw string) (SendQuery, error) {
	v, err := ParseQuery(raw, PrekeySerialParam, CertificateSerialParam)
	if err != nil {
		return SendQuery{}, err
	}
	var q SendQuery
	for _, p := range []struct {
		name string
		into *uint64
	}{{PrekeySerialParam, &q.PrekeySerial}, {CertificateSerialParam, &q.CertificateSerial}} {
		s, ok := v[p.name]
		n, isSerial := parseSerial([]byte(s))
		if !ok || !isSerial {
			return SendQuery{}, &QueryError{p.name}
		}
		*p.into = n
	}
	return q, nil
}

// ParseQuery reads a query of the given parameters: each at most once, and
// none other (PROTOCOL.md §11.2). A parameter left out is not in the map.
func ParseQuery(raw string, params ...string) (map[string]string, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return nil, &QueryError{""}
	}
	out := make(map[string]string, len(v))
	for _, name := range slices.Sorted(maps.Keys(v)) {
		if !slices.Contains(params, name) || len(v[name]) != 1 {
			return nil, &QueryError{name}
		}
		out[name] = v[name][0]
	}
	return out, nil
}

// AdoptRequest is the body of PUT /v1/<address>/account (with a pass): an adopt
// key an account minted. The box joins that account, which may lift its
// limits.
type AdoptRequest struct {
	Key string `json:"key"`
}

// AccountResponse names the account a box now belongs to.
type AccountResponse struct {
	Account string `json:"account"`
}

// Receipt is the answer to a send. A send of a ciphertext the box holds
// unacked gets the receipt it holds (PROTOCOL.md §11.10, step 6).
type Receipt struct {
	ID         string `json:"id"` // lowercase hex SHA-256 of the ciphertext
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
}

// MessageList is GET /v1/<address>/messages: one page of metadata, oldest
// first. NextCursor is null on the last page, and otherwise a cursor
// (CheckCursor). The poll interval is no member: every list answer, a 304
// among them, carries it in Retry-After (PollInterval).
type MessageList struct {
	Count      int64         `json:"count"`
	Messages   []MessageInfo `json:"messages"`
	NextCursor *string       `json:"next_cursor"`
}

// PollInterval reads a list answer's Retry-After: the server's poll interval
// in seconds, delay-seconds in digits alone, as a 429's (PROTOCOL.md §11.11,
// §11.3). A list answer without one, or with one of another form, breaks its
// form. More digits than a uint64 holds read as the most it holds: a reader
// bounds the wait it takes.
func PollInterval(v string) (uint64, error) {
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0, errors.New("the list's Retry-After is not delay-seconds")
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return math.MaxUint64, nil
	}
	return n, nil
}

// Wait reads a list's wait, the long poll's seconds: delay-seconds, digits
// alone, as Retry-After is (PROTOCOL.md §11.11). Any other form is no wait,
// and an error. More digits than a uint64 holds read as the most it holds:
// a server holds a list for at most a time of its own.
func Wait(v string) (uint64, error) {
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0, errors.New("the list's wait is not delay-seconds")
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return math.MaxUint64, nil
	}
	return n, nil
}

// MessageInfo is one message in a list (PROTOCOL.md §11.11). Size is the
// ciphertext's length in bytes: GET /v1/<address>/messages/<id> answers the
// ciphertext itself (CiphertextContentType), and nothing else.
type MessageInfo struct {
	ID         string `json:"id"`
	Size       int64  `json:"size"`
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
}

// cursorGrammar is a list's cursor: opaque and URL-safe, one or more of
// base64url's alphabet (AEP-158; PROTOCOL.md §11.11).
var cursorGrammar = regexp.MustCompile(`\A[A-Za-z0-9_-]+\z`)

// CheckCursor checks that s is a cursor as a list may hand one out. A client
// refuses a list whose next_cursor is not one.
func CheckCursor(s string) error {
	if !cursorGrammar.MatchString(s) {
		return errors.New("the cursor is not one or more of A-Z, a-z, 0-9, - and _")
	}
	return nil
}

// checkType refuses a list whose next_cursor is not a cursor (CheckCursor),
// or that gives a message a size past MaxCiphertext, which is no
// ciphertext's (PROTOCOL.md §11.10): either breaks the list's form, as a
// member of another type does, so it is no answer, and a reader allocates
// nothing by a size it gives that is not held here first.
func (l *MessageList) checkType() error {
	if l.NextCursor != nil && CheckCursor(*l.NextCursor) != nil {
		return &memberError{name: "next_cursor", known: true}
	}
	for _, m := range l.Messages {
		if m.Size > MaxCiphertext {
			return &memberError{name: "size", known: true}
		}
	}
	return nil
}
