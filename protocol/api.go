package protocol

import (
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
)

// The API's JSON bodies. Every byte field is standard base64 of the exact
// file bytes, as in Google Pub/Sub's data and AWS KMS's CiphertextBlob.
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
// declared nothing takes IdentityEd25519 only (PROTOCOL.md §2).
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

// IdentityResponse is GET /v1/<address>/identity: the identity document and
// the current prekey statement with its signature. None of it is trusted
// until checked: the document against the address, the signature's
// certificate against the document, the statement against the certificate.
type IdentityResponse struct {
	Identity        Bytes `json:"identity"`
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
	// SenderKeyTypes is what the box declared with that prekey, on the
	// server's word: nothing signs it. A server that misstates it can only
	// stop a message, which it can do without it.
	SenderKeyTypes []string `json:"sender_key_types,omitempty"`
}

// SendRequest is the body of POST /v1/<recipient>: an age file encrypted to
// the recipient's prekey. The sender is the box whose pass the call carries.
// The message's signature is inside the file, so the server is handed none.
type SendRequest struct {
	// PrekeySerial is the serial of the prekey encrypted to. When the box
	// has a newer one the server answers stale_prekey, and the sender
	// encrypts the same signed envelope again.
	PrekeySerial *uint64 `json:"prekey_serial,omitempty"`
	// CertificateSerial is the serial of the certificate that prekey's
	// statement is signed under. A prekey is named by the two together: a
	// box's statements are ordered by certificate first, so a prekey serial
	// can come again under a later certificate.
	CertificateSerial *uint64 `json:"certificate_serial,omitempty"`
	Ciphertext        Bytes   `json:"ciphertext"`
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

// Receipt is the answer to a send. A retry of the same ciphertext gets the
// original receipt.
type Receipt struct {
	ID         string `json:"id"` // lowercase hex SHA-256 of the ciphertext
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
}

// MessageList is GET /v1/<address>/messages: one page of metadata, oldest
// first. NextCursor is null on the last page.
type MessageList struct {
	Count      int64         `json:"count"`
	Messages   []MessageInfo `json:"messages"`
	NextCursor *string       `json:"next_cursor"`
	PollAfter  int64         `json:"poll_after"`
}

// MessageInfo is one message in a list.
type MessageInfo struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Size       int64  `json:"size"`
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
}

// Message is GET /v1/<address>/messages/<id>. From is the box whose pass the
// send carried, on the server's word: a recipient holds it to the sender it
// verifies inside the ciphertext.
type Message struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
	Ciphertext Bytes  `json:"ciphertext"`
}
