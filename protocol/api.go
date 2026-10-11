package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// The API's JSON bodies. Every byte field is standard base64 of the exact
// file bytes, as in Google Pub/Sub's data and AWS KMS's CiphertextBlob.
// Addresses and message ids travel as strings, so a client can refuse one bad
// entry without losing the rest of a response.

// TokenHeader carries a refreshed owner token on any owner response during a
// server-key rotation: standard base64 of an age file encrypted to the box's
// current prekey, like TokenResponse.Token.
const TokenHeader = "irongall-token" //nolint:gosec // a header name, not a credential

// ErrNotBase64 is returned when a byte field is not standard base64.
var ErrNotBase64 = errors.New("a byte field is not standard base64 of the exact bytes")

// Bytes is a byte field: standard base64 on the wire. Line breaks inside the
// base64 are ignored, so wrapped base64 decodes exactly.
type Bytes []byte

// MarshalJSON implements [json.Marshaler].
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

// UnmarshalJSON implements [json.Unmarshaler]. JSON null leaves the field
// unset; anything but a base64 string is [ErrNotBase64].
func (b *Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return ErrNotBase64
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ErrNotBase64
	}
	*b = v
	return nil
}

// RegisterRequest is the body of PUT /v1/<address>: the identity document, and
// the first prekey statement with the identity's signature over it.
type RegisterRequest struct {
	Identity        Bytes `json:"identity"`
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
}

// PrekeyRequest is the body of PUT /v1/<address>/prekey: a new prekey
// statement, signed by the identity.
type PrekeyRequest struct {
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
}

// TokenResponse carries the owner token, as an age file encrypted to the
// box's current prekey, so only the prekey's holder can read it.
type TokenResponse struct {
	Token Bytes `json:"token"`
}

// IdentityResponse is GET /v1/<address>/identity: the identity document and
// the current prekey statement with its signature. None of it is trusted
// until checked: the document against the address, the statement against the
// document.
type IdentityResponse struct {
	Identity        Bytes `json:"identity"`
	Prekey          Bytes `json:"prekey"`
	PrekeySignature Bytes `json:"prekey_signature"`
}

// SendRequest is the body of POST /v1/<recipient>: an age file encrypted to
// the recipient's prekey, and the sender's signature over it in the
// recipient's message namespace.
type SendRequest struct {
	From string `json:"from"`
	// PrekeySerial is the serial of the prekey encrypted to. When the box
	// has a newer one the server answers stale_prekey, and the sender
	// re-encrypts the same envelope.
	PrekeySerial *uint64 `json:"prekey_serial,omitempty"`
	Ciphertext   Bytes   `json:"ciphertext"`
	Signature    Bytes   `json:"signature"`
}

// AdoptRequest is the body of PUT /v1/<address>/account (Bearer): an adopt
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
	Count      int           `json:"count"`
	Messages   []MessageInfo `json:"messages"`
	NextCursor *string       `json:"next_cursor"`
	PollAfter  int           `json:"poll_after"`
}

// MessageInfo is one message in a list.
type MessageInfo struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Size       int    `json:"size"`
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
}

// Message is GET /v1/<address>/messages/<id>.
type Message struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	ReceivedAt string `json:"received_at"`
	ExpiresAt  string `json:"expires_at"`
	Ciphertext Bytes  `json:"ciphertext"`
	Signature  Bytes  `json:"signature"`
}
