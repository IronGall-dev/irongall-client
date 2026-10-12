package protocol

import "encoding/base64"

// tokenPrefix starts every owner token; tokenBytes is what follows it, once
// decoded: kid ‖ epoch ‖ mac (PROTOCOL.md §6.1).
const (
	tokenPrefix = "igt1_"
	tokenBytes  = 37
)

// IsToken reports whether b has the form of an owner token: "igt1_" and the
// canonical base64url, without padding, of 37 bytes. A client checks it before
// it keeps or sends what it decrypted as a token. A message is an age file to
// the same prekey, so a server can offer one where a token belongs, and a
// client that did not look would send the message back as its bearer.
func IsToken(b []byte) bool {
	// The length is checked first: the decoder skips line breaks, so a token
	// with one after it would otherwise pass.
	if len(b) != len(tokenPrefix)+base64.RawURLEncoding.EncodedLen(tokenBytes) || string(b[:len(tokenPrefix)]) != tokenPrefix {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(b[len(tokenPrefix):]))
	return err == nil && len(raw) == tokenBytes
}
