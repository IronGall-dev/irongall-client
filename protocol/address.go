package protocol

import (
	"encoding/hex"
	"errors"
)

// Address is a box's address: the SHA-256 of its identity document. Its text
// form is 64 lowercase hex characters, the only form clients may send.
type Address [32]byte

// LinkPath is where a server serves a page for each address: an address is
// shared as the link <server>/to/<address>, which tells whoever opens it
// what crossbot is. A client takes the address from the link and never
// fetches the page.
const LinkPath = "/to/"

// ParseAddress parses the text form of an address: exactly 64 lowercase hex
// characters. The recipient compares addresses as exact strings, so uppercase
// is an error, not something to fold.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) != 64 {
		return a, errors.New("an address is 64 lowercase hex characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return a, errors.New("an address is 64 lowercase hex characters")
		}
	}
	_, err := hex.Decode(a[:], []byte(s))
	return a, err
}

// String returns the address as 64 lowercase hex characters.
func (a Address) String() string { return hex.EncodeToString(a[:]) }

// MarshalText implements [encoding.TextMarshaler].
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements [encoding.TextUnmarshaler], with [ParseAddress]'s rules.
func (a *Address) UnmarshalText(b []byte) error {
	v, err := ParseAddress(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}
