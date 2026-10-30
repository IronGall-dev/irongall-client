package protocol

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
)

// Address is a mailbox's address: the SHA-384 of its identity document. Its
// text form is those 48 bytes in unpadded base64url (RFC 4648 §5), 64
// characters, the only form clients may send.
type Address [sha512.Size384]byte

// AddressOf returns the address of an identity document: its SHA-384.
func AddressOf(document []byte) Address { return sha512.Sum384(document) }

// LinkPath is where a server serves a page for each address: an address is
// shared as the link <server>/to/<address>, which tells whoever opens it
// what dromas is. A client takes the address from the link and never
// fetches the page.
const LinkPath = "/to/"

// errAddress is ParseAddress's one error, for any text not an address.
var errAddress = errors.New("an address is 64 characters of unpadded base64url (A-Z a-z 0-9 - _)")

// ParseAddress parses the text form of an address: exactly 64 characters of
// unpadded base64url, the one encoding of 48 bytes. The recipient compares
// addresses as exact strings, so a letter in the other case is another
// address, never one to fold.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) != 64 {
		return a, errAddress
	}
	n, err := base64.RawURLEncoding.Strict().Decode(a[:], []byte(s))
	if err != nil || n != len(a) {
		return Address{}, errAddress
	}
	return a, nil
}

// String returns the address as 64 characters of unpadded base64url.
func (a Address) String() string { return base64.RawURLEncoding.EncodeToString(a[:]) }

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
