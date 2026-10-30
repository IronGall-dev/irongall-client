package protocol

import (
	"crypto/sha512"
	"encoding/base32"
	"errors"
)

// Address is a mailbox's address: the SHA-384 of its identity document. Its
// text form is those 48 bytes in base32 (RFC 4648 §6) in lowercase, without
// padding, as Tor writes an onion address: AddressLen characters of a-z and
// 2-7, the only form clients may send. It has one case, so no two addresses
// differ only in case, and it never begins with "-".
type Address [sha512.Size384]byte

// AddressLen is the length of an address's text form: 384 bits in 5-bit
// characters, the last of which carries 4 bits and a zero.
const AddressLen = (8*sha512.Size384 + 4) / 5

// addressEncoding is RFC 4648 §6's alphabet in lowercase, without padding.
var addressEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// AddressOf returns the address of an identity document: its SHA-384.
func AddressOf(document []byte) Address { return sha512.Sum384(document) }

// LinkPath is where a server serves a page for each address: an address is
// shared as the link <server>/to/<address>, which tells whoever opens it
// what dromas is. A client takes the address from the link and never
// fetches the page.
const LinkPath = "/to/"

// errAddress is ParseAddress's one error, for any text not an address.
var errAddress = errors.New("an address is 77 characters of lowercase base32 (a-z 2-7)")

// ParseAddress parses the text form of an address: exactly AddressLen
// characters of lowercase base32, the one encoding of 48 bytes. The recipient
// compares addresses as exact strings, so uppercase is an error, not something
// to fold.
func ParseAddress(s string) (Address, error) {
	var a Address
	if len(s) != AddressLen {
		return a, errAddress
	}
	// The unused bit of the last character must be zero, so each address has
	// one text form: what is decoded is taken only if it encodes back to s.
	n, err := addressEncoding.Decode(a[:], []byte(s))
	if err != nil || n != len(a) || a.String() != s {
		return Address{}, errAddress
	}
	return a, nil
}

// String returns the address as AddressLen characters of lowercase base32.
func (a Address) String() string { return addressEncoding.EncodeToString(a[:]) }

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
