package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

const (
	// IdentityTag is line 1 of every v1 identity document.
	IdentityTag = "irongall-v1"
	// IdentityDocumentSize is the exact size of an ssh-ed25519 identity
	// document. Another key type's document has another size, as exact.
	IdentityDocumentSize = 93
)

// The identity key types this package defines: the SSH name on line 2 of an
// identity document. Every client verifies IdentityEd25519. Every other type
// is optional: a box of one is reached only by clients that verify it
// (PROTOCOL.md §2).
const (
	IdentityEd25519 = ssh.KeyAlgoED25519
	IdentityP256    = ssh.KeyAlgoECDSA256
)

// IdentityTypes returns the identity key types this package verifies, the one
// every client must verify first.
func IdentityTypes() []string { return []string{IdentityEd25519, IdentityP256} }

// Every ParseIdentity error wraps one of these: the document breaks its
// format, its key fails the key checks, or it is a well-formed document of a
// key type this package does not define. A server answers the first with
// identity_mismatch, the second with bad_key and the third with
// unsupported_key_type.
var (
	ErrIdentityFormat = errors.New("not an identity document")
	ErrIdentityKey    = errors.New("bad identity key")
	ErrIdentityType   = errors.New("an identity key type this client does not verify")
)

// identityForm is the form every identity document has, whatever its key
// type: the tag line, then an SSH key type's name (RFC 4251 §6: printable
// ASCII with no comma, at most 64 characters), one space and base64, each line
// ending in LF, nothing after. It is what lets a client tell a document of a
// type it lacks from something that is no document.
var identityForm = regexp.MustCompile(`\A` + IdentityTag + `\n([!-+\--~]{1,64}) ([A-Za-z0-9+/]+={0,2})\n\z`)

// A defined type: its document's one exact form, in words and as a pattern,
// the checks its key must pass beyond parsing as a key of that type in its one
// encoding, and the most bytes a signature by a box of that type may be
// (SignatureBound).
var identityTypes = map[string]struct {
	form  *regexp.Regexp
	shape string
	check func(ssh.PublicKey) error
	bound int
}{
	// 93 bytes: the key's base64 is 68 characters, of which 25 are fixed and
	// the 26th is one of A to P, the low two bits of the key's length, 32.
	// Its largest signature is 850 bytes, a prekey statement's.
	IdentityEd25519: {
		form:  identityGrammar,
		shape: "it is exactly 93 bytes: \"irongall-v1\", LF, an ssh-ed25519 key with no comment, LF (look for a comment, CRLF, or a missing final newline)",
		check: func(k ssh.PublicKey) error {
			return checkEd25519(k.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))
		},
		bound: 4096,
	},
	// 173 bytes: the key's base64 is 140 characters, of which 53 are fixed,
	// the point's leading 04 (uncompressed) among them. Its largest
	// signature is 947 bytes, a prekey statement's.
	IdentityP256: {
		form:  regexp.MustCompile(`\A` + IdentityTag + `\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB[A-P][A-Za-z0-9+/]{84}[AEIMQUYcgkosw048]=\n\z`),
		shape: "it is exactly 173 bytes: \"irongall-v1\", LF, an ecdsa-sha2-nistp256 key with no comment, LF (look for a comment, CRLF, or a missing final newline)",
		check: func(k ssh.PublicKey) error { return checkP256(k.Marshal()) },
		bound: 4096,
	},
}

// identityGrammar is the whole ssh-ed25519 document: the tag line, then an
// OpenSSH Ed25519 public key with no comment, each line ending in LF, nothing
// after. The key's length is 32 (RFC 8709 §4), so the character holding its
// low two bits is one of A to P: a length of 33 to 35 is no key OpenSSH or
// x/crypto/ssh reads, and would be another document for the same 32 bytes.
var identityGrammar = regexp.MustCompile(`\A` + IdentityTag + `\nssh-ed25519 (AAAAC3NzaC1lZDI1NTE5AAAAI[A-P][A-Za-z0-9+/]{42})\n\z`)

// Identity is a box's identity: its identity document, the key in it, and the
// address that document hashes to.
type Identity struct {
	doc  []byte
	key  ssh.PublicKey
	addr Address
}

// ParseIdentity parses an identity document. It must be exactly the two-line
// form of its key type, the key in its one encoding, and the key must pass
// that type's checks: for Ed25519 a canonical point that is not of small
// order, for P-256 what OpenSSH required of a point on the curve up to
// 10.2p1. Go's crypto/ed25519 accepts small-order and non-canonical Ed25519
// keys, as OpenSSH's own code did before 10.6p1, and Go accepts P-256 points
// OpenSSH refused up to 10.2p1, so each check is explicit.
//
// A well-formed document of a type this package does not define is
// ErrIdentityType: nothing is wrong with it, and nothing it signed can be
// checked here.
func ParseIdentity(doc []byte) (*Identity, error) {
	m := identityForm.FindSubmatch(doc)
	if m == nil {
		return nil, fmt.Errorf("%w: it is \"irongall-v1\", LF, one SSH public key with no comment, LF (look for a comment, CRLF, or a missing final newline)", ErrIdentityFormat)
	}
	name, b64 := string(m[1]), string(m[2])
	wire, err := base64.StdEncoding.Strict().DecodeString(b64)
	t, defined := identityTypes[name]
	if !defined {
		// A document at all? Its key is base64, in its one encoding, of an
		// SSH wire key, which begins with its own type's name.
		if err != nil || !bytes.HasPrefix(wire, sshString(name)) {
			return nil, fmt.Errorf("%w: line 2 is a key type's name, a space, and that key in base64", ErrIdentityFormat)
		}
		return nil, ErrIdentityType
	}
	if !t.form.Match(doc) {
		return nil, fmt.Errorf("%w: %s", ErrIdentityFormat, t.shape)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: it is not valid base64", ErrIdentityKey)
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse as a public key", ErrIdentityKey)
	}
	if key.Type() != name || !bytes.Equal(key.Marshal(), wire) {
		return nil, fmt.Errorf("%w: it is not a key of the type it names, in that type's one encoding", ErrIdentityKey)
	}
	if err := t.check(key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityKey, err)
	}
	return &Identity{
		doc:  bytes.Clone(doc),
		key:  key,
		addr: sha256.Sum256(doc),
	}, nil
}

// NewIdentity builds the identity document for an Ed25519 public key and
// parses it, with every check ParseIdentity makes.
func NewIdentity(pub ed25519.PublicKey) (*Identity, error) {
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return IdentityOf(key)
}

// IdentityOf builds the identity document for a public key of any type this
// package defines and parses it, with every check ParseIdentity makes.
func IdentityOf(key ssh.PublicKey) (*Identity, error) {
	doc := []byte(IdentityTag + "\n" + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n")
	return ParseIdentity(doc)
}

// Document returns the identity document, exactly as hashed.
func (id *Identity) Document() []byte { return bytes.Clone(id.doc) }

// Address returns the address: the SHA-256 of the identity document.
func (id *Identity) Address() Address { return id.addr }

// PublicKey returns the identity key, for verifying its signatures.
func (id *Identity) PublicKey() ssh.PublicKey { return id.key }

// Type returns the identity's key type: the name on line 2 of its document.
func (id *Identity) Type() string { return id.key.Type() }

// sshString is s as an SSH wire string: its length in four bytes, then it.
func sshString(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...) //nolint:gosec // a key type's name: at most 64 bytes
}

// checkEd25519 rejects a key that is not a canonical encoding of a curve
// point, or that is of small order, as libsodium does. A small-order key can
// make one signature verify for many messages.
func checkEd25519(k ed25519.PublicKey) error {
	if len(k) != ed25519.PublicKeySize {
		return errors.New("an Ed25519 key is 32 bytes")
	}
	p, err := new(edwards25519.Point).SetBytes(k)
	if err != nil {
		return errors.New("the identity key is not a point on the curve")
	}
	// SetBytes accepts non-canonical encodings; a canonical one re-encodes
	// to the same bytes.
	if !bytes.Equal(p.Bytes(), k) {
		return errors.New("the identity key is not canonically encoded")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("the identity key is of small order")
	}
	return nil
}

// checkP256 holds a P-256 key, given in SSH wire form, to what OpenSSH
// required of an EC public key beyond a point on the curve up to 10.2p1
// (sshkey_ec_validate_public): each coordinate is longer than half the bits
// of the group's order n, and below n-1. The library has already refused a
// point that is off the curve, compressed, or written with a coordinate of
// the field's size or more.
// OpenSSH dropped the two checks in 10.3p1 as not needed; they stay here,
// and a script on a later OpenSSH takes such a key, a known variance
// (PROTOCOL.md §3).
func checkP256(wire []byte) error {
	const point = 1 + 32 + 32 // 04, x, y
	if len(wire) < point || wire[len(wire)-point] != 4 {
		return errors.New("a P-256 key is an uncompressed point")
	}
	n := elliptic.P256().Params().N
	limit := new(big.Int).Sub(n, big.NewInt(1))
	q := wire[len(wire)-point+1:]
	for _, c := range [][]byte{q[:32], q[32:]} {
		v := new(big.Int).SetBytes(c)
		if v.BitLen() <= n.BitLen()/2 || v.Cmp(limit) >= 0 {
			return errors.New("the identity key is a P-256 point whose coordinate is too short, or is the group's order less one or more")
		}
	}
	return nil
}
