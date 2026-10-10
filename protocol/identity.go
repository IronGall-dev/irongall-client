package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

const (
	// IdentityTag is line 1 of every v1 identity document.
	IdentityTag = "crossbot-v1"
	// IdentityDocumentSize is the exact size of a v1 identity document.
	IdentityDocumentSize = 93
)

// identityGrammar is the whole document: the tag line, then an OpenSSH
// Ed25519 public key with no comment, each line ending in LF, nothing after.
var identityGrammar = regexp.MustCompile(`\Acrossbot-v1\nssh-ed25519 (AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43})\n\z`)

// Identity is a box's identity: its identity document, the Ed25519 key in it,
// and the address that document hashes to.
type Identity struct {
	doc  []byte
	key  ssh.PublicKey
	addr Address
}

// ParseIdentity parses an identity document. It must be exactly the two-line,
// 93-byte form, and its key a canonical Ed25519 point that is not of small
// order. Go's crypto/ed25519 and OpenSSH both accept small-order and
// non-canonical keys, so this check is explicit.
func ParseIdentity(doc []byte) (*Identity, error) {
	if len(doc) != IdentityDocumentSize {
		return nil, errors.New("an identity document is exactly 93 bytes: \"crossbot-v1\", LF, an ssh-ed25519 key with no comment, LF (look for a comment, CRLF, or a missing final newline)")
	}
	m := identityGrammar.FindSubmatch(doc)
	if m == nil {
		return nil, errors.New("not an identity document: \"crossbot-v1\", LF, an ssh-ed25519 key with no comment, LF")
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(string(m[1]))
	if err != nil {
		return nil, errors.New("the identity key is not valid base64")
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return nil, err
	}
	if key.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(key.Marshal(), wire) {
		return nil, errors.New("the identity key is not an ssh-ed25519 key")
	}
	raw := key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if err := checkEd25519(raw); err != nil {
		return nil, err
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
	doc := []byte(IdentityTag + "\n" + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n")
	return ParseIdentity(doc)
}

// Document returns the identity document, exactly as hashed.
func (id *Identity) Document() []byte { return bytes.Clone(id.doc) }

// Address returns the address: the SHA-256 of the identity document.
func (id *Identity) Address() Address { return id.addr }

// PublicKey returns the identity key, for verifying its signatures.
func (id *Identity) PublicKey() ssh.PublicKey { return id.key }

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
