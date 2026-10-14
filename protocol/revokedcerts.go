package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// RevokedCertsTag is line 1 of a revocation of certificates.
const RevokedCertsTag = "irongall-revoke-certs-v1"

// RevokedCertsNamespace is the namespace of box a's revocation of its
// certificates.
func RevokedCertsNamespace(a Address) string { return RevokedCertsTag + ":" + a.String() }

// ErrRevokedCertificates is a revocation of certificates that is malformed,
// is another address's, or is not signed by that address's identity itself.
var ErrRevokedCertificates = errors.New("not a revocation of that address's certificates")

// RevokedCertificates is what an identity signs to revoke the certificates it
// made for its address, and keep the address (PROTOCOL.md §6.3a): every
// certificate whose serial is Through or below. Nothing signed under one is
// taken, whenever it was signed. Through is its own order: whoever holds one
// keeps the highest it has verified, and one that is not higher changes
// nothing, so a certificate once revoked stays revoked.
type RevokedCertificates struct {
	Address Address
	Through uint64
}

// Revokes reports whether a certificate of this serial is revoked.
func (r *RevokedCertificates) Revokes(serial uint64) bool { return serial <= r.Through }

// Statement returns the revocation as it is signed: the tag, the address and
// the serial it revokes through, each on a line.
func (r *RevokedCertificates) Statement() []byte {
	return []byte(RevokedCertsTag + "\n" + r.Address.String() + "\n" + strconv.FormatUint(r.Through, 10) + "\n")
}

// NewRevokedCertificates builds box a's revocation of every certificate up to
// and including serial through, which is one a certificate may have.
func NewRevokedCertificates(a Address, through uint64) (*RevokedCertificates, error) {
	if through == 0 || through > MaxSerial {
		return nil, ErrRevokedCertificates
	}
	return &RevokedCertificates{Address: a, Through: through}, nil
}

// ParseRevokedCertificates parses a revocation of certificates exactly: the
// tag, a lowercase address and a serial from 1 to MaxSerial with no leading
// zero, each on a line ending in LF, and nothing else: no CR, no blank line,
// no byte after the last LF.
func ParseRevokedCertificates(statement []byte) (*RevokedCertificates, error) {
	lines := bytes.Split(statement, []byte("\n"))
	if len(lines) != 4 || len(lines[3]) != 0 || string(lines[0]) != RevokedCertsTag {
		return nil, ErrRevokedCertificates
	}
	a, err := ParseAddress(string(lines[1]))
	if err != nil {
		return nil, ErrRevokedCertificates
	}
	through, ok := parseSerial(lines[2])
	if !ok {
		return nil, ErrRevokedCertificates
	}
	return &RevokedCertificates{Address: a, Through: through}, nil
}

// parseSerial reads a serial as a prekey statement writes one: a decimal
// integer from 1 to MaxSerial, with no leading zero.
func parseSerial(s []byte) (uint64, bool) {
	if !serialGrammar.Match(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(s), 10, 64)
	return n, err == nil && n <= MaxSerial
}

// SignRevokedCertificates signs a revocation of certificates with the
// identity key of its address.
func SignRevokedCertificates(identity ssh.Signer, r *RevokedCertificates) ([]byte, error) {
	return Sign(identity, r.Statement(), RevokedCertsNamespace(r.Address))
}

// VerifyRevokedCertificates checks a revocation of address a's certificates:
// document must hash to a and be an identity document, signature must be
// that identity's own over statement, in RevokedCertsNamespace(a), and
// statement must be a revocation of certificates, in its exact form, that
// names a. As with a revocation of the address, a working key's signature is
// refused: a certificate cannot revoke another, or itself.
//
// An identity of a key type this build does not verify is ErrIdentityType.
// Everything else that fails is ErrRevokedCertificates.
func VerifyRevokedCertificates(a Address, document, statement, signature []byte) (*RevokedCertificates, error) {
	if Address(sha256.Sum256(document)) != a {
		return nil, ErrRevokedCertificates
	}
	id, err := ParseIdentity(document)
	if errors.Is(err, ErrIdentityType) {
		return nil, err
	}
	if err != nil {
		return nil, ErrRevokedCertificates
	}
	if Verify(id, statement, signature, RevokedCertsNamespace(a)) != nil {
		return nil, ErrRevokedCertificates
	}
	r, err := ParseRevokedCertificates(statement)
	if err != nil || r.Address != a {
		return nil, ErrRevokedCertificates
	}
	return r, nil
}
