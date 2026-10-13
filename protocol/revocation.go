package protocol

import (
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/ssh"
)

// Revocations is what a server or an index holds about an address: the body
// of PUT /v1/<address>/revocations and the answer to GET of the same path
// (PROTOCOL.md §6.3). It proves itself: the document hashes to the address
// and the signature verifies under the document's key, so it is worth the
// same from a server, an index or a file a person handed over.
//
// It is also the record a box's owner makes in advance and keeps apart from
// the box. It holds the identity document because a box that is lost no
// longer has one.
type Revocations struct {
	// Identity is the identity document of the address.
	Identity Bytes `json:"identity"`
	// Revocation is the identity's signature over RevocationStatement, in
	// RevokeNamespace: the address is revoked, for good.
	Revocation Bytes `json:"revocation,omitempty"`
	// RevokedCertificates is the address's list of revoked certificates, and
	// RevokedCertificatesSignature the identity's signature over it
	// (VerifyRevokedCertificates): the address goes on, and nothing signed
	// under a listed certificate is taken.
	RevokedCertificates          Bytes `json:"revoked_certificates,omitempty"`
	RevokedCertificatesSignature Bytes `json:"revoked_certificates_signature,omitempty"`
}

// ErrRevocation is a revocation that does not verify: its document does not
// hash to the address, or its signature is not the identity's own over the
// statement.
var ErrRevocation = errors.New("not a revocation of that address")

// SignRevocation signs the revocation of box a with its identity key. The
// statement is fixed text with no date in it, so the signature can be made
// long before it is used.
func SignRevocation(identity ssh.Signer, a Address) ([]byte, error) {
	return Sign(identity, RevocationStatement(a), RevokeNamespace(a))
}

// VerifyRevocation checks a revocation of address a: document must hash to a
// and be an identity document, and signature must be that identity's own
// over RevocationStatement(a), in RevokeNamespace(a). It returns the
// identity.
//
// The signature is the identity key's itself. One made by a working key,
// which carries a certificate, is refused: a working key can be stolen
// without the identity, and must not be able to end the address.
//
// An identity of a key type this build does not verify is ErrIdentityType,
// as from ParseIdentity: nothing it signed can be checked here, a revocation
// included. Everything else that fails is ErrRevocation.
func VerifyRevocation(a Address, document, signature []byte) (*Identity, error) {
	if Address(sha256.Sum256(document)) != a {
		return nil, ErrRevocation
	}
	id, err := ParseIdentity(document)
	if errors.Is(err, ErrIdentityType) {
		return nil, err
	}
	if err != nil {
		return nil, ErrRevocation
	}
	if Verify(id, RevocationStatement(a), signature, RevokeNamespace(a)) != nil {
		return nil, ErrRevocation
	}
	return id, nil
}
