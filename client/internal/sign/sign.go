// Package sign holds a mailbox's keys: its identity, which signs certificates
// and revocations and nothing else, and its working keys, which sign what the
// mailbox says (PROTOCOL.md §5). Nothing else in the client signs with them
// (TestOnlySignSigns), and every signature first asks whether the mailbox holds
// its own revocation, and is refused if it does (PROTOCOL.md §12.5): no path,
// a new one included, can sign around that check.
package sign

import (
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Finished returns why the mailbox may sign nothing more, or nil.
type Finished func() error

// Identity is a mailbox's identity key.
type Identity struct {
	key      ssh.Signer
	finished Finished
}

// NewIdentity holds key, the mailbox's identity, for a mailbox that says whether it
// is finished.
func NewIdentity(key ssh.Signer, finished Finished) *Identity {
	return &Identity{key: key, finished: finished}
}

// PublicKey is the identity's public key.
func (k *Identity) PublicKey() ssh.PublicKey { return k.key.PublicKey() }

// Certify signs a certificate of the working key work, of serial n, made at
// now (protocol.NewCertificate).
func (k *Identity) Certify(id *protocol.Identity, work ssh.PublicKey, n uint64, now time.Time) (*protocol.Certificate, error) {
	if err := k.finished(); err != nil {
		return nil, err
	}
	return protocol.NewCertificate(id, k.key, work, n, now)
}

// Revocation signs the revocation of the address a (protocol.SignRevocation).
func (k *Identity) Revocation(a protocol.Address) ([]byte, error) {
	if err := k.finished(); err != nil {
		return nil, err
	}
	return protocol.SignRevocation(k.key, a)
}

// RevokedCertificates signs the revocation of certificates r
// (protocol.SignRevokedCertificates).
func (k *Identity) RevokedCertificates(r *protocol.RevokedCertificates) ([]byte, error) {
	if err := k.finished(); err != nil {
		return nil, err
	}
	return protocol.SignRevokedCertificates(k.key, r)
}

// Work is a working key, under its certificate.
type Work struct {
	key      ssh.Signer
	finished Finished
}

// NewWork holds key, a working key under its certificate, for a mailbox that
// says whether it is finished.
func NewWork(key ssh.Signer, finished Finished) *Work {
	return &Work{key: key, finished: finished}
}

// Signature signs message in namespace (protocol.Sign): a prekey statement,
// or a message.
func (k *Work) Signature(message []byte, namespace string) ([]byte, error) {
	if err := k.finished(); err != nil {
		return nil, err
	}
	return protocol.Sign(k.key, message, namespace)
}

// Pass signs a pass of the mailbox a, for the server named server, dated now
// (protocol.NewPass).
func (k *Work) Pass(a protocol.Address, server string, now time.Time) (string, time.Time, error) {
	if err := k.finished(); err != nil {
		return "", time.Time{}, err
	}
	return protocol.NewPass(k.key, a, server, now)
}
