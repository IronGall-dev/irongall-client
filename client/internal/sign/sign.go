// Package sign holds a mailbox's keys, and is the one place they sign
// (TestOnlySignSigns). A mailbox is in one of two modes (PROTOCOL.md §5): in
// identity mode its identity signs what it says, its prekey statements, its
// passes and its messages; in working-key mode a working key under a
// certificate the identity made signs them. The identity signs certificates
// and revocations in both. So there are three signers, each from a
// constructor that checks the mode: [Identity], [Certifier] and [Work].
//
// Every signature asks the mailbox again, at the moment it is made, whether it
// may be made: a mailbox that holds its own revocation signs nothing more
// (PROTOCOL.md §12.5), one that holds a trip to working-key mode it did not
// make signs nothing but its address's revocation, and a signer of one mode
// signs nothing once the mailbox is in the other. A revocation of the address
// is always signed, but once the mailbox holds one: it is the answer to every
// one of those. No path, a new one included, signs around these checks.
package sign

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Mode is a mailbox's mode, as it holds it.
type Mode int

const (
	// IdentityMode is a mailbox that holds no revocation of its certificates:
	// its identity signs everything.
	IdentityMode Mode = iota
	// WorkingKeyMode is a mailbox that holds one: a working key under a
	// certificate above it signs what it says.
	WorkingKeyMode
)

// Checks is what a mailbox says at each signature. Finished is why it may sign
// nothing more, its own revocation, or nil. Mode is the mode it holds, or why
// it may sign nothing but its address's revocation: a trip it did not make.
type Checks struct {
	Finished func() error
	Mode     func() (Mode, error)
}

// ErrNotIdentityMode is a signature by the identity, of a statement, a pass or
// a message, asked of a mailbox in working-key mode: every holder of its trip
// refuses one, whatever it signs.
var ErrNotIdentityMode = errors.New("this mailbox is in working-key mode, where its identity signs no statement, pass or message: it sends and drains nothing until a statement under a certificate is taken (dromas prekey renew)")

// ErrNotWorkingKeyMode is a signature by a working key asked of a mailbox in
// identity mode: no holder of its address takes a certificate's.
var ErrNotWorkingKeyMode = errors.New("this mailbox is in identity mode, where no certificate is taken: its identity signs what it says")

// may is the check before a signature of a mode: the mailbox is not finished,
// holds no trip it did not make, and is in mode.
func (c Checks) may(mode Mode) error {
	if err := c.Finished(); err != nil {
		return err
	}
	m, err := c.Mode()
	switch {
	case err != nil:
		return err
	case m == mode:
		return nil
	case mode == IdentityMode:
		return ErrNotIdentityMode
	}
	return ErrNotWorkingKeyMode
}

// Certifier is a mailbox's identity key, as it signs in both modes:
// certificates and revocations.
type Certifier struct {
	key    ssh.Signer
	checks Checks
}

// NewCertifier holds key, the mailbox's identity, for a mailbox that answers
// checks.
func NewCertifier(key ssh.Signer, checks Checks) *Certifier {
	return &Certifier{key: key, checks: checks}
}

// PublicKey is the identity's public key.
func (k *Certifier) PublicKey() ssh.PublicKey { return k.key.PublicKey() }

// Certify signs a certificate of the working key work, of serial n, made at
// now and running for lifetime (protocol.NewCertificate).
func (k *Certifier) Certify(id *protocol.Identity, work ssh.PublicKey, n uint64, now time.Time, lifetime time.Duration) (*protocol.Certificate, error) {
	if err := k.either(); err != nil {
		return nil, err
	}
	return protocol.NewCertificate(id, k.key, work, n, now, lifetime)
}

// RevokedCertificates signs the revocation of certificates r
// (protocol.SignRevokedCertificates): the trip to working-key mode, the first
// one, or a later one that revokes more.
func (k *Certifier) RevokedCertificates(r *protocol.RevokedCertificates) ([]byte, error) {
	if err := k.either(); err != nil {
		return nil, err
	}
	return protocol.SignRevokedCertificates(k.key, r)
}

// Revocation signs the revocation of the address a (protocol.SignRevocation):
// the one signature a mailbox that holds a trip it did not make still makes.
func (k *Certifier) Revocation(a protocol.Address) ([]byte, error) {
	if err := k.checks.Finished(); err != nil {
		return nil, err
	}
	return protocol.SignRevocation(k.key, a)
}

// either is the check before a certificate or a revocation of certificates:
// in either mode, but not by a finished mailbox nor by one holding a trip it
// did not make.
func (k *Certifier) either() error {
	if err := k.checks.Finished(); err != nil {
		return err
	}
	_, err := k.checks.Mode()
	return err
}

// Identity is the mailbox's identity as it signs in identity mode, or why
// it may not.
func (k *Certifier) Identity() (*Identity, error) {
	if err := k.checks.may(IdentityMode); err != nil {
		return nil, err
	}
	return &Identity{key: k.key, checks: k.checks}, nil
}

// Identity is a mailbox's identity in identity mode: it signs its prekey
// statements, passes and messages.
type Identity struct {
	key    ssh.Signer
	checks Checks
}

// Statement signs prekey statement p, in its mailbox's prekey namespace.
func (k *Identity) Statement(p *protocol.Prekey) ([]byte, error) {
	if err := k.checks.may(IdentityMode); err != nil {
		return nil, err
	}
	return protocol.Sign(k.key, p.Statement(), protocol.PrekeyNamespace(p.Address))
}

// Message signs an envelope's line for its recipient to, in to's message
// namespace.
func (k *Identity) Message(line []byte, to protocol.Address) ([]byte, error) {
	if err := k.checks.may(IdentityMode); err != nil {
		return nil, err
	}
	return protocol.Sign(k.key, line, protocol.MessageNamespace(to))
}

// Pass signs a pass of the mailbox a, for the server named server, dated now
// (protocol.NewPass).
func (k *Identity) Pass(a protocol.Address, server string, now time.Time) (string, time.Time, error) {
	if err := k.checks.may(IdentityMode); err != nil {
		return "", time.Time{}, err
	}
	return protocol.NewPass(k.key, a, server, now)
}

// Work is a working key under its certificate, in working-key mode: it signs
// the mailbox's prekey statements, passes and messages.
type Work struct {
	key    ssh.Signer
	checks Checks
}

// NewWork holds key, a working key under its certificate, for a mailbox that
// answers checks, or says why it may not sign: the mailbox is not in
// working-key mode, or may sign nothing.
func NewWork(key ssh.Signer, checks Checks) (*Work, error) {
	if err := checks.may(WorkingKeyMode); err != nil {
		return nil, err
	}
	return &Work{key: key, checks: checks}, nil
}

// Statement signs prekey statement p, in its mailbox's prekey namespace.
func (k *Work) Statement(p *protocol.Prekey) ([]byte, error) {
	if err := k.checks.may(WorkingKeyMode); err != nil {
		return nil, err
	}
	return protocol.Sign(k.key, p.Statement(), protocol.PrekeyNamespace(p.Address))
}

// Message signs an envelope's line for its recipient to, in to's message
// namespace.
func (k *Work) Message(line []byte, to protocol.Address) ([]byte, error) {
	if err := k.checks.may(WorkingKeyMode); err != nil {
		return nil, err
	}
	return protocol.Sign(k.key, line, protocol.MessageNamespace(to))
}

// Pass signs a pass of the mailbox a, for the server named server, dated now
// (protocol.NewPass).
func (k *Work) Pass(a protocol.Address, server string, now time.Time) (string, time.Time, error) {
	if err := k.checks.may(WorkingKeyMode); err != nil {
		return "", time.Time{}, err
	}
	return protocol.NewPass(k.key, a, server, now)
}
