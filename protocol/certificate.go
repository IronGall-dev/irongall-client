package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/IronGall-dev/irongall-client/sshsig"
	"golang.org/x/crypto/ssh"
)

// A box's identity signs nothing but certificates. A certificate names a
// working key, and the working key signs what the box says (PROTOCOL.md §2b).

const (
	// CertificateKeyID is the key id of every v1 certificate.
	CertificateKeyID = "irongall-cert-v1"
	// MaxCertificateLifetime is the longest a certificate may still have to
	// run: twice the TTL, so that a certificate with more than a TTL left
	// outlasts the mail it signs.
	MaxCertificateLifetime = 2 * TTL
)

// Every certificate error wraps one of these. ErrCertificate: it is not a
// certificate of this identity, or it breaks a rule of the format; no clock
// makes it good. ErrCertificateTime: it has not begun or it has ended, by the
// verifier's own clock.
var (
	ErrCertificate     = errors.New("bad certificate")
	ErrCertificateTime = errors.New("the certificate is not valid now")
)

// Certificate is a working key's certificate that has passed CheckCertificate.
type Certificate struct {
	cert *ssh.Certificate
}

// CheckCertificate checks that key is a certificate the identity id signed
// for a working key, and that it is valid at now. A certificate is checked
// against the verifier's own clock, never a time someone else states.
//
// The rules: a user certificate with the key id CertificateKeyID, a serial of
// at least 1, exactly one principal, the box's address, and no critical
// option or extension; for an Ed25519 working key that passes the identity's
// own key checks and is not the identity key; signed by the identity key,
// byte for byte; begun, not ended, and ending at most MaxCertificateLifetime
// from now.
func CheckCertificate(id *Identity, key ssh.PublicKey, now time.Time) (*Certificate, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%w: the signing key is not a certificate", ErrCertificate)
	}
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("%w: it is not a user certificate", ErrCertificate)
	}
	if cert.KeyId != CertificateKeyID {
		return nil, fmt.Errorf("%w: its key id is not %s", ErrCertificate, CertificateKeyID)
	}
	if cert.Serial == 0 {
		return nil, fmt.Errorf("%w: its serial is 0", ErrCertificate)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != id.Address().String() {
		return nil, fmt.Errorf("%w: its one principal must be the box's address", ErrCertificate)
	}
	if len(cert.CriticalOptions) != 0 || len(cert.Extensions) != 0 || len(cert.Reserved) != 0 {
		return nil, fmt.Errorf("%w: it carries an option or an extension", ErrCertificate)
	}
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), id.PublicKey().Marshal()) {
		return nil, fmt.Errorf("%w: it is not signed by the box's identity", ErrCertificate)
	}
	if err := checkWorkingKey(id, cert.Key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}

	// ssh.CertTimeInfinity, the largest value, is past every bound here.
	unix := uint64(max(now.Unix(), 0))
	if unix < cert.ValidAfter {
		return nil, fmt.Errorf("%w: it has not begun", ErrCertificateTime)
	}
	if unix >= cert.ValidBefore {
		return nil, fmt.Errorf("%w: it has ended", ErrCertificateTime)
	}
	if cert.ValidBefore > unix+uint64(MaxCertificateLifetime/time.Second) {
		return nil, fmt.Errorf("%w: it ends more than %d days from now", ErrCertificate, MaxCertificateLifetime/(24*time.Hour))
	}

	// What is left for the library is the signature: CheckCert verifies it
	// against the key inside the certificate, which is the identity's by the
	// comparison above.
	checker := ssh.CertChecker{Clock: func() time.Time { return now }}
	if err := checker.CheckCert(id.Address().String(), cert); err != nil {
		return nil, fmt.Errorf("%w: the identity's signature on it does not verify", ErrCertificate)
	}
	return &Certificate{cert: cert}, nil
}

// checkWorkingKey holds a certified key to the identity's own key checks, and
// refuses the identity key itself: the identity signs certificates only.
func checkWorkingKey(id *Identity, key ssh.PublicKey) error {
	if key == nil || key.Type() != ssh.KeyAlgoED25519 {
		return errors.New("the working key is not an ssh-ed25519 key")
	}
	crypto, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return errors.New("the working key is not an ssh-ed25519 key")
	}
	raw, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return errors.New("the working key is not an ssh-ed25519 key")
	}
	if err := checkEd25519(raw); err != nil {
		return errors.New("the working key is not a canonical Ed25519 point, or is of small order")
	}
	if bytes.Equal(key.Marshal(), id.PublicKey().Marshal()) {
		return errors.New("the working key is the identity key")
	}
	return nil
}

// Serial returns the certificate's serial: higher than every earlier one of
// its identity.
func (c *Certificate) Serial() uint64 { return c.cert.Serial }

// NotAfter returns the first moment the certificate is no longer valid.
func (c *Certificate) NotAfter() time.Time {
	return time.Unix(int64(c.cert.ValidBefore), 0).UTC() //nolint:gosec // CheckCertificate bounded it to 66 days from a clock reading
}

// PublicKey returns the certificate as the key its signatures verify under.
func (c *Certificate) PublicKey() ssh.PublicKey { return c.cert }

// WorkingKey returns the key the certificate is for.
func (c *Certificate) WorkingKey() ssh.PublicKey { return c.cert.Key }

// Marshal returns the certificate's wire bytes. Two certificates with one
// serial are the same certificate only if these are equal.
func (c *Certificate) Marshal() []byte { return c.cert.Marshal() }

// NewCertificate makes the certificate of serial for the working key work,
// signed by identity, the signer for id's key. It is what
// "ssh-keygen -s identity -I irongall-cert-v1 -n <address> -z <serial> -V +66d -O clear work.pub"
// writes: valid from the start of the minute before now, as ssh-keygen dates
// one, to MaxCertificateLifetime after now.
func NewCertificate(id *Identity, identity ssh.Signer, work ssh.PublicKey, serial uint64, now time.Time) (*Certificate, error) {
	if !bytes.Equal(identity.PublicKey().Marshal(), id.PublicKey().Marshal()) {
		return nil, errors.New("the signer is not the box's identity key")
	}
	unix := uint64(max(now.Unix(), 0))
	cert := &ssh.Certificate{
		Key:             work,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           CertificateKeyID,
		ValidPrincipals: []string{id.Address().String()},
		ValidAfter:      (max(unix, 59) - 59) / 60 * 60,
		ValidBefore:     unix + uint64(MaxCertificateLifetime/time.Second),
	}
	if err := cert.SignCert(rand.Reader, identity); err != nil {
		return nil, err
	}
	return CheckCertificate(id, cert, now)
}

// Signer returns the signer whose signatures carry the certificate: work, the
// working key's own signer, under c.
func (c *Certificate) Signer(work ssh.Signer) (ssh.Signer, error) {
	return ssh.NewCertSigner(c.cert, work)
}

// VerifyCertified verifies an armored signature over message, in namespace,
// made by a working key of the identity id. The signature carries the
// certificate: it is taken from there, checked at now (CheckCertificate), and
// the signature is verified under it. It returns the certificate, so a caller
// that keeps the highest serial it has seen can compare.
func VerifyCertified(id *Identity, message, signature []byte, namespace string, now time.Time) (*Certificate, error) {
	blob, err := Dearmor(signature)
	if err != nil {
		return nil, err
	}
	key, err := signingKey(blob)
	if err != nil {
		return nil, err
	}
	cert, err := CheckCertificate(id, key, now)
	if err != nil {
		return nil, err
	}
	if err := sshsig.Verify(cert.PublicKey(), message, blob, namespace); err != nil {
		return nil, err
	}
	return cert, nil
}

// signingKey returns the public key an SSHSIG blob says it was signed with:
// after "SSHSIG" and the version, a length-prefixed key in SSH wire form. The
// key must be in its one encoding, so a certificate has one set of bytes.
func signingKey(blob []byte) (ssh.PublicKey, error) {
	const magic = "SSHSIG"
	notSig := errors.New("not an SSH signature")
	rest, ok := bytes.CutPrefix(blob, []byte(magic))
	if !ok || len(rest) < 8 || binary.BigEndian.Uint32(rest) != 1 {
		return nil, notSig
	}
	n := binary.BigEndian.Uint32(rest[4:])
	rest = rest[8:]
	if uint64(n) > uint64(len(rest)) {
		return nil, notSig
	}
	wire := rest[:n]
	key, err := ssh.ParsePublicKey(wire)
	if err != nil || !bytes.Equal(key.Marshal(), wire) {
		return nil, errors.New("the signature's key does not parse")
	}
	return key, nil
}
