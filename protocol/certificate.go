package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// A mailbox in working-key mode has its identity certify a working key, and the
// working key signs what the mailbox says (PROTOCOL.md §5). A certificate's
// lifetime is its maker's, up to the maximum its server takes; a verifier holds
// it to its window alone.

const (
	// CertificateKeyID is the key id of every v1 certificate.
	CertificateKeyID = "dromas-cert-v1"
)

// LastDate is the latest moment a certificate may name, at either end:
// 9999-12-31T23:59:59Z (PROTOCOL.md §5). One that names a later one, OpenSSH's
// "forever" among them, is no certificate of this protocol.
var LastDate = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// Every certificate error wraps one of these. ErrCertificate: it is not a
// certificate of this identity, or it breaks a rule of the format, the limit
// on how far ahead it may end among them. ErrCertificateTime: it has not begun
// or it has ended, by the verifier's own clock. Which of the two it is,
// ErrCertificateNotBegun or ErrCertificateEnded, and each is an
// ErrCertificateTime.
var (
	ErrCertificate         = errors.New("bad certificate")
	ErrCertificateTime     = errors.New("the certificate is not valid now")
	ErrCertificateNotBegun = fmt.Errorf("%w: it has not begun", ErrCertificateTime)
	ErrCertificateEnded    = fmt.Errorf("%w: it has ended", ErrCertificateTime)
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
// at least 1, exactly one principal, the mailbox's address, and no critical
// option; for a working key of the type its identity's type gives, that passes
// that type's key checks and is not the identity key; signed by the identity
// key, byte for byte; both dates at or before LastDate; begun, and not ended.
// A verifier sets no ceiling on how long one runs: that is a server's, when it
// takes a statement (PROTOCOL.md §11.7).
// As the format says (draft-ietf-sshm-cert-01 §2.1.1): a critical option a
// verifier does not know is refused, and none is known here; an extension it
// does not know is ignored, and none is known here either; and what the
// reserved field holds is ignored.
func CheckCertificate(id *Identity, key ssh.PublicKey, now time.Time) (*Certificate, error) {
	cert, err := certificateForm(id, key)
	if err != nil {
		return nil, err
	}
	// ssh.CertTimeInfinity, the largest value, is past every bound here.
	unix := uint64(max(now.Unix(), 0))
	if unix < cert.ValidAfter {
		return nil, ErrCertificateNotBegun
	}
	if unix >= cert.ValidBefore {
		return nil, ErrCertificateEnded
	}
	return &Certificate{cert: cert}, nil
}

// CheckCertificateRecord checks key as CheckCertificate does, by every rule
// but its dates: that the identity id certified the working key, with every
// field in its form. It is what a mailbox asks of its own record at its server
// (PROTOCOL.md §12.4): which serial it stands at, and whether its identity
// signed it. A certificate's dates bind what is signed under it, never a
// renewal past it, so a record its server took is never one its mailbox cannot
// renew past for a date: one made for longer than the rule now allows, or
// begun earlier than a client dates one, or ended.
func CheckCertificateRecord(id *Identity, key ssh.PublicKey) (*Certificate, error) {
	cert, err := certificateForm(id, key)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}

// certificateForm checks every rule of a certificate that is not a date
// (CheckCertificate), the identity's signature on it among them.
func certificateForm(id *Identity, key ssh.PublicKey) (*ssh.Certificate, error) {
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
	if cert.Serial == 0 || cert.Serial > MaxSerial {
		return nil, fmt.Errorf("%w: its serial is not from 1 to 2^53 − 1", ErrCertificate)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != id.Address().String() {
		return nil, fmt.Errorf("%w: its one principal must be the mailbox's address", ErrCertificate)
	}
	if len(cert.CriticalOptions) != 0 {
		return nil, fmt.Errorf("%w: it carries a critical option", ErrCertificate)
	}
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), id.PublicKey().Marshal()) {
		return nil, fmt.Errorf("%w: it is not signed by the mailbox's identity", ErrCertificate)
	}
	if err := checkWorkingKey(id, cert.Key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	// Dearmor has held a signature's numbers to OpenSSH's bound already; a
	// certificate that reached here another way is held to it too.
	if cert.Signature == nil || strings.HasPrefix(cert.Signature.Format, "ecdsa-sha2-") && ecdsaNumbersAsRead(cert.Signature.Blob) != nil {
		return nil, fmt.Errorf("%w: the identity's signature on it is not one OpenSSH reads", ErrCertificate)
	}

	// The identity's signature, before any verdict on the dates: "it has not
	// begun" is said only of a certificate the identity signed, never of
	// bytes anyone could write. The library checks the dates with the
	// signature, so it is asked at the moment the certificate begins.
	if last := uint64(LastDate.Unix()); cert.ValidAfter > last || cert.ValidBefore > last {
		return nil, fmt.Errorf("%w: it names a date after 9999-12-31", ErrCertificate)
	}
	checker := ssh.CertChecker{Clock: func() time.Time { return time.Unix(int64(cert.ValidAfter), 0) }} //nolint:gosec // bounded above
	if err := checker.CheckCert(id.Address().String(), cert); err != nil {
		return nil, fmt.Errorf("%w: the identity's signature on it does not verify", ErrCertificate)
	}
	return cert, nil
}

// checkWorkingKey holds a certified key to the type the identity's type
// gives its working keys (WorkingKeyType) and to that type's key checks, and
// refuses the identity key itself: SSHSIG does not sign its signing-key field,
// so the identity's own signature, rank 0, could otherwise be wrapped in a
// certificate of the identity's key at a rank above a revocation (PROTOCOL.md
// §5).
func checkWorkingKey(id *Identity, key ssh.PublicKey) error {
	work := WorkingKeyType(id.Type())
	if key == nil || work == "" || key.Type() != work {
		return fmt.Errorf("the working key is not an %s key", work)
	}
	if _, ok := key.(ssh.CryptoPublicKey); !ok {
		return fmt.Errorf("the working key is not an %s key", work)
	}
	if err := identityTypes[work].check(key); err != nil {
		return fmt.Errorf("the working key fails the %s key checks: %v", work, err)
	}
	if bytes.Equal(key.Marshal(), id.PublicKey().Marshal()) {
		return errors.New("the working key is the identity key")
	}
	return nil
}

// Serial returns the certificate's serial. The identity gives each a higher
// one than the last; holding a certificate to that order is the caller's.
func (c *Certificate) Serial() uint64 { return c.cert.Serial }

// NotAfter returns the first moment the certificate is no longer valid.
func (c *Certificate) NotAfter() time.Time {
	return time.Unix(int64(c.cert.ValidBefore), 0).UTC() //nolint:gosec // certificateForm bounded it to LastDate
}

// NotBefore returns the moment the certificate begins.
func (c *Certificate) NotBefore() time.Time {
	return time.Unix(int64(c.cert.ValidAfter), 0).UTC() //nolint:gosec // certificateForm bounded it to LastDate
}

// Lifetime is how long the certificate runs: its valid-before less its
// valid-after, which a server holds to its maximum (PROTOCOL.md §11.7).
func (c *Certificate) Lifetime() time.Duration { return c.NotAfter().Sub(c.NotBefore()) }

// SignsMessages reports whether a message may still be signed under the certificate at
// now: it has more than TTL left, so it outlasts the message, which may wait
// that long to be read.
func (c *Certificate) SignsMessages(now time.Time) bool { return c.NotAfter().Sub(now) > TTL }

// PublicKey returns the certificate as the key its signatures verify under.
func (c *Certificate) PublicKey() ssh.PublicKey { return c.cert }

// WorkingKey returns the key the certificate is for.
func (c *Certificate) WorkingKey() ssh.PublicKey { return c.cert.Key }

// Marshal returns the certificate's wire bytes. Two certificates with one
// serial are the same certificate only if these are equal.
func (c *Certificate) Marshal() []byte { return c.cert.Marshal() }

// NewCertificate makes the certificate of serial for the working key work,
// signed by identity, the signer for id's key, running for lifetime from
// MaxSkew before now: what
// "ssh-keygen -s identity -I dromas-cert-v1 -n <address> -z <serial> -V -1h:+<lifetime less the hour> -O clear work.pub"
// writes. It starts in the past so that a verifier whose clock is behind this
// one takes it at once; ssh-keygen's own default, a minute or two back, is not
// enough between machines that do not share a clock.
func NewCertificate(id *Identity, identity ssh.Signer, work ssh.PublicKey, serial uint64, now time.Time, lifetime time.Duration) (*Certificate, error) {
	if !bytes.Equal(identity.PublicKey().Marshal(), id.PublicKey().Marshal()) {
		return nil, errors.New("the signer is not the mailbox's identity key")
	}
	unix := uint64(max(now.Unix(), 0))
	after := unix - min(unix, uint64(MaxSkew/time.Second))
	cert := &ssh.Certificate{
		Key:             work,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           CertificateKeyID,
		ValidPrincipals: []string{id.Address().String()},
		ValidAfter:      after,
		ValidBefore:     after + uint64(max(lifetime, 0)/time.Second),
	}
	if err := cert.SignCert(rand.Reader, identity); err != nil {
		return nil, err
	}
	return CheckCertificate(id, cert, now)
}

// SerialAt is the serial a client gives a certificate it makes at now, for a
// mailbox whose highest serial it knows of is above, or 0 if it knows of none:
// the seconds since 1970 at its own clock, or one above that serial when the
// clock gives nothing higher (PROTOCOL.md §5).
//
// An identity is a key, and a key keeps no record of what it signed: a mailbox
// restored from its identity alone knows only what a server shows it, which
// may be an older record, and no server has seen a certificate that was made
// and not yet published. The clock is what such a mailbox still has. Numbered by
// it, the certificate made later has the higher serial whichever machine made
// the earlier one, so the serials below a new certificate are those of every
// certificate made before it, known to its maker or not.
//
// A verifier never reads a serial as a time. It compares two of them, and a
// higher one is later: so a clock that reads behind, or one that once read
// ahead, still gives a serial that rises, by one.
func SerialAt(now time.Time, above uint64) uint64 {
	return max(uint64(max(now.Unix(), 0)), above+1)
}

// Signer returns the signer whose signatures carry the certificate: work, the
// working key's own signer, under c.
func (c *Certificate) Signer(work ssh.Signer) (ssh.Signer, error) {
	return ssh.NewCertSigner(c.cert, work)
}

// CertificateBegan returns when the certificate an armored signature carries
// began: the moment to verify a signature at when the question is whether the
// identity ever certified its key, and not whether it is good now. A refused
// message's Findings ask that (whoMade), and keep the start beside a
// signature that verified (signed); a mailbox asks it of a prekey statement it
// kept, and spends the serial of one whose certificate began less than
// MaxSkew before its clock (signedPrekey, in the client).
func CertificateBegan(signature []byte) (time.Time, error) {
	blob, err := Dearmor(signature)
	if err != nil {
		return time.Time{}, err
	}
	key, err := signingKey(blob)
	if err != nil {
		return time.Time{}, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || cert.ValidAfter > 1<<62 {
		return time.Time{}, fmt.Errorf("%w: the signing key is not a certificate", ErrCertificate)
	}
	return time.Unix(int64(cert.ValidAfter), 0).UTC(), nil
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
