package protocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	// PrekeyTag is line 1 of every v1 prekey statement.
	PrekeyTag = "irongall-prekey-v1"
	// PrekeyLifetime is how long a client makes a prekey statement valid for:
	// 31 days, the longest month, plus a day a renewal may wait and a day of
	// slip, so a box checked at least monthly never lapses.
	PrekeyLifetime = 33 * 24 * time.Hour
	// MaxPrekeyLifetime is the longest a prekey statement may still have to
	// run when a server takes it: MaxSkew more than a client asks for, so
	// that a client whose clock is ahead of the server's is not refused. It
	// is the pass's rule (PassLifetime, MaxPassLifetime).
	MaxPrekeyLifetime = PrekeyLifetime + MaxSkew
	// MaxSerial is the largest serial, of a prekey or a certificate, and the
	// largest a revocation of certificates runs through: MaxInteger, 2^53 − 1,
	// since a send names a prekey by its two serials as JSON numbers, and
	// RFC 7493 promises no reader holds a larger integer exactly.
	MaxSerial = MaxInteger
	// TimeLayout is the one timestamp format in signed statements and the
	// envelope: RFC 3339, UTC, to the second.
	TimeLayout = "2006-01-02T15:04:05Z"
)

// KeyType is a prekey's type, named as its age stanza is.
type KeyType string

const (
	// PostQuantum is age's hybrid ML-KEM-768 + X25519 recipient, "age1pq1…",
	// the default.
	PostQuantum KeyType = "mlkem768x25519"
	// Classic is age's X25519 recipient, "age1…".
	Classic KeyType = "X25519"
)

// serialGrammar is a serial's text: a decimal integer with no leading zero,
// of at most 16 digits. Its value is held to MaxSerial after.
var serialGrammar = regexp.MustCompile(`\A[1-9][0-9]{0,15}\z`)

// Prekey is a prekey statement: the box's current age encryption key, signed
// by a working key its identity certified.
type Prekey struct {
	Address  Address   // the box the key belongs to
	Serial   uint64    // strictly increasing per box; the first is 1
	Key      string    // the age recipient: "age1pq1…" or "age1…"
	NotAfter time.Time // the last moment the key may be encrypted to
}

// Statement returns the statement's exact text: five lines, each ending in LF.
func (p *Prekey) Statement() []byte {
	return []byte(PrekeyTag + "\n" +
		p.Address.String() + "\n" +
		strconv.FormatUint(p.Serial, 10) + "\n" +
		p.Key + "\n" +
		p.NotAfter.UTC().Format(TimeLayout) + "\n")
}

// Type returns the key's type, from its prefix.
func (p *Prekey) Type() KeyType {
	if strings.HasPrefix(p.Key, "age1pq1") {
		return PostQuantum
	}
	return Classic
}

// Recipient returns the key as an age recipient to encrypt to.
func (p *Prekey) Recipient() (age.Recipient, error) {
	if p.Type() == PostQuantum {
		return age.ParseHybridRecipient(p.Key)
	}
	return age.ParseX25519Recipient(p.Key)
}

// Expired reports whether the key may no longer be encrypted to at now.
// Senders refuse to encrypt to an expired prekey, with no grace.
func (p *Prekey) Expired(now time.Time) bool { return !now.Before(p.NotAfter) }

// CheckLifetime checks the statement could be published at now: it has not
// expired, and expires at most MaxPrekeyLifetime after now.
func (p *Prekey) CheckLifetime(now time.Time) error {
	if p.Expired(now) {
		return errors.New("the prekey has already expired")
	}
	if p.NotAfter.After(now.Add(MaxPrekeyLifetime)) {
		return fmt.Errorf("a prekey may end at most %d days and %d minutes from now", PrekeyLifetime/(24*time.Hour), MaxSkew/time.Minute)
	}
	return nil
}

// ParsePrekey parses a prekey statement. It must be exactly five LF-terminated
// lines with nothing after them, its serial a decimal integer with no leading
// zero and at most MaxSerial, its key an age recipient in canonical form that
// can be encrypted to (so no small-order X25519 point, in either key type), and
// its not_after a UTC timestamp to the second.
func ParsePrekey(statement []byte) (*Prekey, error) {
	if !bytes.HasSuffix(statement, []byte("\n")) {
		return nil, errors.New("a prekey statement is five lines, each ending in LF")
	}
	lines := strings.Split(string(statement[:len(statement)-1]), "\n")
	if len(lines) != 5 {
		return nil, errors.New("a prekey statement is five lines, each ending in LF")
	}
	if lines[0] != PrekeyTag {
		return nil, fmt.Errorf("a prekey statement starts with %q", PrekeyTag)
	}
	addr, err := ParseAddress(lines[1])
	if err != nil {
		return nil, fmt.Errorf("line 2 of a prekey statement: %v", err)
	}
	serial, ok := parseSerial([]byte(lines[2]))
	if !ok {
		return nil, errors.New("a prekey serial is a decimal integer with no leading zero, from 1 to 2^53 − 1")
	}
	notAfter, err := ParseTime(lines[4])
	if err != nil {
		return nil, fmt.Errorf("not_after: %v", err)
	}
	p := &Prekey{Address: addr, Serial: serial, Key: lines[3], NotAfter: notAfter}
	if err := checkRecipient(p); err != nil {
		return nil, err
	}
	return p, nil
}

// checkRecipient checks the key is an age recipient that age can encrypt to.
// age's parser is already exact (lowercase only, zero padding bits; the
// bad-recipient-uppercase-* vectors hold it to that). It accepts a small-order
// X25519 point, including the X25519 half of a hybrid key, but refuses to
// encrypt to one, so a trial wrap is the check.
func checkRecipient(p *Prekey) error {
	r, err := p.Recipient()
	if err != nil {
		return errors.New("the prekey is not an age recipient")
	}
	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	if _, err := r.Wrap(fileKey); err != nil {
		return errors.New("the prekey cannot be encrypted to")
	}
	return nil
}

// VerifyPrekey verifies a prekey statement of the box whose identity is id,
// at now, and parses it. The signature must be by a working key that identity
// certified, under a certificate valid at now, in id's prekey namespace; the
// statement must name id's own address; and it must not outlive the
// certificate it is signed under. It returns the certificate too: whoever
// keeps the highest serial it has seen for the box compares.
func VerifyPrekey(id *Identity, statement, signature []byte, now time.Time) (*Prekey, *Certificate, error) {
	cert, err := VerifyCertified(id, statement, signature, PrekeyNamespace(id.Address()), now)
	switch {
	case errors.Is(err, ErrCertificateTime):
		// Its own words, and still the error it was to errors.Is: a caller
		// says whose clock judged it.
		if errors.Is(err, ErrCertificateNotBegun) {
			return nil, nil, &worded{"the certificate the prekey is signed under has not begun", ErrCertificateNotBegun}
		}
		return nil, nil, &worded{"the certificate the prekey is signed under has ended", ErrCertificateEnded}
	case err != nil:
		return nil, nil, errors.New("the prekey is not signed by a working key its identity certified")
	}
	p, err := ParsePrekey(statement)
	if err != nil {
		return nil, nil, err
	}
	if p.Address != id.Address() {
		return nil, nil, errors.New("the prekey statement names another box")
	}
	if p.NotAfter.After(cert.NotAfter()) {
		return nil, nil, errors.New("the prekey statement outlives the certificate it is signed under")
	}
	return p, cert, nil
}

// VerifyPrekeyRecord verifies a prekey statement as VerifyPrekey does, at the
// moment its certificate began and not at now. It answers whether the
// identity ever certified the key that signed the statement, which is what a
// box asks of its own record: a box that was away for longer than a
// certificate lasts still has to read its serial to publish the next one.
// Nobody judging another box's prekey uses it.
func VerifyPrekeyRecord(id *Identity, statement, signature []byte) (*Prekey, *Certificate, error) {
	began, err := CertificateBegan(signature)
	if err != nil {
		return nil, nil, errors.New("the prekey is not signed by a working key its identity certified")
	}
	return VerifyPrekey(id, statement, signature, began)
}

// worded is an error that reads as its own words and is still is to
// errors.Is.
type worded struct {
	words string
	is    error
}

func (e *worded) Error() string { return e.words }
func (e *worded) Unwrap() error { return e.is }

// ParseTime parses a timestamp in TimeLayout, exactly: RFC 3339, UTC, to the
// second, as in 2026-10-10T12:00:00Z.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, errors.New("not a UTC timestamp to the second, YYYY-MM-DDTHH:MM:SSZ")
	}
	return t, nil
}
