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
	PrekeyTag = "crossbot-prekey-v1"
	// MaxPrekeyLifetime is the longest a prekey statement may be valid,
	// counted from when it is published: a monthly timer renews with a day or
	// more to spare.
	MaxPrekeyLifetime = 32 * 24 * time.Hour
	// MaxSerial is the largest prekey serial: 18 decimal digits.
	MaxSerial = 999_999_999_999_999_999
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

var serialGrammar = regexp.MustCompile(`\A[1-9][0-9]{0,17}\z`)

// Prekey is a prekey statement: the box's current age encryption key, signed
// by its identity.
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
		return fmt.Errorf("a prekey may be valid for at most %d days", MaxPrekeyLifetime/(24*time.Hour))
	}
	return nil
}

// ParsePrekey parses a prekey statement. It must be exactly five LF-terminated
// lines with nothing after them, its serial a decimal integer with no leading
// zero and at most 18 digits, its key an age recipient in canonical form that
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
	if !serialGrammar.MatchString(lines[2]) {
		return nil, errors.New("a prekey serial is a decimal integer with no leading zero, at most 18 digits")
	}
	serial, err := strconv.ParseUint(lines[2], 10, 64)
	if err != nil {
		return nil, err
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
		return fmt.Errorf("the prekey is not an age recipient: %v", err)
	}
	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	if _, err := r.Wrap(fileKey); err != nil {
		return fmt.Errorf("the prekey cannot be encrypted to: %v", err)
	}
	return nil
}

// VerifyPrekey verifies a prekey statement signed by id, and parses it. The
// signature must be id's, in id's prekey namespace, and the statement must
// name id's own address.
func VerifyPrekey(id *Identity, statement, signature []byte) (*Prekey, error) {
	if err := Verify(id, statement, signature, PrekeyNamespace(id.Address())); err != nil {
		return nil, fmt.Errorf("the prekey is not signed by its identity: %v", err)
	}
	p, err := ParsePrekey(statement)
	if err != nil {
		return nil, err
	}
	if p.Address != id.Address() {
		return nil, errors.New("the prekey statement names another box")
	}
	return p, nil
}

// ParseTime parses a timestamp in TimeLayout, exactly: RFC 3339, UTC, to the
// second, as in 2026-10-10T12:00:00Z.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, errors.New("not a UTC timestamp to the second, YYYY-MM-DDTHH:MM:SSZ")
	}
	return t, nil
}
