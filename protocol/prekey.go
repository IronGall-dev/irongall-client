package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

const (
	// PrekeyTag is line 1 of every v1 prekey statement.
	PrekeyTag = "dromas-prekey-v1"
	// PrekeyLifetime is how long a client makes a prekey statement valid for:
	// 31 days, the longest month, plus a day a renewal may wait and a day of
	// slip, so a mailbox checked at least monthly never lapses.
	PrekeyLifetime = 33 * 24 * time.Hour
	// MaxPrekeyLifetime is the longest a prekey statement may still have to
	// run when a server takes it: MaxSkew more than a client asks for, so
	// that a client whose clock is ahead of the server's is not refused. It
	// is the pass's rule (PassLifetime, MaxPassLifetime).
	MaxPrekeyLifetime = PrekeyLifetime + MaxSkew
	// MaxSerial is the largest serial, of a prekey or a certificate, and the
	// largest a revocation of certificates runs through: MaxInteger, 2^53 − 1,
	// since an answer names a serial as a JSON number (stale_prekey's, a
	// conflict's), and RFC 7493 promises no reader holds a larger integer
	// exactly.
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

// Prekey is a prekey statement: the mailbox's current age encryption key, signed
// by a working key its identity certified.
type Prekey struct {
	Address  Address   // the mailbox the key belongs to
	Serial   uint64    // strictly increasing under one certificate; a client gives it its certificate's serial
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

// ErrPrekeyType is a prekey statement whose key is a well-formed age
// recipient of a type this client cannot encrypt to: a Bech32 string whose
// human-readable part begins "age", and is neither X25519's "age" nor the
// hybrid's "age1pq". Nothing is wrong with such a statement: a type defined
// later takes no new tag, so a sender refuses it as unsupported_prekey_type,
// never as a statement that does not verify (PROTOCOL.md §14, §6).
var ErrPrekeyType = errors.New("the prekey is an age recipient of a type this client cannot encrypt to")

// ParsePrekey parses a prekey statement. It must be exactly five LF-terminated
// lines with nothing after them, its serial a decimal integer with no leading
// zero and at most MaxSerial, its key an age recipient in canonical form that
// can be encrypted to (so no small-order X25519 point, in either key type), and
// its not_after a UTC timestamp to the second. A key that is a well-formed
// age recipient of another type is ErrPrekeyType.
func ParsePrekey(statement []byte) (*Prekey, error) {
	p, err := parsePrekey(statement)
	if err != nil {
		return nil, err
	}
	if err := checkRecipient(p); err != nil {
		return nil, err
	}
	return p, nil
}

// parsePrekey is ParsePrekey with the key left unchecked: its type is the
// last thing a verifier asks, once the statement is otherwise good.
func parsePrekey(statement []byte) (*Prekey, error) {
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
	return &Prekey{Address: addr, Serial: serial, Key: lines[3], NotAfter: notAfter}, nil
}

// checkRecipient checks the key is an age recipient that age can encrypt to.
// Its type is its Bech32 human-readable part: "age" or "age1pq", and any
// other that begins "age" is ErrPrekeyType. age's parser is already exact
// (lowercase only, zero padding bits; the bad-recipient-uppercase-* vectors
// hold it to that). It accepts a small-order X25519 point, including the
// X25519 half of a hybrid key, but refuses to encrypt to one, so a trial wrap
// is the check.
func checkRecipient(p *Prekey) error {
	switch hrp, ok := bech32HRP(p.Key); {
	case ok && (hrp == "age" || hrp == "age1pq"):
	case ok && strings.HasPrefix(hrp, "age"):
		return ErrPrekeyType
	default:
		return errors.New("the prekey is not an age recipient")
	}
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

// bech32Charset is Bech32's alphabet, each character's value its index.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Polymod is BIP 173's checksum over values: the human-readable part
// expanded, then the data and its checksum. A Bech32 string's is 1.
func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3} {
			if top>>i&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

// bech32HRP returns the human-readable part of s, if s is a Bech32 string
// (BIP 173) as age writes a recipient: in lowercase, its checksum good, and
// its data whole bytes, with fewer than five bits left over and those zero.
// age takes a string of any length, where BIP 173 stops at 90, and so does
// this.
func bech32HRP(s string) (string, bool) {
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", false
	}
	hrp, data := s[:pos], s[pos+1:]
	values := make([]byte, 0, 2*len(hrp)+1+len(data))
	for i := 0; i < len(hrp); i++ {
		if c := hrp[i]; c < 33 || c > 126 || c >= 'A' && c <= 'Z' {
			return "", false
		}
		values = append(values, hrp[i]>>5)
	}
	values = append(values, 0)
	for i := 0; i < len(hrp); i++ {
		values = append(values, hrp[i]&31)
	}
	for i := 0; i < len(data); i++ {
		v := strings.IndexByte(bech32Charset, data[i])
		if v < 0 {
			return "", false
		}
		values = append(values, byte(v)) //nolint:gosec // an index into the 32-character alphabet
	}
	if bech32Polymod(values) != 1 {
		return "", false
	}
	n := len(data) - 6
	if left := n * 5 % 8; left >= 5 || n > 0 && values[len(values)-7]&(1<<left-1) != 0 {
		return "", false
	}
	return hrp, true
}

// VerifyPrekey verifies a prekey statement of the mailbox whose identity is id,
// at now, and parses it. The signature must be by a working key that identity
// certified, under a certificate valid at now, in id's prekey namespace; the
// statement must name id's own address; and it must not outlive the
// certificate it is signed under. It returns the certificate too: whoever
// keeps the highest serial it has seen for the mailbox compares. The key's type
// is checked last, so ErrPrekeyType is a statement good in every other way,
// and comes with the statement and its certificate, for a caller to hold to
// its own rules first (#167).
func VerifyPrekey(id *Identity, statement, signature []byte, now time.Time) (*Prekey, *Certificate, error) {
	return verifyPrekey(id, statement, signature, func(key ssh.PublicKey) (*Certificate, error) { return CheckCertificate(id, key, now) })
}

// verifyPrekey is VerifyPrekey with the certificate held to check.
func verifyPrekey(id *Identity, statement, signature []byte, check func(ssh.PublicKey) (*Certificate, error)) (*Prekey, *Certificate, error) {
	cert, err := verifyCertified(id, statement, signature, PrekeyNamespace(id.Address()), check)
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
	p, err := parsePrekey(statement)
	if err != nil {
		return nil, nil, err
	}
	if p.Address != id.Address() {
		return nil, nil, errors.New("the prekey statement names another mailbox")
	}
	if p.NotAfter.After(cert.NotAfter()) {
		return nil, nil, errors.New("the prekey statement outlives the certificate it is signed under")
	}
	if err := checkRecipient(p); errors.Is(err, ErrPrekeyType) {
		return p, cert, err
	} else if err != nil {
		return nil, nil, err
	}
	return p, cert, nil
}

// VerifyPrekeyRecord verifies a prekey statement as VerifyPrekey does, by
// every rule but its certificate's dates (CheckCertificateRecord). It answers
// whether the identity certified the key that signed the statement, and at
// which serials it stands, which is what a mailbox asks of its own record
// (PROTOCOL.md §12.4): a mailbox that was away for longer than a certificate
// lasts, or whose record its server took under a rule since changed, still
// has to read its serial to publish the next one. Nobody judging another
// mailbox's prekey uses it.
func VerifyPrekeyRecord(id *Identity, statement, signature []byte) (*Prekey, *Certificate, error) {
	return verifyPrekey(id, statement, signature, func(key ssh.PublicKey) (*Certificate, error) { return CheckCertificateRecord(id, key) })
}

// Order is where a prekey statement would stand in its mailbox's order
// (PROTOCOL.md §5): its own serial, and the serial and the SHA-256 of the
// certificate its signature carries.
type Order struct {
	Serial     uint64
	CertSerial uint64
	Cert       [32]byte
}

// PrekeyOrder reads a statement's Order and verifies nothing: not the
// signature, not the certificate, not the key. A server reads it to refuse,
// before any signature check, a statement it could not take even if it
// verified, and trusts it for nothing more: a statement that passes is
// verified in full after.
func PrekeyOrder(statement, signature []byte) (Order, error) {
	notOrdered := errors.New("the prekey statement or its signature does not parse")
	lines := strings.SplitN(string(statement), "\n", 4)
	if len(lines) < 4 || lines[0] != PrekeyTag {
		return Order{}, notOrdered
	}
	serial, ok := parseSerial([]byte(lines[2]))
	if !ok {
		return Order{}, notOrdered
	}
	blob, err := Dearmor(signature)
	if err != nil {
		return Order{}, notOrdered
	}
	key, err := signingKey(blob)
	if err != nil {
		return Order{}, notOrdered
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return Order{}, notOrdered
	}
	return Order{Serial: serial, CertSerial: cert.Serial, Cert: sha256.Sum256(cert.Marshal())}, nil
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
