package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"
)

// A box proves itself to a server with a pass: a short statement of who is
// calling, which server, and until when, signed by the box's working key. It
// says nothing of what a call does, so a server is handed no proof of any
// send (PROTOCOL.md §6.1b).

const (
	// PassTag is line 1 of every pass statement.
	PassTag = "irongall-pass-v1"
	// PassScheme is the Authorization scheme a pass travels under.
	PassScheme = "irongall-pass"
	// PassLifetime is how long a client makes a pass good for.
	PassLifetime = 10 * time.Minute
	// MaxPassLifetime is the longest a pass may still have to run when a
	// server takes it. It is longer than PassLifetime so that a client whose
	// clock runs fast is not refused, with no allowance for skew in any check.
	MaxPassLifetime = time.Hour
)

// Every pass error wraps one of these. ErrPass: it is not a pass of this box
// for this server, or it breaks its format. ErrPassExpired: it has run out,
// and the box signs another.
var (
	ErrPass        = errors.New("bad pass")
	ErrPassExpired = errors.New("the pass has expired")
)

// PassNamespace is the namespace of box a's passes.
func PassNamespace(a Address) string { return PassTag + ":" + a.String() }

// serverNameGrammar is a host as an HTTP client names it: a lowercase name or
// IPv4 address, or an IPv6 address in brackets, then a port if there is one.
var serverNameGrammar = regexp.MustCompile(`\A(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?\z`)

// CheckServerName checks that s can stand in a pass as the server's name: the
// host of the server's URL, lowercase, with its port if it has one.
func CheckServerName(s string) error {
	if len(s) > 255 || !serverNameGrammar.MatchString(s) {
		return fmt.Errorf("%w: the server's name is its host, lowercase, with its port if it has one", ErrPass)
	}
	return nil
}

// PassStatement is the text a pass signs: the tag, the box's address, the
// server's name as the box calls it, and the moment the pass runs out, each
// line ending in LF.
func PassStatement(a Address, server string, notAfter time.Time) []byte {
	return []byte(PassTag + "\n" + a.String() + "\n" + server + "\n" + notAfter.UTC().Format(TimeLayout) + "\n")
}

// Pass is what an Authorization header carries: whose pass it is, when it
// runs out, and the working key's signature on the statement.
type Pass struct {
	Address   Address
	NotAfter  time.Time
	signature []byte // armored, as "ssh-keygen -Y sign" writes it
}

// passGrammar is the whole Authorization value, in its one form.
var passGrammar = regexp.MustCompile(`\A` + PassScheme + ` address="([0-9a-f]{64})", not_after="([0-9TZ:-]{20})", signature="([A-Za-z0-9+/]+={0,2})"\z`)

// NewPass makes box a's pass for server, good for PassLifetime from now, and
// returns it as the Authorization header's value. signer is the working key
// under its certificate (Certificate.Signer).
func NewPass(signer ssh.Signer, a Address, server string, now time.Time) (authorization string, notAfter time.Time, err error) {
	if err := CheckServerName(server); err != nil {
		return "", time.Time{}, err
	}
	notAfter = now.UTC().Truncate(time.Second).Add(PassLifetime)
	sig, err := Sign(signer, PassStatement(a, server, notAfter), PassNamespace(a))
	if err != nil {
		return "", time.Time{}, err
	}
	return PassScheme + ` address="` + a.String() + `", not_after="` + notAfter.Format(TimeLayout) +
		`", signature="` + base64.StdEncoding.EncodeToString(sig) + `"`, notAfter, nil
}

// ParsePass parses an Authorization header's value. It must be exactly
//
//	irongall-pass address="<64 hex>", not_after="<time>", signature="<base64>"
//
// with the signature the standard base64 of the signature file. Nothing is
// verified yet.
func ParsePass(authorization string) (*Pass, error) {
	m := passGrammar.FindStringSubmatch(authorization)
	if m == nil {
		return nil, fmt.Errorf(`%w: it is %s address="…", not_after="…", signature="…"`, ErrPass, PassScheme)
	}
	a, err := ParseAddress(m[1])
	if err != nil {
		return nil, fmt.Errorf("%w: its address is not an address", ErrPass)
	}
	notAfter, err := ParseTime(m[2])
	if err != nil {
		return nil, fmt.Errorf("%w: its not_after is not a time", ErrPass)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(m[3])
	if err != nil {
		return nil, fmt.Errorf("%w: its signature is not base64", ErrPass)
	}
	return &Pass{Address: a, NotAfter: notAfter, signature: sig}, nil
}

// Verify checks the pass at now: that it is the pass of the box whose
// identity is id, made for server, not run out, running out at most
// MaxPassLifetime from now, and signed by a working key of that identity
// under a certificate valid at now. It returns the certificate: a server
// takes a pass only under the box's current one, and only for a name that
// is the server's own, which are the caller's to check.
func (p *Pass) Verify(id *Identity, server string, now time.Time) (*Certificate, error) {
	if p.Address != id.Address() {
		return nil, fmt.Errorf("%w: it is another box's", ErrPass)
	}
	if err := CheckServerName(server); err != nil {
		return nil, err
	}
	if !now.Before(p.NotAfter) {
		return nil, ErrPassExpired
	}
	if p.NotAfter.After(now.Add(MaxPassLifetime)) {
		return nil, fmt.Errorf("%w: it runs out more than %d minutes from now", ErrPass, MaxPassLifetime/time.Minute)
	}
	cert, err := VerifyCertified(id, PassStatement(p.Address, server, p.NotAfter), p.signature, PassNamespace(p.Address), now)
	if err != nil {
		if errors.Is(err, ErrCertificate) || errors.Is(err, ErrCertificateTime) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: its signature does not verify", ErrPass)
	}
	return cert, nil
}
