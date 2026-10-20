package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/sshsig"
	"golang.org/x/crypto/ssh"
)

// A box proves itself to a server with a pass: a short statement of who is
// calling, which server, and until when, signed by the box's working key. It
// says nothing of what a call does, so the pass hands a server no proof of
// any send (PROTOCOL.md §6.1b).

const (
	// PassTag is line 1 of every pass statement.
	PassTag = "irongall-pass-v1"
	// PassScheme is the Authorization scheme a pass travels under.
	PassScheme = "irongall-pass"
	// PassLifetime is how long a client makes a pass good for.
	PassLifetime = 10 * time.Minute
	// MaxPassLifetime is the longest a pass may still have to run when a
	// server takes it. It is longer than PassLifetime so that a client whose
	// clock runs fast is not refused.
	MaxPassLifetime = time.Hour
	// MaxSkew is how far apart two clocks can be with everything here still
	// working: an hour. The pass sets it. A box is taken by a server while its
	// clock is less than PassLifetime slow and no more than MaxPassLifetime
	// less PassLifetime fast, by the server's, and any two such clocks are
	// less than MaxPassLifetime apart. Every check is exact at the verifier's
	// own clock, and whoever makes a time-limited thing leaves this much room:
	// a certificate starts MaxSkew before it is made (NewCertificate), a
	// server takes a prekey that ends up to MaxSkew past PrekeyLifetime
	// (MaxPrekeyLifetime), and a reader takes a sent_at up to MaxSkew ahead
	// (OpenEnvelope). PROTOCOL.md §0.
	MaxSkew = MaxPassLifetime
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
// host of the server's URL, lowercase, with its port only when that is not the
// scheme's default (PROTOCOL.md §6.1b).
func CheckServerName(s string) error {
	if len(s) > 255 || !serverNameGrammar.MatchString(s) {
		return fmt.Errorf("%w: the server's name is its host, lowercase, with its port only when that is not the scheme's default", ErrPass)
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

// MaxPassAuthorization is the longest an Authorization value carrying a pass
// can be in the one form a sender writes: its fixed parts, an address, a time,
// and the standard base64 of a signature of MaxSignature bytes. A pass is
// signed by an Ed25519 working key, under the certificate its identity
// signed, so its size is its identity's key type's; and ParsePass refuses a
// longer value, in any form, before it reads it, so before it knows the box
// (PROTOCOL.md §6.1b). So the bound is the most any identity key type allows,
// and whitespace a sender adds counts toward it.
const MaxPassAuthorization = len(PassScheme+` address="", not_after="", signature=""`) + 64 + len(TimeLayout) + (MaxSignature+2)/3*4

// passSignature is the form of a pass's signature value: standard base64,
// padded, with nothing else in it (Go's decoder would skip a line break).
var passSignature = regexp.MustCompile(`\A[A-Za-z0-9+/]+={0,2}\z`)

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
	return (&Pass{Address: a, NotAfter: notAfter, signature: sig}).Authorization(), notAfter, nil
}

// Authorization is the pass in the one form a client writes it (PROTOCOL.md
// §6.1b), whatever form it was read from, its signature too (armored): a
// server that remembers passes remembers each by this, so one pass written
// two ways is one pass (IronGall-dev/irongall-server#69).
func (p *Pass) Authorization() string {
	return PassScheme + ` address="` + p.Address.String() + `", not_after="` + p.NotAfter.UTC().Format(TimeLayout) +
		`", signature="` + base64.StdEncoding.EncodeToString(p.armored()) + `"`
}

// armored is the pass's signature as Armor writes it, from the blob a
// verifier reads (Dearmor), with nothing in the reserved field, which
// nothing signs (sshsig.Verify): one form for every way of writing one
// signature that OpenSSH reads as the same (PROTOCOL.md §3). A signature
// that does not read is as it was sent; such a pass never verifies.
func (p *Pass) armored() []byte {
	blob, err := Dearmor(p.signature)
	if err != nil {
		return p.signature
	}
	r := wireReader(blob[10:]) // after SSHSIG and its version, which Dearmor wrote as 1
	key, ok1 := r.string()
	namespace, ok2 := r.string()
	_, ok3 := r.string() // reserved
	hash, ok4 := r.string()
	sig, ok5 := r.string()
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return p.signature
	}
	out := append([]byte{}, blob[:10]...)
	for _, s := range [][]byte{key, namespace, nil, hash, sig} {
		out = appendWireString(out, s)
	}
	return Armor(append(out, r...)) // what follows the five fields, for the verifier to refuse
}

// ParsePass parses an Authorization header's value, read as RFC 9110 §11
// lets a recipient read credentials (PROTOCOL.md §6.1b): the scheme in any
// case and one space or more, then the three parameters, address, not_after
// and signature, in any order, each name in any case and given once, with
// optional whitespace around each comma and each "=", empty list elements
// skipped (§5.6.1.2), and each value a token or a quoted-string. A
// quoted-string holding a backslash is refused: no value's alphabet holds a
// character that needs one. Each value is then held to its own form: 64
// lowercase hex, a time as TimeLayout writes it, and padded standard base64
// of the signature file. A sender writes the one form NewPass makes. Nothing
// is verified yet.
func ParsePass(authorization string) (*Pass, error) {
	if len(authorization) > MaxPassAuthorization {
		return nil, fmt.Errorf("%w: it is longer than a pass can be", ErrPass)
	}
	values, err := passParams(strings.Trim(authorization, " \t"))
	if err != nil {
		return nil, fmt.Errorf(`%w: %s; a pass is %s address="…", not_after="…", signature="…"`, ErrPass, err, PassScheme)
	}
	a, err := ParseAddress(values["address"])
	if err != nil {
		return nil, fmt.Errorf("%w: its address is not an address", ErrPass)
	}
	notAfter, err := ParseTime(values["not_after"])
	if err != nil {
		return nil, fmt.Errorf("%w: its not_after is not a time", ErrPass)
	}
	if !passSignature.MatchString(values["signature"]) {
		return nil, fmt.Errorf("%w: its signature is not base64", ErrPass)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(values["signature"])
	if err != nil {
		return nil, fmt.Errorf("%w: its signature is not base64", ErrPass)
	}
	return &Pass{Address: a, NotAfter: notAfter, signature: sig}, nil
}

// passParams reads credentials = auth-scheme 1*SP #auth-param (RFC 9110
// §11.4), where the scheme is PassScheme and the list's elements are
// address, not_after and signature, each once. It returns the three values
// by their names in lowercase.
func passParams(v string) (map[string]string, error) {
	scheme, rest, ok := strings.Cut(v, " ")
	if !strings.EqualFold(scheme, PassScheme) {
		return nil, errors.New("its scheme is not " + PassScheme)
	}
	if !ok {
		return nil, errors.New("it has no parameters")
	}
	rest = strings.TrimLeft(rest, " ")
	values := make(map[string]string, 3)
	// #element is [ element ] *( OWS "," OWS [ element ] ) (§5.6.1.2).
	for {
		if rest != "" && rest[0] != ',' {
			name, value, after, err := authParam(rest)
			if err != nil {
				return nil, err
			}
			name = strings.ToLower(name)
			if name != "address" && name != "not_after" && name != "signature" {
				return nil, errors.New("it has a parameter a pass has not")
			}
			if _, twice := values[name]; twice {
				return nil, errors.New("it names a parameter twice")
			}
			values[name] = value
			rest = after
		}
		rest = trimOWS(rest)
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return nil, errors.New("its parameters are not a list")
		}
		rest = trimOWS(rest[1:])
	}
	if len(values) != 3 {
		return nil, errors.New("it lacks a parameter")
	}
	return values, nil
}

// authParam reads one auth-param = token BWS "=" BWS ( token / quoted-string )
// from the start of s, and returns its name, its value and what follows.
func authParam(s string) (name, value, rest string, err error) {
	n := tokenLength(s)
	if n == 0 {
		return "", "", "", errors.New("a parameter's name is not a token")
	}
	name, rest = s[:n], trimOWS(s[n:])
	if rest == "" || rest[0] != '=' {
		return "", "", "", errors.New("a parameter has no value")
	}
	rest = trimOWS(rest[1:])
	if rest == "" || rest[0] != '"' {
		n = tokenLength(rest)
		if n == 0 {
			return "", "", "", errors.New("a value is neither a token nor a quoted-string")
		}
		return name, rest[:n], rest[n:], nil
	}
	for i := 1; i < len(rest); i++ {
		switch c := rest[i]; {
		case c == '"':
			return name, rest[1:i], rest[i+1:], nil
		case c == '\\':
			return "", "", "", errors.New("a quoted value holds a backslash")
		case c != '\t' && (c < ' ' || c == 0x7f):
			return "", "", "", errors.New("a quoted value holds a control character")
		}
	}
	return "", "", "", errors.New("a quoted value is not closed")
}

// tokenLength is how many bytes at the start of s are tchar (RFC 9110 §5.6.2).
func tokenLength(s string) int {
	for i := 0; i < len(s); i++ {
		if !tchar(s[i]) {
			return i
		}
	}
	return len(s)
}

// tchar reports whether c may be in a token: a letter, a digit, or one of
// the visible characters RFC 9110 §5.6.2 does not count as delimiters.
func tchar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// trimOWS drops optional whitespace, spaces and tabs, from the start of s.
func trimOWS(s string) string { return strings.TrimLeft(s, " \t") }

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

// VerifyUnder checks the pass against a certificate known by the SHA-256 of
// its bytes, sum: the one a caller has on record for the box. The pass must
// be for server, not run out, signed under exactly that certificate, which
// must name the box the pass names and must not have ended, and the working
// key's signature must verify. It returns the certificate.
//
// It makes one signature check, and none for a pass under another
// certificate (ErrCertificate), so a pass that is not the box's is cheap to
// refuse. It does NOT check the identity's signature on the certificate, nor
// the certificate's other rules: that is CheckCertificate, which a caller
// makes on what this returns, as Verify does in one step.
func (p *Pass) VerifyUnder(sum [sha256.Size]byte, server string, now time.Time) (ssh.PublicKey, error) {
	if err := CheckServerName(server); err != nil {
		return nil, err
	}
	if !now.Before(p.NotAfter) {
		return nil, ErrPassExpired
	}
	if p.NotAfter.After(now.Add(MaxPassLifetime)) {
		return nil, fmt.Errorf("%w: it runs out more than %d minutes from now", ErrPass, MaxPassLifetime/time.Minute)
	}
	blob, err := Dearmor(p.signature)
	if err != nil {
		return nil, fmt.Errorf("%w: its signature is not one", ErrPass)
	}
	key, err := signingKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: its signature is not one", ErrPass)
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || sha256.Sum256(cert.Marshal()) != sum {
		return nil, fmt.Errorf("%w: the pass is not signed under the certificate on record", ErrCertificate)
	}
	// The certificate on record names the identity that signed it, and so
	// the bound its box's signatures are held to.
	if cert.SignatureKey == nil || withinBound(p.signature, cert.SignatureKey.Type()) != nil {
		return nil, fmt.Errorf("%w: its signature is longer than its identity's key type allows", ErrPass)
	}
	// The pass names a box, and the certificate names the one it is for.
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != p.Address.String() {
		return nil, fmt.Errorf("%w: it is another box's", ErrPass)
	}
	// Of a certificate's rules, the one that stops holding by itself: it ends.
	switch unix := uint64(max(now.Unix(), 0)); {
	case unix < cert.ValidAfter:
		return nil, ErrCertificateNotBegun
	case unix >= cert.ValidBefore:
		return nil, ErrCertificateEnded
	}
	if err := sshsig.Verify(cert, PassStatement(p.Address, server, p.NotAfter), blob, PassNamespace(p.Address)); err != nil {
		return nil, fmt.Errorf("%w: its signature does not verify", ErrPass)
	}
	return cert, nil
}
