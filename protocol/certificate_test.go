package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// certMailbox is an identity, its signer, and a working key with its signer.
type certMailbox struct {
	id       *Identity
	identity ssh.Signer
	work     ssh.Signer
}

func newCertMailbox(t *testing.T) certMailbox {
	t.Helper()
	signer := func() (ed25519.PublicKey, ssh.Signer) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return pub, s
	}
	pub, identity := signer()
	id, err := NewIdentity(pub)
	if err != nil {
		t.Fatal(err)
	}
	_, work := signer()
	return certMailbox{id: id, identity: identity, work: work}
}

// rawCert is the certificate NewCertificate would make at now, unsigned, for
// a test to change before it signs.
func (b certMailbox) rawCert(now time.Time) *ssh.Certificate {
	unix := uint64(now.Unix())
	return &ssh.Certificate{
		Key:             b.work.PublicKey(),
		Serial:          7,
		CertType:        ssh.UserCert,
		KeyId:           CertificateKeyID,
		ValidPrincipals: []string{b.id.Address().String()},
		ValidAfter:      unix - 60,
		ValidBefore:     unix + uint64(MaxCertificateLifetime/time.Second),
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	b := newCertMailbox(t)
	now := time.Date(2026, 10, 12, 19, 19, 1, 0, time.UTC)
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Serial() != 7 || !cert.NotAfter().Equal(now.Add(CertificateLifetime)) {
		t.Errorf("serial %d, ends %v", cert.Serial(), cert.NotAfter())
	}
	if got := cert.PublicKey().(*ssh.Certificate).ValidAfter; got != uint64(now.Add(-MaxSkew).Unix()) {
		t.Errorf("begins at %d, not MaxSkew before it was made", got)
	}
	if !bytes.Equal(cert.WorkingKey().Marshal(), b.work.PublicKey().Marshal()) {
		t.Error("the working key is not the one certified")
	}
	signer, err := cert.Signer(b.work)
	if err != nil {
		t.Fatal(err)
	}
	msg, ns := []byte("hello dromas\n"), MessageNamespace(b.id.Address())
	sig, err := Sign(signer, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCertified(b.id, msg, sig, ns, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), cert.Marshal()) {
		t.Error("the certificate taken from the signature is not the one that signed")
	}

	// The signature holds for that message, that namespace and that identity only.
	other := newCertMailbox(t)
	if _, err := VerifyCertified(b.id, []byte("hello droma5\n"), sig, ns, now); err == nil {
		t.Error("verified an altered message")
	}
	if _, err := VerifyCertified(b.id, msg, sig, PrekeyNamespace(b.id.Address()), now); err == nil {
		t.Error("verified in another namespace")
	}
	if _, err := VerifyCertified(other.id, msg, sig, ns, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("another identity: %v", err)
	}
	// A signature by the working key alone carries no certificate.
	bare, err := Sign(b.work, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCertified(b.id, msg, bare, ns, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a signature by the bare working key: %v", err)
	}
	// So does one by the identity itself: the identity signs certificates only.
	direct, err := Sign(b.identity, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCertified(b.id, msg, direct, ns, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a signature by the identity key: %v", err)
	}
	for _, junk := range [][]byte{nil, []byte("SSHSIG"), Armor([]byte("SSHSIG\x00\x00\x00\x01\x00\x00\xff\xff")), Armor([]byte("SSHSIG\x00\x00\x00\x02\x00\x00\x00\x00"))} {
		if _, err := VerifyCertified(b.id, msg, junk, ns, now); err == nil {
			t.Errorf("verified %q", junk)
		}
	}
}

func TestCertificateRules(t *testing.T) {
	b := newCertMailbox(t)
	other := newCertMailbox(t)
	now := time.Date(2026, 10, 12, 19, 19, 1, 0, time.UTC)
	unix := uint64(now.Unix())
	lifetime := uint64(MaxCertificateLifetime / time.Second)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ssh.NewPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	smallOrder, err := ssh.NewPublicKey(ed25519.PublicKey(append([]byte{1}, make([]byte, 31)...)))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func(*ssh.Certificate)
		signer ssh.Signer // nil: the identity
		after  func(*ssh.Certificate)
		want   error // nil: it passes
	}{
		{name: "as ssh-keygen writes it"},
		{name: "begins this second", change: func(c *ssh.Certificate) { c.ValidAfter = unix }},
		{name: "ends next second", change: func(c *ssh.Certificate) { c.ValidBefore = unix + 1 }},
		{name: "ends in exactly 64 days and an hour", change: func(c *ssh.Certificate) { c.ValidBefore = unix + lifetime }},

		{name: "a host certificate", change: func(c *ssh.Certificate) { c.CertType = ssh.HostCert }, want: ErrCertificate},
		{name: "another key id", change: func(c *ssh.Certificate) { c.KeyId = "work" }, want: ErrCertificate},
		{name: "no key id", change: func(c *ssh.Certificate) { c.KeyId = "" }, want: ErrCertificate},
		{name: "serial 0", change: func(c *ssh.Certificate) { c.Serial = 0 }, want: ErrCertificate},
		{name: "no principal", change: func(c *ssh.Certificate) { c.ValidPrincipals = nil }, want: ErrCertificate},
		{name: "another mailbox's address", change: func(c *ssh.Certificate) { c.ValidPrincipals = []string{other.id.Address().String()} }, want: ErrCertificate},
		{name: "two principals", change: func(c *ssh.Certificate) { c.ValidPrincipals = append(c.ValidPrincipals, other.id.Address().String()) }, want: ErrCertificate},
		{name: "the address in capitals", change: func(c *ssh.Certificate) { c.ValidPrincipals = []string{strings.ToUpper(b.id.Address().String())} }, want: ErrCertificate},
		{name: "an extension OpenSSH defines", change: func(c *ssh.Certificate) { c.Extensions = map[string]string{"permit-pty": ""} }},
		{name: "an extension nobody defines, with a value", change: func(c *ssh.Certificate) {
			c.Extensions = map[string]string{"nobody-defines@dromas.invalid": "a value", "permit-pty": ""}
		}},
		{name: "reserved bytes", change: func(c *ssh.Certificate) { c.Reserved = []byte("not read") }},
		{name: "a critical option", change: func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "/bin/true"} }, want: ErrCertificate},
		{name: "source-address, which the library leaves to its caller", change: func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"source-address": "127.0.0.1/32"} }, want: ErrCertificate},
		{name: "a critical option nobody defines", change: func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"nobody-defines@dromas.invalid": ""} }, want: ErrCertificate},
		{name: "signed by another key", signer: other.identity, want: ErrCertificate},
		{name: "the identity key as the working key", change: func(c *ssh.Certificate) { c.Key = b.identity.PublicKey() }, want: ErrCertificate},
		{name: "a P-256 working key", change: func(c *ssh.Certificate) { c.Key = p256Key }, want: ErrCertificate},
		{name: "a small-order working key", change: func(c *ssh.Certificate) { c.Key = smallOrder }, want: ErrCertificate},
		{name: "ends in 64 days, an hour and a second", change: func(c *ssh.Certificate) { c.ValidBefore = unix + lifetime + 1 }, want: ErrCertificate},
		{name: "never ends", change: func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity }, want: ErrCertificate},
		// Its form is refused before its dates are read: never "not begun" (#435).
		{name: "not begun and never ends", change: func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = unix+3600, ssh.CertTimeInfinity }, want: ErrCertificate},
		{name: "altered after it was signed", after: func(c *ssh.Certificate) { c.Serial++ }, want: ErrCertificate},

		{name: "begins next second", change: func(c *ssh.Certificate) { c.ValidAfter = unix + 1 }, want: ErrCertificateTime},
		{name: "ended this second", change: func(c *ssh.Certificate) { c.ValidBefore = unix }, want: ErrCertificateTime},
		{name: "ended long ago", change: func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 1, 2 }, want: ErrCertificateTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := b.rawCert(now)
			if tc.change != nil {
				tc.change(cert)
			}
			signer := tc.signer
			if signer == nil {
				signer = b.identity
			}
			if err := cert.SignCert(rand.Reader, signer); err != nil {
				t.Fatal(err)
			}
			if tc.after != nil {
				tc.after(cert)
			}
			// Through the wire form, as a verifier meets it.
			key, err := ssh.ParsePublicKey(cert.Marshal())
			if err != nil {
				t.Fatal(err)
			}
			_, err = CheckCertificate(b.id, key, now)
			if tc.want == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// Not a certificate at all.
	if _, err := CheckCertificate(b.id, b.work.PublicKey(), now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a bare key: %v", err)
	}
	// NewCertificate signs only with the identity it is given.
	if _, err := NewCertificate(b.id, other.identity, b.work.PublicKey(), 1, now); err == nil {
		t.Error("NewCertificate signed with a key that is not the identity")
	}
	if _, err := NewCertificate(b.id, b.identity, b.identity.PublicKey(), 1, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("NewCertificate certified the identity key: %v", err)
	}
}

// TestCertificateAgainstSSHKeygen holds the check to stock ssh-keygen in both
// directions: a certificate and a signature it makes verify here, and ones
// made here verify there.
func TestCertificateAgainstSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	dir := t.TempDir()
	run := func(stdin []byte, args ...string) ([]byte, error) {
		cmd := exec.Command("ssh-keygen", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
		cmd.Stdin = bytes.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return nil, errors.New(strings.TrimSpace(errb.String() + " " + err.Error()))
		}
		return out.Bytes(), nil
	}
	must := func(stdin []byte, args ...string) []byte {
		t.Helper()
		out, err := run(stdin, args...)
		if err != nil {
			t.Fatalf("ssh-keygen %v: %v", args, err)
		}
		return out
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, k := range []string{"identity", "work", "plain"} {
		must(nil, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", k)
	}
	identityKey, _, _, _, err := ssh.ParseAuthorizedKey(read("identity.pub"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewIdentity(identityKey.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	a := id.Address().String()
	msg, ns := []byte("hello dromas\n"), MessageNamespace(id.Address())
	now := time.Now()

	// ssh-keygen's certificate and signature, checked here.
	must(nil, "-q", "-s", "identity", "-I", CertificateKeyID, "-n", a, "-z", "7", "-V", "+64d", "-O", "clear", "work.pub")
	sig := must(msg, "-Y", "sign", "-n", ns, "-f", "work-cert.pub")
	cert, err := VerifyCertified(id, msg, sig, ns, now)
	if err != nil {
		t.Fatalf("ssh-keygen's certificate and signature: %v", err)
	}
	if cert.Serial() != 7 {
		t.Errorf("serial %d", cert.Serial())
	}
	// Without "-O clear" ssh-keygen adds five extensions. None means
	// anything here, and an extension a verifier does not know is ignored
	// (draft-ietf-sshm-cert-01 §2.1.1); a critical option is refused.
	if err := os.Rename(filepath.Join(dir, "work-cert.pub"), filepath.Join(dir, "clear-cert.pub")); err != nil {
		t.Fatal(err)
	}
	must(nil, "-q", "-s", "identity", "-I", CertificateKeyID, "-n", a, "-z", "8", "-V", "+64d", "work.pub")
	sig = must(msg, "-Y", "sign", "-n", ns, "-f", "work-cert.pub")
	if _, err := VerifyCertified(id, msg, sig, ns, now); err != nil {
		t.Errorf("a certificate with ssh-keygen's default extensions: %v", err)
	}
	must(nil, "-q", "-s", "identity", "-I", CertificateKeyID, "-n", a, "-z", "9", "-V", "+64d", "-O", "clear", "-O", "force-command=true", "work.pub")
	sig = must(msg, "-Y", "sign", "-n", ns, "-f", "work-cert.pub")
	if _, err := VerifyCertified(id, msg, sig, ns, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a certificate with a critical option: %v", err)
	}

	// A certificate and a signature made here, checked by ssh-keygen.
	identity, err := ssh.ParsePrivateKey(read("identity"))
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.ParsePrivateKey(read("plain"))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := NewCertificate(id, identity, work.PublicKey(), 9, now)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ours.Signer(work)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = Sign(signer, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ours.sig", sig)
	write("signers", []byte(a+" cert-authority "+string(read("identity.pub"))))
	must(msg, "-Y", "verify", "-f", "signers", "-I", a, "-n", ns, "-s", "ours.sig")
	// The control: listed as an ordinary key, the identity verifies nothing.
	write("plain-signers", []byte(a+" "+string(read("identity.pub"))))
	if _, err := run(msg, "-Y", "verify", "-f", "plain-signers", "-I", a, "-n", ns, "-s", "ours.sig"); err == nil {
		t.Error("ssh-keygen verified with the identity listed as an ordinary key")
	}
}

// A certificate's serial is its maker's clock, in seconds, or one above the
// highest serial the maker knows of when the clock gives nothing higher: it
// rises whatever the clock does, and is never 0.
func TestSerialAt(t *testing.T) {
	for _, c := range []struct {
		name  string
		now   int64
		above uint64
		want  uint64
	}{
		{"a new mailbox: the clock", 1_800_000_000, 0, 1_800_000_000},
		{"the clock has moved on: the clock", 1_800_000_000, 1_700_000_000, 1_800_000_000},
		{"a mailbox numbered by a count before: the clock", 1_800_000_000, 7, 1_800_000_000},
		{"one below the clock: the clock", 1_800_000_000, 1_799_999_999, 1_800_000_000},
		{"the same second: one above", 1_800_000_000, 1_800_000_000, 1_800_000_001},
		{"the clock reads behind the last: one above", 1_800_000_000, 1_900_000_000, 1_900_000_001},
		{"a clock at 1970: never 0", 0, 0, 1},
		{"a clock before 1970: never 0", -5, 0, 1},
		{"a clock before 1970, and a serial known", -5, 41, 42},
	} {
		if got := SerialAt(time.Unix(c.now, 0), c.above); got != c.want {
			t.Errorf("%s: SerialAt(%d, %d) = %d, want %d", c.name, c.now, c.above, got, c.want)
		}
	}
}

// A mailbox's own record is judged by every rule of a certificate but its dates
// (CheckCertificateRecord; PROTOCOL.md §12.4): what CheckCertificate refuses
// at now for a date, it takes; what it refuses for anything else, it refuses.
func TestARecordIsJudgedByEveryRuleButItsDates(t *testing.T) {
	b, other := newCertMailbox(t), newCertMailbox(t)
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	unix := uint64(now.Unix())
	for _, tc := range []struct {
		name   string
		change func(*ssh.Certificate)
		signer ssh.Signer
		record bool // whether a record is taken
	}{
		{name: "made for 65 days", change: func(c *ssh.Certificate) { c.ValidBefore = unix + 65*86400 }, record: true},
		{name: "begun two hours back", change: func(c *ssh.Certificate) { c.ValidAfter = unix - 7200 }, record: true},
		{name: "valid from 1970", change: func(c *ssh.Certificate) { c.ValidAfter = 0 }, record: true},
		{name: "ended long ago", change: func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 1, 2 }, record: true},
		{name: "not begun", change: func(c *ssh.Certificate) { c.ValidAfter = unix + 60 }, record: true},
		{name: "never ends", change: func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity }},
		{name: "ends before it begins", change: func(c *ssh.Certificate) { c.ValidBefore = c.ValidAfter }},
		{name: "another key id", change: func(c *ssh.Certificate) { c.KeyId = "work" }},
		{name: "signed by another key", signer: other.identity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := b.rawCert(now)
			if tc.change != nil {
				tc.change(cert)
			}
			signer := tc.signer
			if signer == nil {
				signer = b.identity
			}
			if err := cert.SignCert(rand.Reader, signer); err != nil {
				t.Fatal(err)
			}
			key, err := ssh.ParsePublicKey(cert.Marshal())
			if err != nil {
				t.Fatal(err)
			}
			// Each case is refused for a date where the record was judged
			// before: at now, or at its own start.
			_, atNow := CheckCertificate(b.id, key, now)
			_, atStart := CheckCertificate(b.id, key, time.Unix(int64(cert.ValidAfter), 0)) //nolint:gosec // a time in this test
			if atNow == nil && atStart == nil {
				t.Fatal("taken at now and at its start: this case is no test of the record")
			}
			_, err = CheckCertificateRecord(b.id, key)
			if tc.record && err != nil {
				t.Fatalf("a record refused: %v", err)
			}
			if !tc.record && !errors.Is(err, ErrCertificate) {
				t.Fatalf("a record taken that breaks a rule that is no date: %v", err)
			}
		})
	}
}
