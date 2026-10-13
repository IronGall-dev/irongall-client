package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

// passBox is a certBox with a certificate two hours old at now, and the signer
// that carries it.
func passBox(t *testing.T, now time.Time) (certBox, *Certificate, ssh.Signer) {
	t.Helper()
	b := newCertBox(t)
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 3, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cert.Signer(b.work)
	if err != nil {
		t.Fatal(err)
	}
	return b, cert, signer
}

func TestPassRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 12, 21, 30, 15, 500, time.UTC)
	b, cert, signer := passBox(t, now)
	a := b.id.Address()
	header, notAfter, err := NewPass(signer, a, "irongall.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 12, 21, 40, 15, 0, time.UTC); !notAfter.Equal(want) {
		t.Errorf("runs out at %v, want %v", notAfter, want)
	}
	if !strings.HasPrefix(header, `irongall-pass address="`+a.String()+`", not_after="2026-10-12T21:40:15Z", signature="`) {
		t.Errorf("header %q", header)
	}
	pass, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pass.Verify(b.id, "irongall.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), cert.Marshal()) {
		t.Error("the certificate returned is not the one the pass was signed under")
	}
	// Good to the last second, for a server whose clock is up to
	// MaxPassLifetime less PassLifetime behind the box's.
	if _, err := pass.Verify(b.id, "irongall.dev", notAfter.Add(-time.Second)); err != nil {
		t.Errorf("a second before it runs out: %v", err)
	}
	if _, err := pass.Verify(b.id, "irongall.dev", notAfter.Add(-MaxPassLifetime)); err != nil {
		t.Errorf("exactly %v before it runs out: %v", MaxPassLifetime, err)
	}

	other := newCertBox(t)
	for name, tc := range map[string]struct {
		id     *Identity
		server string
		at     time.Time
		want   error
	}{
		"run out":                {b.id, "irongall.dev", notAfter, ErrPassExpired},
		"long after":             {b.id, "irongall.dev", notAfter.Add(24 * time.Hour), ErrPassExpired},
		"too far ahead":          {b.id, "irongall.dev", notAfter.Add(-MaxPassLifetime - time.Second), ErrPass},
		"another server":         {b.id, "example.org", now, ErrPass},
		"the same host, a port":  {b.id, "irongall.dev:8443", now, ErrPass},
		"another box's identity": {other.id, "irongall.dev", now, ErrPass},
		"no server name":         {b.id, "", now, ErrPass},
		"a name in capitals":     {b.id, "IronGall.dev", now, ErrPass},
		"a name with a path":     {b.id, "irongall.dev/v1", now, ErrPass},
	} {
		if _, err := pass.Verify(tc.id, tc.server, tc.at); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	// A signature made for something else is no pass: the namespace differs.
	stmt := PassStatement(a, "irongall.dev", notAfter)
	for name, ns := range map[string]string{"a message": MessageNamespace(a), "a prekey": PrekeyNamespace(a)} {
		sig, err := Sign(signer, stmt, ns)
		if err != nil {
			t.Fatal(err)
		}
		forged := &Pass{Address: a, NotAfter: notAfter, signature: sig}
		if _, err := forged.Verify(b.id, "irongall.dev", now); !errors.Is(err, ErrPass) {
			t.Errorf("a signature in the namespace of %s: %v", name, err)
		}
	}
	// Nor is one by the working key without its certificate, or by the identity.
	for name, s := range map[string]ssh.Signer{"the bare working key": b.work, "the identity": b.identity} {
		h, _, err := NewPass(s, a, "irongall.dev", now)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePass(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Verify(b.id, "irongall.dev", now); !errors.Is(err, ErrCertificate) {
			t.Errorf("a pass signed by %s: %v", name, err)
		}
	}
	// A later not_after than the one signed.
	later := *pass
	later.NotAfter = notAfter.Add(time.Minute)
	if _, err := later.Verify(b.id, "irongall.dev", now); !errors.Is(err, ErrPass) {
		t.Errorf("a not_after that was not signed: %v", err)
	}
	// A pass that is good, under a certificate that has ended, is refused for the certificate.
	b2, _, signer2 := passBox(t, now.Add(-CertificateLifetime+2*time.Hour+5*time.Minute))
	h2, _, err := NewPass(signer2, b2.id.Address(), "irongall.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParsePass(h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Verify(b2.id, "irongall.dev", now); err != nil {
		t.Errorf("five minutes before its certificate ends: %v", err)
	}
	if _, err := p2.Verify(b2.id, "irongall.dev", now.Add(5*time.Minute)); !errors.Is(err, ErrCertificateTime) {
		t.Errorf("at the moment its certificate ends: %v", err)
	}
}

func TestParsePass(t *testing.T) {
	a := strings.Repeat("0123456789abcdef", 4)
	sig := base64.StdEncoding.EncodeToString([]byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"))
	good := `irongall-pass address="` + a + `", not_after="2026-10-12T21:40:15Z", signature="` + sig + `"`
	p, err := ParsePass(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.Address.String() != a || !p.NotAfter.Equal(time.Date(2026, 10, 12, 21, 40, 15, 0, time.UTC)) {
		t.Errorf("parsed %v %v", p.Address, p.NotAfter)
	}
	for name, bad := range map[string]string{
		"empty":                      "",
		"a bearer token":             "Bearer igt1_" + strings.Repeat("A", 50),
		"the scheme in capitals":     strings.Replace(good, "irongall-pass", "IronGall-Pass", 1),
		"no space after a comma":     strings.Replace(good, `", not_after`, `",not_after`, 1),
		"another order":              `irongall-pass not_after="2026-10-12T21:40:15Z", address="` + a + `", signature="` + sig + `"`,
		"an extra parameter":         good + `, extra="1"`,
		"a trailing newline":         good + "\n",
		"an address in capitals":     strings.Replace(good, a, strings.ToUpper(a), 1),
		"a short address":            strings.Replace(good, a, a[:63], 1),
		"a time with an offset":      strings.Replace(good, "21:40:15Z", "21:40:15+", 1),
		"a time that is no time":     strings.Replace(good, "2026-10-12T21:40:15Z", "2026-13-12T21:40:15Z", 1),
		"no quotes":                  strings.ReplaceAll(good, `"`, ""),
		"an empty signature":         strings.Replace(good, sig, "", 1),
		"base64url in the signature": strings.Replace(good, sig, strings.NewReplacer("+", "-", "/", "_").Replace(sig)+"-", 1),
		"loose base64 padding":       strings.Replace(good, sig, sig+"=", 1),
	} {
		if _, err := ParsePass(bad); !errors.Is(err, ErrPass) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckServerName(t *testing.T) {
	for _, s := range []string{"irongall.dev", "irongall:8080", "127.0.0.1:8013", "localhost", "[::1]:8080", "a-b.example.org:443"} {
		if err := CheckServerName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "IronGall.dev", "https://irongall.dev", "irongall.dev/", "irongall.dev:", "irongall.dev:123456", "irongall dev", "irongall.dev\n", "-irongall.dev", "irongall.dev.:80x", strings.Repeat("a", 256)} {
		if err := CheckServerName(s); !errors.Is(err, ErrPass) {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// TestPassAgainstSSHKeygen holds the pass to stock tools both ways: one made
// with printf and ssh-keygen verifies here, and one made here verifies there.
func TestPassAgainstSSHKeygen(t *testing.T) {
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
	for _, k := range []string{"identity", "work"} {
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
	a := id.Address()
	now := time.Now()
	notAfter := now.UTC().Truncate(time.Second).Add(PassLifetime)
	must(nil, "-q", "-s", "identity", "-I", CertificateKeyID, "-n", a.String(), "-z", "1", "-V", "+66d", "-O", "clear", "work.pub")

	// printf and ssh-keygen make a pass; it verifies here.
	stmt := "irongall-pass-v1\n" + a.String() + "\nirongall.dev\n" + notAfter.Format(TimeLayout) + "\n"
	sig := must([]byte(stmt), "-Y", "sign", "-n", "irongall-pass-v1:"+a.String(), "-f", "work-cert.pub")
	header := `irongall-pass address="` + a.String() + `", not_after="` + notAfter.Format(TimeLayout) + `", signature="` + base64.StdEncoding.EncodeToString(sig) + `"`
	pass, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pass.Verify(id, "irongall.dev", now); err != nil {
		t.Fatalf("a pass made with printf and ssh-keygen: %v", err)
	}

	// A pass made here verifies with ssh-keygen, against the statement printf rebuilds.
	identity, err := ssh.ParsePrivateKey(read("identity"))
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.ParsePrivateKey(read("work"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := NewCertificate(id, identity, work.PublicKey(), 2, now)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cert.Signer(work)
	if err != nil {
		t.Fatal(err)
	}
	ours, oursNotAfter, err := NewPass(signer, a, "irongall.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePass(ours)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ours.sig", p.signature)
	write("signers", []byte(a.String()+" cert-authority "+string(read("identity.pub"))))
	rebuilt := "irongall-pass-v1\n" + a.String() + "\nirongall.dev\n" + oursNotAfter.Format(TimeLayout) + "\n"
	must([]byte(rebuilt), "-Y", "verify", "-f", "signers", "-I", a.String(), "-n", "irongall-pass-v1:"+a.String(), "-s", "ours.sig")
	// The control: for another server's name the same signature fails.
	if _, err := run([]byte(strings.Replace(rebuilt, "irongall.dev", "example.org", 1)), "-Y", "verify", "-f", "signers", "-I", a.String(), "-n", "irongall-pass-v1:"+a.String(), "-s", "ours.sig"); err == nil {
		t.Error("ssh-keygen verified the pass for another server's name")
	}
}
