package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

// passMailbox is a certMailbox with a certificate two hours old at now, and the signer
// that carries it.
func passMailbox(t *testing.T, now time.Time) (certMailbox, *Certificate, ssh.Signer) {
	t.Helper()
	b := newCertMailbox(t)
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
	b, cert, signer := passMailbox(t, now)
	a := b.id.Address()
	header, notAfter, err := NewPass(signer, a, "dromas.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 12, 21, 40, 15, 0, time.UTC); !notAfter.Equal(want) {
		t.Errorf("runs out at %v, want %v", notAfter, want)
	}
	if !strings.HasPrefix(header, `dromas-pass address="`+a.String()+`", not_after="2026-10-12T21:40:15Z", signature="`) {
		t.Errorf("header %q", header)
	}
	pass, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pass.Verify(b.id, "dromas.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), cert.Marshal()) {
		t.Error("the certificate returned is not the one the pass was signed under")
	}
	// Good to the last second, for a server whose clock is up to
	// MaxPassLifetime less PassLifetime behind the mailbox's.
	if _, err := pass.Verify(b.id, "dromas.dev", notAfter.Add(-time.Second)); err != nil {
		t.Errorf("a second before it runs out: %v", err)
	}
	if _, err := pass.Verify(b.id, "dromas.dev", notAfter.Add(-MaxPassLifetime)); err != nil {
		t.Errorf("exactly %v before it runs out: %v", MaxPassLifetime, err)
	}

	other := newCertMailbox(t)
	for name, tc := range map[string]struct {
		id     *Identity
		server string
		at     time.Time
		want   error
	}{
		"run out":                    {b.id, "dromas.dev", notAfter, ErrPassExpired},
		"long after":                 {b.id, "dromas.dev", notAfter.Add(24 * time.Hour), ErrPassExpired},
		"too far ahead":              {b.id, "dromas.dev", notAfter.Add(-MaxPassLifetime - time.Second), ErrPass},
		"another server":             {b.id, "example.org", now, ErrPass},
		"the same host, a port":      {b.id, "dromas.dev:8443", now, ErrPass},
		"another mailbox's identity": {other.id, "dromas.dev", now, ErrPass},
		"no server name":             {b.id, "", now, ErrPass},
		"a name in capitals":         {b.id, "Dromas.dev", now, ErrPass},
		"a name with a path":         {b.id, "dromas.dev/v1", now, ErrPass},
	} {
		if _, err := pass.Verify(tc.id, tc.server, tc.at); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}

	// A signature made for something else is no pass: the namespace differs.
	stmt := PassStatement(a, "dromas.dev", notAfter)
	for name, ns := range map[string]string{"a message": MessageNamespace(a), "a prekey": PrekeyNamespace(a)} {
		sig, err := Sign(signer, stmt, ns)
		if err != nil {
			t.Fatal(err)
		}
		forged := &Pass{Address: a, NotAfter: notAfter, signature: sig}
		if _, err := forged.Verify(b.id, "dromas.dev", now); !errors.Is(err, ErrPass) {
			t.Errorf("a signature in the namespace of %s: %v", name, err)
		}
	}
	// Nor is one by the working key without its certificate, or by the identity.
	for name, s := range map[string]ssh.Signer{"the bare working key": b.work, "the identity": b.identity} {
		h, _, err := NewPass(s, a, "dromas.dev", now)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePass(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Verify(b.id, "dromas.dev", now); !errors.Is(err, ErrCertificate) {
			t.Errorf("a pass signed by %s: %v", name, err)
		}
	}
	// A later not_after than the one signed.
	later := *pass
	later.NotAfter = notAfter.Add(time.Minute)
	if _, err := later.Verify(b.id, "dromas.dev", now); !errors.Is(err, ErrPass) {
		t.Errorf("a not_after that was not signed: %v", err)
	}
	// A pass that is good, under a certificate that has ended, is refused for the certificate.
	b2, _, signer2 := passMailbox(t, now.Add(-CertificateLifetime+2*time.Hour+5*time.Minute))
	h2, _, err := NewPass(signer2, b2.id.Address(), "dromas.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParsePass(h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Verify(b2.id, "dromas.dev", now); err != nil {
		t.Errorf("five minutes before its certificate ends: %v", err)
	}
	if _, err := p2.Verify(b2.id, "dromas.dev", now.Add(5*time.Minute)); !errors.Is(err, ErrCertificateTime) {
		t.Errorf("at the moment its certificate ends: %v", err)
	}
}

// VerifyUnder is Verify for a caller that checked the mailbox's certificate
// before and kept its hash: the pass must be under exactly that certificate,
// for this server, not run out, and the working key's signature must verify.
// It is the same for an identity of either type, since the identity's own
// signature is not what it checks.
func TestPassVerifyUnder(t *testing.T) {
	now := time.Date(2026, 10, 12, 21, 30, 15, 0, time.UTC)
	ed, edCert, edSigner := passMailbox(t, now)
	p256 := p256Mailbox(t)
	pCert, err := NewCertificate(p256.id, p256.identity, p256.work.PublicKey(), 3, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pSigner, err := pCert.Signer(p256.work)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]struct {
		mailbox certMailbox
		cert    *Certificate
		signer  ssh.Signer
	}{"ssh-ed25519": {ed, edCert, edSigner}, "ecdsa-sha2-nistp256": {p256, pCert, pSigner}} {
		a := b.mailbox.id.Address()
		header, notAfter, err := NewPass(b.signer, a, "dromas.dev", now)
		if err != nil {
			t.Fatal(err)
		}
		pass, err := ParsePass(header)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b.cert.Marshal())
		under, err := pass.VerifyUnder(sum, "dromas.dev", now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// What it returns is the certificate, which CheckCertificate then
		// holds to the identity: together they are what Verify checks.
		if checked, err := CheckCertificate(b.mailbox.id, under, now); err != nil || sha256.Sum256(checked.Marshal()) != sum {
			t.Fatalf("%s: the certificate VerifyUnder returned: %v", name, err)
		}
		// What Verify takes, VerifyUnder takes, and the certificate is the same one.
		if got, err := pass.Verify(b.mailbox.id, "dromas.dev", now); err != nil || sha256.Sum256(got.Marshal()) != sum {
			t.Fatalf("%s: Verify: %v", name, err)
		}
		// A later certificate of the same identity for the same key: the pass is not under it.
		later, err := NewCertificate(b.mailbox.id, b.mailbox.identity, b.mailbox.work.PublicKey(), 4, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pass.VerifyUnder(sha256.Sum256(later.Marshal()), "dromas.dev", now); !errors.Is(err, ErrCertificate) {
			t.Errorf("%s: under another certificate: %v", name, err)
		}
		// A pass that names another mailbox, signed by this mailbox's working key
		// under this mailbox's certificate: the certificate is for this mailbox.
		elsewhere, _, err := NewPass(b.signer, newCertMailbox(t).id.Address(), "dromas.dev", now)
		if err != nil {
			t.Fatal(err)
		}
		ep, err := ParsePass(elsewhere)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ep.VerifyUnder(sum, "dromas.dev", now); !errors.Is(err, ErrPass) {
			t.Errorf("%s: a pass naming another mailbox, under this mailbox's certificate: %v", name, err)
		}
		if _, err := pass.VerifyUnder(sum, "example.org", now); !errors.Is(err, ErrPass) {
			t.Errorf("%s: for another server: %v", name, err)
		}
		if _, err := pass.VerifyUnder(sum, "dromas.dev", notAfter); !errors.Is(err, ErrPassExpired) {
			t.Errorf("%s: at the moment it runs out: %v", name, err)
		}
		if _, err := pass.VerifyUnder(sum, "dromas.dev", notAfter.Add(-MaxPassLifetime-time.Second)); !errors.Is(err, ErrPass) {
			t.Errorf("%s: more than an hour ahead: %v", name, err)
		}
		// The same statement signed by another key, in a signature that
		// carries this certificate: the hash matches, and the signature does
		// not verify. A signature does not cover the key it names, so the
		// certificate can be put in place of the signer's own.
		other := newCertMailbox(t)
		bare, err := Sign(other.work, PassStatement(a, "dromas.dev", notAfter), PassNamespace(a))
		if err != nil {
			t.Fatal(err)
		}
		blob, err := Dearmor(bare)
		if err != nil {
			t.Fatal(err)
		}
		const head = len("SSHSIG") + 4 // then the signing key, as a string
		swapped := append([]byte{}, blob[:head]...)
		swapped = binary.BigEndian.AppendUint32(swapped, uint32(len(b.cert.Marshal())))
		swapped = append(swapped, b.cert.Marshal()...)
		swapped = append(swapped, blob[head+4+int(binary.BigEndian.Uint32(blob[head:])):]...)
		fp, err := ParsePass(PassScheme + ` address="` + a.String() + `", not_after="` + notAfter.Format(TimeLayout) + `", signature="` + base64.StdEncoding.EncodeToString(Armor(swapped)) + `"`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fp.VerifyUnder(sum, "dromas.dev", now); !errors.Is(err, ErrPass) {
			t.Errorf("%s: a pass another key signed, carrying the certificate: %v", name, err)
		}
		if _, err := fp.Verify(b.mailbox.id, "dromas.dev", now); !errors.Is(err, ErrPass) {
			t.Errorf("%s: Verify took a pass another key signed, carrying the certificate: %v", name, err)
		}
		// A certificate that has ended: a pass signed under it a moment before it ends, checked a moment after.
		end := b.cert.NotAfter()
		late, _, err := NewPass(b.signer, a, "dromas.dev", end.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		lp, err := ParsePass(late)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lp.VerifyUnder(sum, "dromas.dev", end); !errors.Is(err, ErrCertificateTime) {
			t.Errorf("%s: after the certificate ended: %v", name, err)
		}
	}
}

func TestParsePass(t *testing.T) {
	a := strings.Repeat("abcdefgh234567", 5) + "abcdefa"
	sig := base64.StdEncoding.EncodeToString([]byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"))
	good := `dromas-pass address="` + a + `", not_after="2026-10-12T21:40:15Z", signature="` + sig + `"`
	p, err := ParsePass(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.Address.String() != a || !p.NotAfter.Equal(time.Date(2026, 10, 12, 21, 40, 15, 0, time.UTC)) {
		t.Errorf("parsed %v %v", p.Address, p.NotAfter)
	}
	// What RFC 9110 §11 lets a recipient read is read as the same values
	// (testdata/vectors/pass/ has each form against a real signature).
	for name, form := range map[string]string{
		"the scheme in capitals":      strings.Replace(good, "dromas-pass", "Dromas-Pass", 1),
		"a name in capitals":          strings.Replace(good, "not_after=", "NOT_AFTER=", 1),
		"no space after a comma":      strings.Replace(good, `", not_after`, `",not_after`, 1),
		"another order":               `dromas-pass not_after="2026-10-12T21:40:15Z", address="` + a + `", signature="` + sig + `"`,
		"whitespace around = and ,":   `dromas-pass address =` + "\t" + `"` + a + `" ,not_after= "2026-10-12T21:40:15Z"` + "\t,\t" + `signature ="` + sig + `"`,
		"spaces after the scheme":     strings.Replace(good, "dromas-pass ", "dromas-pass   ", 1),
		"the address as a token":      strings.Replace(good, `"`+a+`"`, a, 1),
		"empty list elements":         `dromas-pass , ,address="` + a + `",,not_after="2026-10-12T21:40:15Z", signature="` + sig + `",`,
		"whitespace around the value": " " + good + "\t",
	} {
		q, err := ParsePass(form)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if q.Address != p.Address || !q.NotAfter.Equal(p.NotAfter) || !bytes.Equal(q.signature, p.signature) {
			t.Errorf("%s: read as other values", name)
		}
	}
	for name, bad := range map[string]string{
		"empty":                      "",
		"a bearer token":             "Bearer drt1_" + strings.Repeat("A", 50),
		"the scheme alone":           "dromas-pass",
		"a tab after the scheme":     strings.Replace(good, "dromas-pass ", "dromas-pass\t", 1),
		"a name twice":               good + `, Address="` + a + `"`,
		"a backslash":                strings.Replace(good, `address="`, `address="`+"\\", 1),
		"a control character":        strings.Replace(good, `signature="`, `signature="`+"\x01", 1),
		"a quote not closed":         strings.TrimSuffix(good, `"`),
		"no parameter":               "dromas-pass ,",
		"a parameter missing":        `dromas-pass address="` + a + `", not_after="2026-10-12T21:40:15Z"`,
		"a space in the signature":   strings.Replace(good, sig, sig[:4]+" "+sig[4:], 1),
		"a line break in the base64": strings.Replace(good, sig, sig[:4]+"\n"+sig[4:], 1),
		"an extra parameter":         good + `, extra="1"`,
		"a trailing newline":         good + "\n",
		"an address in capitals":     strings.Replace(good, a, strings.ToUpper(a), 1),
		"a short address":            strings.Replace(good, a, a[:63], 1),
		"a time with an offset":      strings.Replace(good, "21:40:15Z", "21:40:15+", 1),
		"a time that is no time":     strings.Replace(good, "2026-10-12T21:40:15Z", "2026-13-12T21:40:15Z", 1),
		"no quotes":                  strings.ReplaceAll(good, `"`, ""), // ":" and "=" are not a token's
		"an empty signature":         strings.Replace(good, sig, "", 1),
		"base64url in the signature": strings.Replace(good, sig, strings.NewReplacer("+", "-", "/", "_").Replace(sig)+"-", 1),
		"loose base64 padding":       strings.Replace(good, sig, sig+"=", 1),
	} {
		if _, err := ParsePass(bad); !errors.Is(err, ErrPass) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The value is bounded by what a pass can be: one carrying a signature of
	// MaxSignature bytes is the longest, and parses. A longer value is refused
	// for its length, before the grammar or the base64 is read. (A signature
	// of a byte or two more has base64 of the same length: Dearmor refuses it.)
	withSig := func(n int) string {
		return `dromas-pass address="` + a + `", not_after="2026-10-12T21:40:15Z", signature="` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'.'}, n)) + `"`
	}
	if v := withSig(MaxSignature); len(v) != MaxPassAuthorization {
		t.Errorf("a pass with a signature of %d bytes is %d bytes long, and MaxPassAuthorization is %d", MaxSignature, len(v), MaxPassAuthorization)
	} else if _, err := ParsePass(v); err != nil {
		t.Errorf("the longest pass: %v", err)
	}
	if _, err := ParsePass(withSig(MaxSignature + 3)); !errors.Is(err, ErrPass) || !strings.Contains(err.Error(), "longer than a pass can be") {
		t.Errorf("a pass one base64 group too long: %v", err)
	}
}

func TestCheckServerName(t *testing.T) {
	for _, s := range []string{"dromas.dev", "dromas:8080", "127.0.0.1:8013", "localhost", "[::1]:8080", "a-b.example.org:443"} {
		if err := CheckServerName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "Dromas.dev", "https://dromas.dev", "dromas.dev/", "dromas.dev:", "dromas.dev:123456", "dromas dev", "dromas.dev\n", "-dromas.dev", "dromas.dev.:80x", strings.Repeat("a", 256)} {
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
	must(nil, "-q", "-s", "identity", "-I", CertificateKeyID, "-n", a.String(), "-z", "1", "-V", "+64d1h", "-O", "clear", "work.pub")
	// Read after ssh-keygen dates the certificate from its own clock: read
	// before, a run slowed past a second gave a certificate that ends more
	// than 64 days and an hour from now.
	now := time.Now()
	notAfter := now.UTC().Truncate(time.Second).Add(PassLifetime)

	// printf and ssh-keygen make a pass; it verifies here.
	stmt := "dromas-pass-v1\n" + a.String() + "\ndromas.dev\n" + notAfter.Format(TimeLayout) + "\n"
	sig := must([]byte(stmt), "-Y", "sign", "-n", "dromas-pass-v1:"+a.String(), "-f", "work-cert.pub")
	header := `dromas-pass address="` + a.String() + `", not_after="` + notAfter.Format(TimeLayout) + `", signature="` + base64.StdEncoding.EncodeToString(sig) + `"`
	pass, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pass.Verify(id, "dromas.dev", now); err != nil {
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
	ours, oursNotAfter, err := NewPass(signer, a, "dromas.dev", now)
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
	rebuilt := "dromas-pass-v1\n" + a.String() + "\ndromas.dev\n" + oursNotAfter.Format(TimeLayout) + "\n"
	must([]byte(rebuilt), "-Y", "verify", "-f", "signers", "-I", a.String(), "-n", "dromas-pass-v1:"+a.String(), "-s", "ours.sig")
	// The control: for another server's name the same signature fails.
	if _, err := run([]byte(strings.Replace(rebuilt, "dromas.dev", "example.org", 1)), "-Y", "verify", "-f", "signers", "-I", a.String(), "-n", "dromas-pass-v1:"+a.String(), "-s", "ours.sig"); err == nil {
		t.Error("ssh-keygen verified the pass for another server's name")
	}
}

// senderForm is the one form a sender writes a pass in (PROTOCOL.md §8),
// the only one a server took before it read passes as RFC 9110 lets it.
var senderForm = regexp.MustCompile(`\A` + PassScheme + ` address="([a-z2-7]{77})", not_after="([0-9TZ:-]{20})", signature="([A-Za-z0-9+/]+={0,2})"\z`)

// Whatever ParsePass takes, in any form, it reads as the values of a pass in
// the one form a sender writes: those values, written in that form, are
// taken and read back the same. So a looser read of the header gives no value
// the sender's form could not, and the statement the signature covers is
// built from the same values either way.
func FuzzParsePass(f *testing.F) {
	header := strings.TrimSuffix(string(read(f, "a/pass.authorization")), "\n")
	f.Add(header)
	m, err := filepath.Glob(filepath.Join(vectors, "pass", "*.authorization"))
	if err != nil || len(m) == 0 {
		f.Fatalf("no pass/ vectors: %v", err)
	}
	for _, name := range m {
		f.Add(string(read(f, filepath.Join("pass", filepath.Base(name)))))
	}
	f.Fuzz(func(t *testing.T, v string) {
		p, err := ParsePass(v)
		if err != nil {
			if !errors.Is(err, ErrPass) {
				t.Fatalf("refused, but not as ErrPass: %v", err)
			}
			return
		}
		if len(v) > MaxPassAuthorization {
			t.Fatalf("took a value of %d bytes", len(v))
		}
		canonical := p.Authorization()
		if !senderForm.MatchString(canonical) {
			t.Fatalf("its values are not a sender's: %q", canonical)
		}
		q, err := ParsePass(canonical)
		if err != nil {
			t.Fatalf("its values in a sender's form are refused: %v", err)
		}
		if q.Address != p.Address || !q.NotAfter.Equal(p.NotAfter) || !bytes.Equal(q.signature, p.armored()) || q.Authorization() != canonical {
			t.Fatalf("its values in a sender's form read otherwise: %q", canonical)
		}
	})
}

// A pass written another way that a verifier reads as the same is written
// back as one pass, its signature too: the armor's line breaks and
// whitespace, CRLF after the BEGIN line, a NUL before the END line, text
// after it, SSHSIG version 0, a NUL ending the namespace and bytes in the
// reserved field, which nothing signs. A server remembers a pass by its
// Authorization, so each costs it one check (dromas-dev/dromas-server#69).
// A signature that differs in a byte the verifier reads is another pass: a
// bit of the signature itself, the hash it names, a byte after its five
// fields (#445).
func TestAPassWrittenAnotherWayIsOnePass(t *testing.T) {
	header := strings.TrimSuffix(string(read(t, "a/pass.authorization")), "\n")
	p, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Authorization(); got != header {
		t.Fatalf("the vector's pass is written back otherwise:\n%s\n%s", got, header)
	}
	armored := p.signature
	blob, err := Dearmor(armored)
	if err != nil {
		t.Fatal(err)
	}
	// rewrite is blob with version v, a NUL after its namespace when nul,
	// reserved in its reserved field, the hash named hash where it is not
	// empty and tail after the five fields, armored as ssh-keygen does.
	rewrite := func(v uint32, nul bool, reserved []byte, hash string, tail []byte) []byte {
		r := wireReader(blob[10:])
		key, _ := r.string()
		ns, _ := r.string()
		_, _ = r.string()
		named, _ := r.string()
		sig, _ := r.string()
		if nul {
			ns = append(append([]byte{}, ns...), 0)
		}
		if hash != "" {
			named = []byte(hash)
		}
		out := binary.BigEndian.AppendUint32([]byte("SSHSIG"), v)
		for _, s := range [][]byte{key, ns, reserved, named, sig} {
			out = appendWireString(out, s)
		}
		return Armor(append(out, tail...))
	}
	body := bytes.IndexByte(armored, '\n') + 1
	forms := map[string][]byte{
		"CRLF after the BEGIN line":    bytes.Replace(armored, []byte("-----\n"), []byte("-----\r\n"), 1),
		"text after the END line":      append(append([]byte{}, armored...), "anything"...),
		"a tab inside the base64":      bytes.Replace(armored, []byte("-----\n"), []byte("-----\n\t"), 1),
		"a NUL before the END line":    bytes.Replace(armored, []byte("\n-----END"), []byte("\x00\n-----END"), 1),
		"the base64 on one line":       []byte(armorBegin + base64.StdEncoding.EncodeToString(blob) + "\n" + armorEnd + "\n"),
		"a space inside the base64":    append(append(append([]byte{}, armored[:body+7]...), ' '), armored[body+7:]...),
		"SSHSIG version 0":             rewrite(0, false, nil, "", nil),
		"a NUL ending the namespace":   rewrite(1, true, nil, "", nil),
		"a byte in the reserved field": rewrite(1, false, []byte{'x'}, "", nil),
	}
	for name, sig := range forms {
		if _, err := Dearmor(sig); err != nil {
			t.Fatalf("%s: OpenSSH's reading refuses it: %v", name, err)
		}
		q, err := ParsePass(strings.Replace(header, base64.StdEncoding.EncodeToString(armored), base64.StdEncoding.EncodeToString(sig), 1))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := q.Authorization(); got != header {
			t.Errorf("%s: written back as another pass", name)
		}
	}
	// A byte the verifier reads: one bit of the signature itself, in its
	// last string, the other hash §3.2 lets a signature name (the vector's
	// is sha512), and a byte after the five fields, which it refuses.
	flipped := append([]byte{}, blob...)
	flipped[len(flipped)-1] ^= 1
	others := map[string][]byte{
		"a bit of the signature":       Armor(flipped),
		"the hash named sha256":        rewrite(1, false, nil, "sha256", nil),
		"a byte after the five fields": rewrite(1, false, nil, "", []byte{0}),
	}
	for name, sig := range others {
		q, err := ParsePass(strings.Replace(header, base64.StdEncoding.EncodeToString(armored), base64.StdEncoding.EncodeToString(sig), 1))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if q.Authorization() == header {
			t.Errorf("%s: written back as the same pass", name)
		}
	}
}

// LowerASCII, the one fold a protocol token is compared by, lowers A to Z
// and nothing else: no character Unicode's case folding takes for an ASCII
// letter (the long s, the Kelvin sign, the dotted capital I) becomes one
// (#405).
func TestLowerASCIILowersAToZAlone(t *testing.T) {
	for in, want := range map[string]string{
		"Dromas-Pass":    "dromas-pass",
		"BYTES":          "bytes",
		"byteſ":          "byteſ",
		"KEY":            "Key",
		"İD":             "İd",
		"[]^_`{|}~@AZaz": "[]^_`{|}~@azaz",
	} {
		if got := LowerASCII(in); got != want {
			t.Errorf("LowerASCII(%q) = %q, want %q", in, got, want)
		}
	}
}
