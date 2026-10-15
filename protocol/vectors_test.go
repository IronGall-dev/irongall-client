package protocol

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/IronGall-dev/irongall-client/sshsig"
	"golang.org/x/crypto/ssh"
)

const vectors = "../testdata/vectors"

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(vectors, pattern))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) == 0 {
		t.Fatalf("no vectors match %s", pattern)
	}
	return m
}

func vectorNow(t *testing.T) time.Time {
	t.Helper()
	now, err := ParseTime(strings.TrimSpace(string(read(t, "now"))))
	if err != nil {
		t.Fatal(err)
	}
	return now
}

// vectorKey returns a box's RFC 8032 test key from input/<box>.ed25519.
func vectorKey(t *testing.T, box string) (ssh.Signer, ed25519.PublicKey) {
	t.Helper()
	s := bufio.NewScanner(bytes.NewReader(read(t, "input/"+box+".ed25519")))
	var lines [][]byte
	for s.Scan() {
		b, err := hex.DecodeString(s.Text())
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, b)
	}
	priv := ed25519.NewKeyFromSeed(lines[0])
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), lines[1]) {
		t.Fatalf("%s: the seed does not give the public key", box)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, lines[1]
}

func vectorIdentity(t *testing.T, box string) *Identity {
	t.Helper()
	id, err := ParseIdentity(read(t, box+"/identity.doc"))
	if err != nil {
		t.Fatalf("%s: %v", box, err)
	}
	return id
}

func TestVectorIdentities(t *testing.T) {
	for _, box := range []string{"a", "b"} {
		id := vectorIdentity(t, box)
		if got, want := id.Address().String(), strings.TrimSpace(string(read(t, box+"/address"))); got != want {
			t.Errorf("%s: address %s, want %s", box, got, want)
		}
		_, pub := vectorKey(t, box)
		built, err := NewIdentity(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(built.Document(), read(t, box+"/identity.doc")) {
			t.Errorf("%s: NewIdentity built a different document", box)
		}
	}
}

// Box C's identity is of the optional type, and everything a box says is
// checked under it as under an Ed25519 one.
func TestVectorP256Identity(t *testing.T) {
	now := vectorNow(t)
	c := vectorIdentity(t, "c")
	if c.Type() != IdentityP256 || len(c.Document()) != 173 {
		t.Errorf("c: a %s identity of %d bytes", c.Type(), len(c.Document()))
	}
	if got, want := c.Address().String(), strings.TrimSpace(string(read(t, "c/address"))); got != want {
		t.Errorf("c: address %s, want %s", got, want)
	}
	built, err := IdentityOf(c.PublicKey())
	if err != nil || !bytes.Equal(built.Document(), read(t, "c/identity.doc")) {
		t.Errorf("c: IdentityOf built a different document: %v", err)
	}
	p, cert, err := VerifyPrekey(c, read(t, "c/prekey-1.txt"), read(t, "c/prekey-1.txt.sig"), now)
	if err != nil || p.Serial != 1 || cert.Serial() != 1 {
		t.Fatalf("c/prekey-1.txt: %v", err)
	}
	// A statement under C's certificate is not A's, and A's is not C's.
	a := vectorIdentity(t, "a")
	if _, _, err := VerifyPrekey(a, read(t, "c/prekey-1.txt"), read(t, "c/prekey-1.txt.sig"), now); err == nil {
		t.Error("C's statement verified for A")
	}
	if _, err := VerifyCertified(c, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), PrekeyNamespace(a.Address()), now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a signature under A's certificate, checked against C's identity: %v", err)
	}
}

func TestVectorBadIdentities(t *testing.T) {
	for _, f := range glob(t, "identity/*.doc") {
		doc, _ := os.ReadFile(f)
		name := filepath.Base(f)
		_, err := ParseIdentity(doc)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// A server answers a format error with identity_mismatch, a key
		// error with bad_key, and a well-formed document of a type it does
		// not register with unsupported_key_type.
		keyCase := strings.HasPrefix(name, "small-order") || name == "non-canonical.doc" || name == "negative-zero.doc"
		p256Refuses := name == "p256-short-coordinate.doc" || name == "p256-coordinate-over-order.doc"
		want := ErrIdentityFormat
		switch {
		case keyCase, p256Refuses, name == "p256-off-curve.doc", name == "p256-coordinate-not-reduced.doc":
			want = ErrIdentityKey
		case strings.HasPrefix(name, "unsupported-"):
			want = ErrIdentityType
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want it to wrap %v", name, err, want)
		}
		// Control: these two are points on the curve in the one encoding,
		// which the library takes, so the check OpenSSH makes has to be ours.
		if p256Refuses {
			wire := mustB64(t, bytes.Fields(doc)[2])
			if key, err := ssh.ParsePublicKey(wire); err != nil || !bytes.Equal(key.Marshal(), wire) {
				t.Errorf("%s: control: the library refuses it already: %v", name, err)
			}
		}
		// Control: the key cases are well-formed documents, so the KEY check
		// is what refused them, and edwards25519 itself decodes the point,
		// so the check has to be ours.
		if keyCase {
			m := identityGrammar.FindSubmatch(doc)
			if m == nil {
				t.Errorf("%s: control: not a well-formed document", name)
				continue
			}
			key, err := ssh.ParsePublicKey(mustB64(t, m[1]))
			if err != nil {
				t.Fatal(err)
			}
			raw := key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
			if _, err := new(edwards25519.Point).SetBytes(raw); err != nil && name != "negative-zero.doc" {
				t.Errorf("%s: control: edwards25519 rejects it already: %v", name, err)
			}
		}
	}
}

// vectorCertificate parses a kept certificate, a line of "<type> <base64>".
func vectorCertificate(t *testing.T, name string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey(read(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return key
}

// vectorWorker returns a box's working key as a signer under its kept
// certificate: what "ssh-keygen -Y sign -f work-cert.pub" signs with.
func vectorWorker(t *testing.T, box string) ssh.Signer {
	t.Helper()
	work, _ := vectorKey(t, box+"-work")
	cert, err := CheckCertificate(vectorIdentity(t, box), vectorCertificate(t, box+"/work-cert.pub"), vectorNow(t))
	if err != nil {
		t.Fatalf("%s/work-cert.pub: %v", box, err)
	}
	s, err := cert.Signer(work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVectorCertificates(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	for _, c := range []struct {
		id   *Identity
		file string
	}{{a, "a/work-cert.pub"}, {b, "b/work-cert.pub"}} {
		cert, err := CheckCertificate(c.id, vectorCertificate(t, c.file), now)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if cert.Serial() != 1 || !cert.NotAfter().Equal(now.Add(CertificateLifetime)) || !cert.SignsMail(now) {
			t.Errorf("%s: serial %d, ends %s", c.file, cert.Serial(), cert.NotAfter())
		}
	}
	if _, err := CheckCertificate(b, vectorCertificate(t, "a/work-cert.pub"), now); !errors.Is(err, ErrCertificate) {
		t.Errorf("B took A's certificate: %v", err)
	}
	st := read(t, "a/prekey-1.txt")
	for _, f := range glob(t, "cert/ok-*.pub") {
		name := strings.TrimSuffix(filepath.Base(f), ".pub")
		if _, err := CheckCertificate(a, vectorCertificate(t, "cert/"+name+".pub"), now); err != nil {
			t.Errorf("%s: CheckCertificate: %v", name, err)
		}
		if _, err := VerifyCertified(a, st, read(t, "cert/"+name+".sig"), PrekeyNamespace(a.Address()), now); err != nil {
			t.Errorf("%s: VerifyCertified: %v", name, err)
		}
	}
	for _, f := range glob(t, "cert/bad-*.pub") {
		name := strings.TrimSuffix(filepath.Base(f), ".pub")
		key := vectorCertificate(t, "cert/"+name+".pub")
		sig := read(t, "cert/"+name+".sig")
		want := ErrCertificate
		switch name {
		case "bad-ended":
			want = ErrCertificateEnded
		case "bad-not-begun":
			want = ErrCertificateNotBegun
		}
		if _, err := CheckCertificate(a, key, now); !errors.Is(err, want) {
			t.Errorf("%s: CheckCertificate: %v, want %v", name, err, want)
		}
		if _, err := VerifyCertified(a, st, sig, PrekeyNamespace(a.Address()), now); !errors.Is(err, want) {
			t.Errorf("%s: VerifyCertified: %v, want %v", name, err, want)
		}
		// Control: the signature is good under the certificate it carries,
		// so the certificate is what was refused.
		blob, err := Dearmor(sig)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := sshsig.Verify(key, st, blob, PrekeyNamespace(a.Address())); err != nil {
			t.Errorf("%s: control: the signature itself fails: %v", name, err)
		}
	}
}

func TestVectorPrekeys(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	for _, c := range []struct {
		id     *Identity
		file   string
		sig    string
		serial uint64
		typ    KeyType
	}{
		{a, "a/prekey-1.txt", "a/prekey-1.txt.sig", 1, PostQuantum},
		{a, "a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", 1, PostQuantum},
		{a, "a/prekey-2.txt", "a/prekey-2.txt.sig", 2, Classic},
		{b, "b/prekey-1.txt", "b/prekey-1.txt.sig", 1, PostQuantum},
	} {
		p, cert, err := VerifyPrekey(c.id, read(t, c.file), read(t, c.sig), now)
		if err != nil {
			t.Errorf("%s: %v", c.sig, err)
			continue
		}
		if p.Serial != c.serial || p.Type() != c.typ || p.Expired(now) || p.CheckLifetime(now) != nil || cert.Serial() != 1 {
			t.Errorf("%s: serial %d type %s expired %v lifetime %v", c.file, p.Serial, p.Type(), p.Expired(now), p.CheckLifetime(now))
		}
		if !bytes.Equal(p.Statement(), read(t, c.file)) {
			t.Errorf("%s: Statement does not reproduce the file", c.file)
		}
		if _, err := p.Recipient(); err != nil {
			t.Errorf("%s: %v", c.file, err)
		}
	}
	if _, _, err := VerifyPrekey(b, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), now); err == nil {
		t.Error("B accepted A's prekey")
	}
	// A statement is checked at the verifier's clock: once its certificate
	// has ended, it no longer verifies.
	if _, _, err := VerifyPrekey(a, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), now.Add(CertificateLifetime)); err == nil {
		t.Error("a prekey statement verified after its certificate ended")
	}
}

func TestVectorBadPrekeys(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	// These fail at the signature or its certificate; every other bad-* is
	// well signed, so its format is what refuses it.
	signature := map[string]bool{
		"bad-wrong-namespace": true, "bad-signed-by-b": true, "bad-signed-by-the-identity": true,
		"bad-signed-by-a-bare-working-key": true,
	}
	for _, f := range glob(t, "prekey/*.txt") {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		st, _ := os.ReadFile(f)
		sig, _ := os.ReadFile(f + ".sig")
		p, _, err := VerifyPrekey(a, st, sig, now)
		switch {
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			if !signature[name] {
				if _, err := VerifyCertified(a, st, sig, PrekeyNamespace(a.Address()), now); err != nil {
					t.Errorf("%s: control: the signature itself fails: %v", name, err)
				}
			}
		case name == "expired":
			if err != nil || !p.Expired(now) || p.CheckLifetime(now) == nil {
				t.Errorf("%s: want valid and expired: %v", name, err)
			}
		case name == "longest":
			if err != nil || p.Expired(now) || p.CheckLifetime(now) != nil || !p.NotAfter.Equal(now.Add(MaxPrekeyLifetime)) {
				t.Errorf("%s: want valid, not expired, and the longest a server takes: %v", name, err)
			}
		case name == "too-long":
			if err != nil || p.Expired(now) || p.CheckLifetime(now) == nil || !p.NotAfter.Equal(now.Add(MaxPrekeyLifetime+time.Second)) {
				t.Errorf("%s: want valid, not expired, and refused for publishing: %v", name, err)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// TestVectorSignatures checks Go's signatures are byte-identical to the
// ssh-keygen ones in the vectors: Ed25519 is deterministic, and a signature
// under a kept certificate carries that certificate's bytes.
func TestVectorSignatures(t *testing.T) {
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	ia, _ := vectorKey(t, "a")
	wa, wb := vectorWorker(t, "a"), vectorWorker(t, "b")
	for _, c := range []struct {
		signer ssh.Signer
		msg    string
		sig    string
		ns     string
	}{
		{wa, "a/prekey-1.txt", "a/prekey-1.txt.sig", PrekeyNamespace(a.Address())},
		{wa, "a/prekey-2.txt", "a/prekey-2.txt.sig", PrekeyNamespace(a.Address())},
		{wb, "b/prekey-1.txt", "b/prekey-1.txt.sig", PrekeyNamespace(b.Address())},
		{wa, "a/pass.txt", "a/pass.sig", PassNamespace(a.Address())},
		{wa, "message/a-to-b.line", "message/a-to-b.sig", MessageNamespace(b.Address())},
		{ia, "a/revoke.txt", "a/revoke.sig", RevokeNamespace(a.Address())},
	} {
		got, err := Sign(c.signer, read(t, c.msg), c.ns)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, read(t, c.sig)) {
			t.Errorf("%s: Go's signature differs from ssh-keygen's:\n%s", c.sig, got)
		}
	}
	// The revocation is the identity's own signature, the one thing it signs
	// beside certificates.
	if err := Verify(a, read(t, "a/revoke.txt"), read(t, "a/revoke.sig"), RevokeNamespace(a.Address())); err != nil {
		t.Errorf("a/revoke.sig: %v", err)
	}
	if !bytes.Equal(RevocationStatement(a.Address()), read(t, "a/revoke.txt")) {
		t.Error("RevocationStatement differs from a/revoke.txt")
	}
}

// One signature in the forms sig/ holds: each ok-* is read as "ssh-keygen -Y
// verify" reads it and verifies, and each bad-* is refused (PROTOCOL.md §3).
// sh/sh_test.go holds the script to the same verdicts, and ssh-keygen too but
// for the ones it takes and a verifier here does not.
func TestVectorSignatureForms(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	stmt := read(t, "a/prekey-1.txt")
	for _, f := range glob(t, "sig/*.sig") {
		name := "sig/" + filepath.Base(f)
		_, err := VerifyCertified(a, stmt, read(t, name), PrekeyNamespace(a.Address()), now)
		if ok := strings.HasPrefix(filepath.Base(f), "ok-"); ok != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(read(t, "sig/ok-4096-bytes.sig")); n != MaxSignature {
		t.Errorf("sig/ok-4096-bytes.sig is %d bytes, not the bound", n)
	}
	if n := len(read(t, "sig/bad-4097-bytes.sig")); n != MaxSignature+1 {
		t.Errorf("sig/bad-4097-bytes.sig is %d bytes, not one over the bound", n)
	}
}

func TestVectorPass(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	const server = "irongall.example"
	header := strings.TrimSuffix(string(read(t, "a/pass.authorization")), "\n")
	got, notAfter, err := NewPass(vectorWorker(t, "a"), a.Address(), server, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != header || !notAfter.Equal(now.Add(PassLifetime)) {
		t.Errorf("NewPass differs from a/pass.authorization:\n%s", got)
	}
	if !bytes.Equal(PassStatement(a.Address(), server, notAfter), read(t, "a/pass.txt")) {
		t.Error("PassStatement differs from a/pass.txt")
	}
	p, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	if cert, err := p.Verify(a, server, now); err != nil || cert.Serial() != 1 {
		t.Errorf("a/pass.authorization: %v", err)
	}
	if _, err := p.Verify(a, "another.example", now); !errors.Is(err, ErrPass) {
		t.Errorf("a pass for one server was taken by another: %v", err)
	}
	if _, err := p.Verify(b, server, now); !errors.Is(err, ErrPass) {
		t.Errorf("A's pass was taken as B's: %v", err)
	}
	if _, err := p.Verify(a, server, now.Add(PassLifetime)); !errors.Is(err, ErrPassExpired) {
		t.Errorf("a pass was taken at the moment it runs out: %v", err)
	}
}

// plainVerdicts is what B makes of each plain/ vector at ./now: "" for a
// message that is delivered, or the code it is refused with.
var plainVerdicts = map[string]string{
	"accept-no-padding":                                  "",
	"accept-padded":                                      "",
	"accept-anything-after-the-signature":                "",
	"accept-every-field":                                 "",
	"refuse-signed-for-another-box":                      RefusedSignature,
	"refuse-signed-by-the-identity":                      RefusedSignature,
	"refuse-signed-by-a-bare-working-key":                RefusedSignature,
	"refuse-certificate-ended":                           RefusedSignature,
	"refuse-line-changed-after-signing":                  RefusedSignature,
	"refuse-another-box-s-identity-document":             RefusedSignature,
	"refuse-from-is-not-the-identity":                    RefusedAttribution,
	"accept-p256-sender":                                 "",
	"refuse-unsupported-key-type":                        RefusedKeyType,
	"refuse-from-is-not-the-identity-of-an-unknown-type": RefusedAttribution,
	"refuse-to-another-box":                              RefusedAttribution,
	"refuse-no-identity":                                 RefusedIdentity,
	"refuse-identity-not-base64":                         RefusedIdentity,
	"refuse-identity-of-small-order":                     RefusedIdentity,
	"refuse-no-line-feed":                                RefusedMessage,
	"refuse-no-signature":                                RefusedMessage,
	"refuse-blank-line-before-the-signature":             RefusedMessage,
	"refuse-signature-first":                             RefusedMessage,
	"refuse-no-end-line":                                 RefusedMessage,
	"refuse-end-line-without-its-line-feed":              RefusedMessage,
	"refuse-crlf":                                        RefusedMessage,
	"refuse-envelope-on-two-lines":                       RefusedMessage,
	"accept-whitespace-in-the-signature":                 "",
	"refuse-signature-over-4096-bytes":                   RefusedSignature,
}

func TestVectorPlaintexts(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	seen := 0
	for _, f := range glob(t, "plain/*.txt") {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		a := a
		if name == "accept-p256-sender" {
			a = vectorIdentity(t, "c")
		}
		want, known := plainVerdicts[name]
		if !known {
			t.Errorf("%s: unknown vector", name)
			continue
		}
		seen++
		pt, _ := os.ReadFile(f)
		m, err := OpenSigned(pt, b.Address(), now)
		var refused *EnvelopeError
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case want == "" && (m.Sender.Address() != a.Address() || m.Envelope.From != a.Address() || m.Certificate.Serial() != 1):
			t.Errorf("%s: delivered as from %s", name, m.Sender.Address())
		case want != "" && err == nil:
			t.Errorf("%s: accepted", name)
		case want != "" && (!errors.As(err, &refused) || refused.Code != want):
			t.Errorf("%s: refused as %v, want %s", name, err, want)
		}
		// The line that was checked is the first line as it arrived, byte
		// for byte: nothing is verified or read from a rebuilt copy.
		if err == nil && !bytes.HasPrefix(pt, m.Line) {
			t.Errorf("%s: the line that was verified is not the bytes that arrived", name)
		}
	}
	if seen != len(plainVerdicts) {
		t.Errorf("%d of %d plain/ vectors are present", seen, len(plainVerdicts))
	}
	// What follows the first END line is never read: the second signature
	// block in this vector is B's, and the message is still A's.
	if m, err := OpenSigned(read(t, "plain/accept-anything-after-the-signature.txt"), b.Address(), now); err != nil || !bytes.Equal(m.Signature, read(t, "message/a-to-b.sig")) {
		t.Errorf("the signature taken is not the first block: %v", err)
	}
}

func TestVectorMessage(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	// Go builds the same plaintext as the stock tools did: the line, the
	// signature under the kept certificate, and the padding for B's prekey.
	env := &Envelope{From: a.Address(), To: b.Address(), SentAt: now, MsgID: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b", Identity: a.Document(), Body: []byte(`"hello"`)}
	line, sig, err := SignEnvelope(env, vectorWorker(t, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(line, read(t, "message/a-to-b.line")) || !bytes.Equal(sig, read(t, "message/a-to-b.sig")) {
		t.Errorf("SignEnvelope differs from message/a-to-b.line and .sig:\n%s%s", line, sig)
	}
	pt, sealed := Plaintext(line, sig, PostQuantum)
	m := read(t, "message/a-to-b.age")
	if !bytes.Equal(pt, read(t, "message/a-to-b.plain")) || sealed != len(m) {
		t.Errorf("Plaintext differs from message/a-to-b.plain: %d bytes for a file of %d, want %d", len(pt), sealed, len(m))
	}
	if !bytes.HasPrefix(m, []byte("age-encryption.org/v1\n-> mlkem768x25519 ")) {
		t.Error("the message is not a post-quantum age file")
	}
	if len(m) != PaddedSize(len(m)) {
		t.Errorf("the message is %d bytes, not a whole number of blocks", len(m))
	}
}

func TestVectorEnvelopes(t *testing.T) {
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	for _, f := range glob(t, "envelope/*.json") {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		pt, _ := os.ReadFile(f)
		env, err := OpenEnvelope(pt, a.Address(), b.Address(), now)
		switch {
		case strings.HasPrefix(name, "accept-"):
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if name == "accept-case-variant-key" && err == nil && string(env.Body) != `"benign"` {
				t.Errorf("%s: body %s: BODY is an unknown key, never the body", name, env.Body)
			}
		case strings.HasPrefix(name, "refuse-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			// The two ends of the sent_at window have a code each.
			var ee *EnvelopeError
			if want := map[string]string{"refuse-33-days-and-1s-old": RefusedStale, "refuse-1-hour-and-1s-ahead": RefusedFuture}[name]; want != "" && (!errors.As(err, &ee) || ee.Code != want) {
				t.Errorf("%s: refused as %v, want the code %s", name, err, want)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

func mustB64(t *testing.T, s []byte) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// oddR signs as an Ed25519 key does, with an R that RFC 8032's signer never
// makes: the neutral point (r = 0), or rB plus the point of order 2, (0, -1).
// Only the key's holder can make either.
type oddR struct {
	priv   ed25519.PrivateKey
	order2 bool
}

func (o oddR) PublicKey() ssh.PublicKey {
	k, _ := ssh.NewPublicKey(o.priv.Public())
	return k
}

func (o oddR) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	d := sha512.Sum512(o.priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(d[:32])
	if err != nil {
		return nil, err
	}
	r, R := edwards25519.NewScalar(), edwards25519.NewIdentityPoint()
	if o.order2 {
		w := sha512.Sum512([]byte("irongall vector: R plus the point of order 2"))
		if _, err := r.SetUniformBytes(w[:]); err != nil {
			return nil, err
		}
		t, err := new(edwards25519.Point).SetBytes(append(append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 30)...), 0x7f))
		if err != nil {
			return nil, err
		}
		R.Add(new(edwards25519.Point).ScalarBaseMult(r), t)
	}
	k := sha512.New()
	k.Write(R.Bytes())
	k.Write(o.priv.Public().(ed25519.PublicKey))
	k.Write(data)
	h, err := edwards25519.NewScalar().SetUniformBytes(k.Sum(nil))
	if err != nil {
		return nil, err
	}
	S := edwards25519.NewScalar().MultiplyAdd(h, a, r)
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: append(R.Bytes(), S.Bytes()...)}, nil
}

// The two sig/ vectors stock tools cannot make: A's first prekey statement
// signed by its working key with an R that RFC 8032's signer never makes.
// The equation without the cofactor, as Go's crypto/ed25519 and OpenSSL
// check it, takes a neutral R and refuses R plus a point of order 2; OpenSSH's
// own Ed25519 from 10.6p1 judges both the other way (PROTOCOL.md §3). They
// are made here, the same bytes each time, and the kept files are held to
// them: IRONGALL_WRITE_VECTORS=1 writes them.
func TestVectorsEd25519R(t *testing.T) {
	a := vectorIdentity(t, "a")
	seed, err := hex.DecodeString(strings.Fields(string(read(t, "input/a-work.ed25519")))[0])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CheckCertificate(a, vectorCertificate(t, "a/work-cert.pub"), vectorNow(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		name   string
		order2 bool
	}{{"sig/ok-r-small-order.sig", false}, {"sig/bad-r-plus-order-2.sig", true}} {
		signer, err := cert.Signer(oddR{ed25519.NewKeyFromSeed(seed), v.order2})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(signer, read(t, "a/prekey-1.txt"), PrekeyNamespace(a.Address()))
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("IRONGALL_WRITE_VECTORS") != "" {
			if err := os.WriteFile(filepath.Join(vectors, v.name), sig, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(read(t, v.name), sig) {
			t.Errorf("%s is not what this test makes", v.name)
		}
	}
}
