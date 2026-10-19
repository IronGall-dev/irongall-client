package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// p256Box is a box whose identity is a P-256 key, with an Ed25519 working key.
func p256Box(t *testing.T) certBox {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityOf(identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	_, w, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(w)
	if err != nil {
		t.Fatal(err)
	}
	return certBox{id: id, identity: identity, work: work}
}

func docOf(typ string, wire []byte) []byte {
	return []byte(IdentityTag + "\n" + typ + " " + base64.StdEncoding.EncodeToString(wire) + "\n")
}

// A document of a key type this package does not define is told apart from
// something that is no document: the first is ErrIdentityType, and nothing is
// wrong with it; the second is ErrIdentityFormat.
func TestAnIdentityOfATypeThisClientLacks(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Pub, err := ssh.NewPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	const made = "no-such-key-type@irongall.invalid"
	madeWire := append(sshString(made), 1, 2, 3)
	long := strings.Repeat("x", 64)
	lacks := map[string][]byte{
		"an RSA key":                     docOf(rsaPub.Type(), rsaPub.Marshal()),
		"a P-384 key":                    docOf(p384Pub.Type(), p384Pub.Marshal()),
		"a type nobody defines":          docOf(made, madeWire),
		"a name of 64 characters":        docOf(long, sshString(long)),
		"a name and nothing after it":    docOf(made, sshString(made)),
		"a key that is not a key at all": docOf(made, append(sshString(made), bytes.Repeat([]byte{0xff}, 300)...)),
	}
	for name, doc := range lacks {
		if _, err := ParseIdentity(doc); !errors.Is(err, ErrIdentityType) {
			t.Errorf("%s: %v, want ErrIdentityType", name, err)
		}
	}
	tooLong := strings.Repeat("x", 65)
	b64 := base64.StdEncoding.EncodeToString(madeWire)
	notDocuments := map[string][]byte{
		"a name the wire key does not begin with": docOf(made, rsaPub.Marshal()),
		"a name of 65 characters":                 docOf(tooLong, sshString(tooLong)),
		"a comma in the name":                     docOf("a,b", sshString("a,b")),
		"a comment":                               []byte(IdentityTag + "\n" + made + " " + b64 + " me@host\n"),
		"two spaces":                              []byte(IdentityTag + "\n" + made + "  " + b64 + "\n"),
		"no final newline":                        []byte(IdentityTag + "\n" + made + " " + b64),
		"CRLF":                                    []byte(IdentityTag + "\r\n" + made + " " + b64 + "\r\n"),
		"a third line":                            []byte(IdentityTag + "\n" + made + " " + b64 + "\n\n"),
		"another tag":                             []byte("irongall-v2\n" + made + " " + b64 + "\n"),
		"a character after the padding":           []byte(IdentityTag + "\n" + made + " " + b64[:len(b64)-1] + "B\n"),
		"base64 without its padding":              []byte(IdentityTag + "\n" + made + " " + strings.TrimRight(base64.StdEncoding.EncodeToString(append(madeWire, 0)), "=") + "\n"),
		"no key":                                  []byte(IdentityTag + "\n" + made + " \n"),
		"nothing":                                 nil,
	}
	for name, doc := range notDocuments {
		if _, err := ParseIdentity(doc); !errors.Is(err, ErrIdentityFormat) {
			t.Errorf("%s: %v, want ErrIdentityFormat", name, err)
		}
	}
	// A type this package defines is never "a type it lacks": a bad document
	// of one is a bad document.
	for _, typ := range IdentityTypes() {
		if _, err := ParseIdentity(docOf(typ, append(sshString(typ), 1, 2, 3))); !errors.Is(err, ErrIdentityFormat) {
			t.Errorf("a broken %s document: %v, want ErrIdentityFormat", typ, err)
		}
	}
}

// The P-256 form's fixed characters are the base64 of a P-256 key's fixed
// bytes, so the pattern refuses nothing a key can be.
func TestP256DocumentForm(t *testing.T) {
	for range 200 {
		b := p256Box(t)
		doc := b.id.Document()
		if len(doc) != 173 || b.id.Type() != IdentityP256 {
			t.Fatalf("a P-256 document of %d bytes, type %s", len(doc), b.id.Type())
		}
		got, err := ParseIdentity(doc)
		if err != nil || got.Address() != b.id.Address() {
			t.Fatalf("a P-256 document does not parse: %v", err)
		}
	}
}

// The Ed25519 form's 26th character holds the low two bits of the key's
// length, 32, and the high four of its first byte: the pattern takes a key
// whatever that byte is, and refuses the same key with its length written
// 33, 34 or 35, which no SSH parser reads, as a broken form (#118).
func TestEd25519DocumentForm(t *testing.T) {
	seen := map[byte]bool{}
	for len(seen) < 16 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := NewIdentity(pub)
		if err != nil || len(id.Document()) != 93 {
			t.Fatalf("an Ed25519 document does not parse: %v", err)
		}
		seen[pub[0]>>4] = true
		for _, n := range []byte{33, 34, 35} {
			wire := append(append(sshString(IdentityEd25519), 0, 0, 0, n), pub...)
			if _, err := ParseIdentity(docOf(IdentityEd25519, wire)); !errors.Is(err, ErrIdentityFormat) {
				t.Fatalf("its key with the length written %d: %v, want ErrIdentityFormat", n, err)
			}
			if _, err := ssh.ParsePublicKey(wire); err == nil {
				t.Fatalf("control: x/crypto/ssh reads the length written %d", n)
			}
		}
	}
}

// What OpenSSH required of a P-256 point beyond being on the curve up to
// 10.2p1, and the protocol still does: each coordinate more than 128 bits
// long, and below the group's order less one.
func TestCheckP256(t *testing.T) {
	n := elliptic.P256().Params().N
	wire := func(x, y *big.Int) []byte {
		q := append([]byte{4}, x.FillBytes(make([]byte, 32))...)
		q = append(q, y.FillBytes(make([]byte, 32))...)
		return append(append(sshString(IdentityP256), sshString("nistp256")...), append([]byte{0, 0, 0, 65}, q...)...)
	}
	two128 := new(big.Int).Lsh(big.NewInt(1), 128)
	ok := two128                                     // 129 bits
	short := new(big.Int).Sub(two128, big.NewInt(1)) // 128 bits
	last := new(big.Int).Sub(n, big.NewInt(2))       // n - 2
	over := new(big.Int).Sub(n, big.NewInt(1))       // n - 1
	for _, c := range []struct {
		name string
		x, y *big.Int
		good bool
	}{
		{"both just long enough", ok, ok, true},
		{"both just below the limit", last, last, true},
		{"x of 128 bits", short, ok, false},
		{"y of 128 bits", ok, short, false},
		{"x of n - 1", over, ok, false},
		{"y of n - 1", ok, over, false},
		{"x of zero", new(big.Int), ok, false},
	} {
		if err := checkP256(wire(c.x, c.y)); (err == nil) != c.good {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := checkP256([]byte{2}); err == nil {
		t.Error("a key that is no uncompressed point passed")
	}
}

// A P-256 identity certifies an Ed25519 working key, and what that key signs
// verifies under it; a certificate another P-256 key signed does not.
func TestAP256IdentityCertifies(t *testing.T) {
	b, other := p256Box(t), p256Box(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 3, now)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cert.Signer(b.work)
	if err != nil {
		t.Fatal(err)
	}
	msg, ns := []byte("a statement\n"), "irongall-test-v1:"+b.id.Address().String()
	sig, err := Sign(signer, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyCertified(b.id, msg, sig, ns, now); err != nil || got.Serial() != 3 {
		t.Fatalf("a signature under a P-256 identity's certificate: %v", err)
	}
	if _, err := VerifyCertified(other.id, msg, sig, ns, now); !errors.Is(err, ErrCertificate) {
		t.Errorf("it verified for another P-256 identity: %v", err)
	}
	if _, err := NewCertificate(b.id, other.identity, b.work.PublicKey(), 3, now); err == nil {
		t.Error("a certificate was made with a signer that is not the identity")
	}
	// A working key is an Ed25519 key, whatever its identity's type.
	if _, err := NewCertificate(b.id, b.identity, other.identity.PublicKey(), 4, now); err == nil {
		t.Error("a P-256 key was certified as a working key")
	}

	// An ECDSA signature (r, s) verifies as (r, n - s) too, and with either
	// number written longer, up to the 2,049 bytes OpenSSH reads, and anyone
	// who has seen a certificate can write those. So a certificate of an ECDSA identity has many sets of bytes,
	// and nothing may rest on a certificate's bytes being the only ones its
	// identity signed.
	c := cert.PublicKey().(*ssh.Certificate)
	var rs struct{ R, S *big.Int }
	if err := ssh.Unmarshal(c.Signature.Blob, &rs); err != nil {
		t.Fatal(err)
	}
	rs.S.Sub(elliptic.P256().Params().N, rs.S)
	twin := *c
	twin.Signature = &ssh.Signature{Format: c.Signature.Format, Blob: ssh.Marshal(rs)}
	parsed, err := ssh.ParsePublicKey(twin.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	got, err := CheckCertificate(b.id, parsed, now)
	if err != nil {
		t.Fatalf("the twin of an ECDSA certificate is refused, which no check here promises: %v", err)
	}
	if bytes.Equal(got.Marshal(), cert.Marshal()) || got.Serial() != cert.Serial() {
		t.Error("the twin is not a second set of bytes for the same certificate")
	}

	// r written with zero bytes before it: taken to 2,049 bytes in all, the
	// most OpenSSH's sshbuf_get_bignum2 reads, and refused at one more, as
	// every OpenSSH build refuses it.
	var raw struct{ R, S []byte }
	if err := ssh.Unmarshal(c.Signature.Blob, &raw); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{maxMPInt, maxMPInt + 1} {
		long := *c
		r := append(make([]byte, n-len(raw.R)), raw.R...)
		long.Signature = &ssh.Signature{Format: c.Signature.Format, Blob: ssh.Marshal(struct{ R, S []byte }{r, raw.S})}
		parsed, err := ssh.ParsePublicKey(long.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		_, err = CheckCertificate(b.id, parsed, now)
		if n == maxMPInt && err != nil {
			t.Errorf("r in %d bytes, which OpenSSH reads, is refused: %v", n, err)
		}
		if n > maxMPInt && !errors.Is(err, ErrCertificate) {
			t.Errorf("r in %d bytes, which OpenSSH refuses, is taken: %v", n, err)
		}
	}
}
