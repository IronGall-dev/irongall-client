package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A revocation of certificates is the identity's own signature over an exact
// text: the vectors hold the two that are revocations and every way one can
// fail to be.
func TestVectorRevokedCertificates(t *testing.T) {
	a := vectorIdentity(t, "a")
	doc := read(t, "a/identity.doc")
	four, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-through-4.txt"), read(t, "revoked/ok-through-4.sig"))
	if err != nil || four.Through != 4 || !four.Revokes(1) || !four.Revokes(4) || four.Revokes(5) {
		t.Fatalf("revoked/ok-through-4: %+v, %v", four, err)
	}
	if _, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-through-4.txt"), read(t, "revoked/ok-through-4.sha256.sig")); err != nil {
		t.Errorf("revoked/ok-through-4.sha256.sig: %v", err)
	}
	top, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-through-the-highest.txt"), read(t, "revoked/ok-through-the-highest.sig"))
	if err != nil || top.Through != MaxSerial || !top.Revokes(MaxSerial) {
		t.Fatalf("revoked/ok-through-the-highest: %+v, %v", top, err)
	}
	// What this code builds and signs is what ssh-keygen signed.
	signer, _ := vectorKey(t, "a")
	built, err := NewRevokedCertificates(a.Address(), 4)
	if err != nil || !bytes.Equal(built.Statement(), read(t, "revoked/ok-through-4.txt")) {
		t.Fatalf("NewRevokedCertificates differs from the vector: %v\n%s", err, built.Statement())
	}
	if sig, err := SignRevokedCertificates(signer, built); err != nil || !bytes.Equal(sig, read(t, "revoked/ok-through-4.sig")) {
		t.Errorf("SignRevokedCertificates differs from ssh-keygen's: %v", err)
	}

	bad := glob(t, "revoked/bad-*.txt")
	if len(bad) != 20 {
		t.Fatalf("%d revoked/bad-* vectors, want 20", len(bad))
	}
	for _, f := range bad {
		name := "revoked/" + strings.TrimSuffix(filepath.Base(f), ".txt")
		if _, err := VerifyRevokedCertificates(a.Address(), doc, read(t, name+".txt"), read(t, name+".sig")); !errors.Is(err, ErrRevokedCertificates) {
			t.Errorf("%s: taken as a revocation of A's certificates: %v", name, err)
		}
	}
	// Controls: the working key's signature is good under A's certificate,
	// and each malformed one carries a good signature of A's identity, so it
	// is the rule and the form that refuse them.
	if s, err := VerifySigned(a, read(t, "revoked/bad-by-a-working-key.txt"), read(t, "revoked/bad-by-a-working-key.sig"), RevokedCertsNamespace(a.Address()), vectorNow(t)); err != nil || s.Identity() {
		t.Errorf("revoked/bad-by-a-working-key.sig is not a good signature under A's certificate, so it tests nothing: %v", err)
	}
	for _, name := range []string{"bad-a-list", "bad-a-second-serial", "bad-crlf", "bad-no-serial", "bad-another-address", "bad-serial-zero", "bad-no-final-newline", "bad-nul"} {
		if err := Verify(a, read(t, "revoked/"+name+".txt"), read(t, "revoked/"+name+".sig"), RevokedCertsNamespace(a.Address())); err != nil {
			t.Errorf("revoked/%s.sig is not A's signature over it, so the vector tests nothing: %v", name, err)
		}
	}
	// B's address with A's revocation, and A's revocation with B's document.
	b := vectorIdentity(t, "b")
	if _, err := VerifyRevokedCertificates(b.Address(), doc, read(t, "revoked/ok-through-4.txt"), read(t, "revoked/ok-through-4.sig")); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("A's revocation, for B's address: %v", err)
	}
	if _, err := VerifyRevokedCertificates(a.Address(), read(t, "b/identity.doc"), read(t, "revoked/ok-through-4.txt"), read(t, "revoked/ok-through-4.sig")); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("A's revocation, with B's document: %v", err)
	}
}

// A revocation runs through a serial a certificate may have, and what is
// built parses back to itself.
func TestRevokedCertificatesAreBuiltInOneForm(t *testing.T) {
	a := vectorIdentity(t, "a").Address()
	r, err := NewRevokedCertificates(a, 1792085999)
	if err != nil {
		t.Fatal(err)
	}
	want := RevokedCertsTag + "\n" + a.String() + "\n1792085999\n"
	if string(r.Statement()) != want {
		t.Fatalf("built:\n%s\nwant:\n%s", r.Statement(), want)
	}
	back, err := ParseRevokedCertificates(r.Statement())
	if err != nil || *back != *r {
		t.Fatalf("what was built does not parse back to itself: %+v, %v", back, err)
	}
	for _, through := range []uint64{0, MaxSerial + 1} {
		if _, err := NewRevokedCertificates(a, through); !errors.Is(err, ErrRevokedCertificates) {
			t.Errorf("through %d: built: %v", through, err)
		}
	}
}

// An identity of the optional key type signs a revocation of its
// certificates as it signs one of its address, and the revocation is as
// bound to its address under one as under Ed25519.
func TestAP256IdentityRevokesCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityOf(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRevokedCertificates(id.Address(), 2)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignRevokedCertificates(signer, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyRevokedCertificates(id.Address(), id.Document(), r.Statement(), sig); err != nil || !got.Revokes(2) || got.Revokes(3) {
		t.Fatalf("a P-256 identity's revocation: %+v, %v", got, err)
	}
	a := vectorIdentity(t, "a")
	if _, err := VerifyRevokedCertificates(a.Address(), read(t, "a/identity.doc"), r.Statement(), sig); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("another identity's revocation, taken for A: %v", err)
	}
}
