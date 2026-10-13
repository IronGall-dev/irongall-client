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

// A list of revoked certificates is the identity's own signature over an
// exact text: the vectors hold the two that are lists and every way one can
// fail to be.
func TestVectorRevokedCertificates(t *testing.T) {
	a := vectorIdentity(t, "a")
	doc := read(t, "a/identity.doc")
	one, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-one-range.txt"), read(t, "revoked/ok-one-range.sig"))
	if err != nil || one.Version != 1 || !one.Revokes(1) || !one.Revokes(4) || one.Revokes(5) {
		t.Fatalf("revoked/ok-one-range: %+v, %v", one, err)
	}
	if _, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-one-range.txt"), read(t, "revoked/ok-one-range.sha256.sig")); err != nil {
		t.Errorf("revoked/ok-one-range.sha256.sig: %v", err)
	}
	many, err := VerifyRevokedCertificates(a.Address(), doc, read(t, "revoked/ok-serials-and-ranges.txt"), read(t, "revoked/ok-serials-and-ranges.sig"))
	if err != nil || many.Version != 7 || len(many.Ranges) != 4 {
		t.Fatalf("revoked/ok-serials-and-ranges: %+v, %v", many, err)
	}
	for serial, want := range map[uint64]bool{1: false, 2: true, 3: false, 5: true, 9: true, 10: false, 11: true, 12: false, MaxSerial: true} {
		if many.Revokes(serial) != want {
			t.Errorf("revoked/ok-serials-and-ranges: Revokes(%d) = %v", serial, !want)
		}
	}
	// What this code builds and signs is what ssh-keygen signed.
	signer, _ := vectorKey(t, "a")
	built, err := NewRevokedCertificates(a.Address(), 7, []SerialRange{{11, 11}, {5, 9}, {MaxSerial, MaxSerial}, {2, 2}})
	if err != nil || !bytes.Equal(built.Statement(), read(t, "revoked/ok-serials-and-ranges.txt")) {
		t.Fatalf("NewRevokedCertificates differs from the vector: %v\n%s", err, built.Statement())
	}
	if sig, err := SignRevokedCertificates(signer, built); err != nil || !bytes.Equal(sig, read(t, "revoked/ok-serials-and-ranges.sig")) {
		t.Errorf("SignRevokedCertificates differs from ssh-keygen's: %v", err)
	}

	bad := glob(t, "revoked/bad-*.txt")
	if len(bad) != 20 {
		t.Fatalf("%d revoked/bad-* vectors, want 20", len(bad))
	}
	for _, f := range bad {
		name := "revoked/" + strings.TrimSuffix(filepath.Base(f), ".txt")
		if _, err := VerifyRevokedCertificates(a.Address(), doc, read(t, name+".txt"), read(t, name+".sig")); !errors.Is(err, ErrRevokedCertificates) {
			t.Errorf("%s: taken as a list of A's revoked certificates: %v", name, err)
		}
	}
	// Controls: the working key's signature is good under A's certificate,
	// and each malformed list carries a good signature of A's identity, so
	// it is the rule and the form that refuse them.
	if _, err := VerifyCertified(a, read(t, "revoked/bad-by-a-working-key.txt"), read(t, "revoked/bad-by-a-working-key.sig"), RevokedCertsNamespace(a.Address()), vectorNow(t)); err != nil {
		t.Errorf("revoked/bad-by-a-working-key.sig is not a good signature under A's certificate, so it tests nothing: %v", err)
	}
	for _, name := range []string{"bad-overlap", "bad-crlf", "bad-no-serials", "bad-another-address", "bad-version-zero", "bad-no-final-newline", "bad-nul"} {
		if err := Verify(a, read(t, "revoked/"+name+".txt"), read(t, "revoked/"+name+".sig"), RevokedCertsNamespace(a.Address())); err != nil {
			t.Errorf("revoked/%s.sig is not A's signature over it, so the vector tests nothing: %v", name, err)
		}
	}
	// B's address with A's list, and A's list with B's document.
	b := vectorIdentity(t, "b")
	if _, err := VerifyRevokedCertificates(b.Address(), doc, read(t, "revoked/ok-one-range.txt"), read(t, "revoked/ok-one-range.sig")); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("A's list, for B's address: %v", err)
	}
	if _, err := VerifyRevokedCertificates(a.Address(), read(t, "b/identity.doc"), read(t, "revoked/ok-one-range.txt"), read(t, "revoked/ok-one-range.sig")); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("A's list, with B's document: %v", err)
	}
}

// A list is built in its one form whatever order and overlap it is given,
// and what is built parses back to itself.
func TestRevokedCertificatesAreBuiltInOneForm(t *testing.T) {
	a := vectorIdentity(t, "a").Address()
	r, err := NewRevokedCertificates(a, 3, []SerialRange{{7, 9}, {1, 4}, {5, 5}, {8, 12}, {20, 20}})
	if err != nil {
		t.Fatal(err)
	}
	want := RevokedCertsTag + "\n" + a.String() + "\n3\n1-5\n7-12\n20\n"
	if string(r.Statement()) != want {
		t.Fatalf("built:\n%s\nwant:\n%s", r.Statement(), want)
	}
	back, err := ParseRevokedCertificates(r.Statement())
	if err != nil || !bytes.Equal(back.Statement(), r.Statement()) {
		t.Fatalf("what was built does not parse back to itself: %v", err)
	}
	for name, bad := range map[string]struct {
		version uint64
		ranges  []SerialRange
	}{
		"version 0":          {0, []SerialRange{{1, 1}}},
		"a version too high": {MaxSerial + 1, []SerialRange{{1, 1}}},
		"no serial":          {1, nil},
		"serial 0":           {1, []SerialRange{{0, 3}}},
		"a range backwards":  {1, []SerialRange{{4, 1}}},
		"a serial too high":  {1, []SerialRange{{1, MaxSerial + 1}}},
	} {
		if _, err := NewRevokedCertificates(a, bad.version, bad.ranges); !errors.Is(err, ErrRevokedCertificates) {
			t.Errorf("%s: built: %v", name, err)
		}
	}
}

// An identity of the optional key type signs its list as it signs its
// revocation, and a list is as bound to its address under one as under
// Ed25519.
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
	list, err := NewRevokedCertificates(id.Address(), 1, []SerialRange{{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignRevokedCertificates(signer, list)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyRevokedCertificates(id.Address(), id.Document(), list.Statement(), sig); err != nil || !got.Revokes(2) {
		t.Fatalf("a P-256 identity's list: %v", err)
	}
	a := vectorIdentity(t, "a")
	if _, err := VerifyRevokedCertificates(a.Address(), read(t, "a/identity.doc"), list.Statement(), sig); !errors.Is(err, ErrRevokedCertificates) {
		t.Errorf("another identity's list, taken for A: %v", err)
	}
}
