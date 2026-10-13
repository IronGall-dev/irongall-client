package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
)

// A revocation is the identity's own signature over fixed text, so anyone
// holding the address can check one, and it is the same bytes whenever it is
// made.
func TestVectorRevocation(t *testing.T) {
	a := vectorIdentity(t, "a")
	doc := read(t, "a/identity.doc")
	for _, sig := range []string{"a/revoke.sig", "a/revoke.sha256.sig"} {
		id, err := VerifyRevocation(a.Address(), doc, read(t, sig))
		if err != nil || id.Address() != a.Address() {
			t.Errorf("%s: %v", sig, err)
		}
	}
	signer, _ := vectorKey(t, "a")
	got, err := SignRevocation(signer, a.Address())
	if err != nil || !bytes.Equal(got, read(t, "a/revoke.sig")) {
		t.Errorf("SignRevocation differs from a/revoke.sig: %v\n%s", err, got)
	}

	// Box C's identity is a P-256 key: its revocation is checked the same way.
	c := vectorIdentity(t, "c")
	if !bytes.Equal(RevocationStatement(c.Address()), read(t, "c/revoke.txt")) {
		t.Error("RevocationStatement differs from c/revoke.txt")
	}
	if _, err := VerifyRevocation(c.Address(), read(t, "c/identity.doc"), read(t, "c/revoke.sig")); err != nil {
		t.Errorf("c/revoke.sig: %v", err)
	}
}

// What is not a revocation of box A. Each signature here is a good signature
// of something: none is the identity's own over A's statement.
func TestVectorBadRevocations(t *testing.T) {
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	docA, docB := read(t, "a/identity.doc"), read(t, "b/identity.doc")
	names := glob(t, "revoke/bad-*.sig")
	if len(names) != 4 {
		t.Fatalf("%d revoke/bad-* vectors, want 4", len(names))
	}
	for _, f := range names {
		name := "revoke/" + filepath.Base(f)
		if _, err := VerifyRevocation(a.Address(), docA, read(t, name)); !errors.Is(err, ErrRevocation) {
			t.Errorf("%s: taken as a revocation of A: %v", name, err)
		}
	}
	// The working key's signature is good under its certificate, which is why
	// it has to be refused by rule and not by luck.
	if _, err := VerifyCertified(a, read(t, "a/revoke.txt"), read(t, "revoke/bad-by-a-working-key.sig"), RevokeNamespace(a.Address()), vectorNow(t)); err != nil {
		t.Errorf("revoke/bad-by-a-working-key.sig is not a good signature under A's certificate, so it tests nothing: %v", err)
	}

	for _, c := range []struct {
		name     string
		addr     Address
		doc, sig []byte
	}{
		{"A's revocation, for B's address", b.Address(), docA, read(t, "a/revoke.sig")},
		{"A's revocation, with B's document", a.Address(), docB, read(t, "a/revoke.sig")},
		{"A's signature over B's revocation, as B's", b.Address(), docB, read(t, "revoke/bad-of-another-box.sig")},
		{"A's signature over B's revocation, with A's document", b.Address(), docA, read(t, "revoke/bad-of-another-box.sig")},
		{"a document with a byte added", a.Address(), append(bytes.Clone(docA), '\n'), read(t, "a/revoke.sig")},
		{"no signature", a.Address(), docA, nil},
		{"no document", a.Address(), nil, read(t, "a/revoke.sig")},
		{"a prekey statement's signature", a.Address(), docA, read(t, "a/prekey-1.txt.sig")},
	} {
		if _, err := VerifyRevocation(c.addr, c.doc, c.sig); !errors.Is(err, ErrRevocation) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// An identity of a key type this build does not verify says so: nothing
	// it signed can be checked here.
	other := read(t, "identity/unsupported-type.doc")
	if _, err := VerifyRevocation(Address(sha256.Sum256(other)), other, read(t, "a/revoke.sig")); !errors.Is(err, ErrIdentityType) {
		t.Errorf("a document of another key type: %v", err)
	}
}
