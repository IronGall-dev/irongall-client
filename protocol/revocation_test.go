package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
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

// Revocations in forms every OpenSSH build reads the same way (PROTOCOL.md
// §3): A's with one NUL ending its key's type, and C's, by a P-256 identity,
// with one ending its curve and with r at the 2,049 bytes OpenSSH reads, all
// taken; and C's with r a byte longer, refused.
func TestVectorRevocationForms(t *testing.T) {
	a, c := vectorIdentity(t, "a"), vectorIdentity(t, "c")
	docA, docC := read(t, "a/identity.doc"), read(t, "c/identity.doc")
	oks, cs := glob(t, "revoke/ok-*.sig"), glob(t, "revoke/c-*.sig")
	if len(oks) == 0 || len(cs) < 2 {
		t.Fatalf("%d revoke/ok-* and %d revoke/c-* vectors", len(oks), len(cs))
	}
	for _, f := range oks {
		if _, err := VerifyRevocation(a.Address(), docA, read(t, "revoke/"+filepath.Base(f))); err != nil {
			t.Errorf("revoke/%s: %v", filepath.Base(f), err)
		}
	}
	for _, f := range cs {
		name := filepath.Base(f)
		_, err := VerifyRevocation(c.Address(), docC, read(t, "revoke/"+name))
		if ok := strings.HasPrefix(name, "c-ok-"); ok != (err == nil) {
			t.Errorf("revoke/%s: %v", name, err)
		}
	}
}

// What is not a revocation of box A. Each signature here is a good signature
// of something: none is the identity's own over A's statement.
func TestVectorBadRevocations(t *testing.T) {
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	docA, docB := read(t, "a/identity.doc"), read(t, "b/identity.doc")
	names := glob(t, "revoke/bad-*.sig")
	if len(names) != 5 {
		t.Fatalf("%d revoke/bad-* vectors, want 5", len(names))
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

// A revocation record names its own type, first, whoever writes it; a reader
// takes one without it, as the route says what the body is, and refuses one
// that names any other type, an empty one or one of another JSON type
// included, as a request with its member named (PROTOCOL.md §6.3).
func TestARecordNamesItsType(t *testing.T) {
	b, err := json.Marshal(Revocations{Identity: Bytes("doc"), Revocation: Bytes("sig")})
	if err != nil || string(b) != `{"type":"revocation_record","identity":"ZG9j","revocation":"c2ln"}` {
		t.Fatalf("written as %s, %v", b, err)
	}
	other := "revocation"
	if b, _ := json.Marshal(&Revocations{Type: &other, Identity: Bytes("doc")}); !strings.HasPrefix(string(b), `{"type":"revocation_record",`) {
		t.Fatalf("a record written with another type in hand: %s", b)
	}
	for body, want := range map[string]error{
		`{"type":"revocation_record","identity":"ZG9j","revocation":"c2ln"}`: nil,
		`{"identity":"ZG9j","revocation":"c2ln"}`:                            nil,
		`{"type":null,"identity":"ZG9j","revocation":"c2ln"}`:                nil,
		`{"type":"revocation","identity":"ZG9j","revocation":"c2ln"}`:        ErrMemberValue,
		`{"type":"","identity":"ZG9j","revocation":"c2ln"}`:                  ErrMemberValue,
		`{"type":"Revocation_Record","identity":"ZG9j"}`:                     ErrMemberValue,
		`{"type":1,"identity":"ZG9j","revocation":"c2ln"}`:                   ErrJSON,
	} {
		for _, read := range []func([]byte, any) error{Unmarshal, UnmarshalRequest} {
			var rec Revocations
			if err := read([]byte(body), &rec); !errors.Is(err, want) || (want == nil) != (err == nil) {
				t.Errorf("%s: %v, want %v", body, err, want)
			} else if want == ErrMemberValue && Member(err) != "type" {
				t.Errorf("%s: the error names %q, not the member type", body, Member(err))
			}
		}
	}
}
