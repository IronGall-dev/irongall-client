package protocol

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
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

func TestVectorBadIdentities(t *testing.T) {
	for _, f := range glob(t, "identity/*.doc") {
		doc, _ := os.ReadFile(f)
		name := filepath.Base(f)
		_, err := ParseIdentity(doc)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// A server answers a format error with identity_mismatch and a key
		// error with bad_key.
		keyCase := strings.HasPrefix(name, "small-order") || name == "non-canonical.doc" || name == "negative-zero.doc"
		if want := map[bool]error{true: ErrIdentityKey, false: ErrIdentityFormat}[keyCase]; !errors.Is(err, want) {
			t.Errorf("%s: %v, want it to wrap %v", name, err, want)
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
		p, err := VerifyPrekey(c.id, read(t, c.file), read(t, c.sig))
		if err != nil {
			t.Errorf("%s: %v", c.sig, err)
			continue
		}
		if p.Serial != c.serial || p.Type() != c.typ || p.Expired(now) || p.CheckLifetime(now) != nil {
			t.Errorf("%s: serial %d type %s expired %v lifetime %v", c.file, p.Serial, p.Type(), p.Expired(now), p.CheckLifetime(now))
		}
		if !bytes.Equal(p.Statement(), read(t, c.file)) {
			t.Errorf("%s: Statement does not reproduce the file", c.file)
		}
		if _, err := p.Recipient(); err != nil {
			t.Errorf("%s: %v", c.file, err)
		}
	}
	if _, err := VerifyPrekey(b, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig")); err == nil {
		t.Error("B accepted A's prekey")
	}
}

func TestVectorBadPrekeys(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	for _, f := range glob(t, "prekey/*.txt") {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		st, _ := os.ReadFile(f)
		sig, _ := os.ReadFile(f + ".sig")
		p, err := VerifyPrekey(a, st, sig)
		switch {
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			// Control: apart from the signature cases, the signature is
			// good, so the format check is what refused it.
			if name != "bad-wrong-namespace" && name != "bad-signed-by-b" {
				if err := Verify(a, st, sig, PrekeyNamespace(a.Address())); err != nil {
					t.Errorf("%s: control: the signature itself fails: %v", name, err)
				}
			}
		case name == "expired":
			if err != nil || !p.Expired(now) || p.CheckLifetime(now) == nil {
				t.Errorf("%s: want valid and expired: %v", name, err)
			}
		case name == "too-long":
			if err != nil || p.Expired(now) || p.CheckLifetime(now) == nil {
				t.Errorf("%s: want valid, not expired, and refused for publishing: %v", name, err)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// TestVectorSignatures checks Go's signatures are byte-identical to the
// ssh-keygen ones in the vectors: Ed25519 is deterministic.
func TestVectorSignatures(t *testing.T) {
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	sa, _ := vectorKey(t, "a")
	sb, _ := vectorKey(t, "b")
	for _, c := range []struct {
		signer ssh.Signer
		id     *Identity
		msg    string
		sig    string
		ns     string
	}{
		{sa, a, "a/prekey-1.txt", "a/prekey-1.txt.sig", PrekeyNamespace(a.Address())},
		{sa, a, "a/prekey-2.txt", "a/prekey-2.txt.sig", PrekeyNamespace(a.Address())},
		{sb, b, "b/prekey-1.txt", "b/prekey-1.txt.sig", PrekeyNamespace(b.Address())},
		{sa, a, "a/revoke.txt", "a/revoke.sig", RevokeNamespace(a.Address())},
		{sa, a, "message/a-to-b.age", "message/a-to-b.age.sig", MessageNamespace(b.Address())},
	} {
		got, err := Sign(c.signer, read(t, c.msg), c.ns)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, read(t, c.sig)) {
			t.Errorf("%s: Go's signature differs from ssh-keygen's:\n%s", c.sig, got)
		}
		if err := Verify(c.id, read(t, c.msg), read(t, c.sig), c.ns); err != nil {
			t.Errorf("%s: %v", c.sig, err)
		}
	}
	if !bytes.Equal(RevocationStatement(a.Address()), read(t, "a/revoke.txt")) {
		t.Error("RevocationStatement differs from a/revoke.txt")
	}
}

func TestVectorMessage(t *testing.T) {
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	m := read(t, "message/a-to-b.age")
	if err := Verify(a, m, read(t, "message/a-to-b.age.sig"), MessageNamespace(b.Address())); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := Verify(a, m, read(t, "message/a-to-b.age.for-another-box.sig"), MessageNamespace(b.Address())); err == nil {
		t.Error("a signature for another box verified for B")
	}
	if err := Verify(b, m, read(t, "message/a-to-b.age.sig"), MessageNamespace(b.Address())); err == nil {
		t.Error("A's signature verified as B's")
	}
	if !bytes.HasPrefix(m, []byte("age-encryption.org/v1\n-> mlkem768x25519 ")) {
		t.Error("the message is not a post-quantum age file")
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
