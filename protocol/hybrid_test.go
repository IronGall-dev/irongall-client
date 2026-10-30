package protocol

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hybridSigner is a new ssh-mldsa44-ed25519 key.
func hybridSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ssh.GenerateCompositeKey(ssh.KeyAlgoMLDSA44Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// hybridMailbox is a mailbox whose identity and working key are
// ssh-mldsa44-ed25519 keys.
func hybridMailbox(t *testing.T) certMailbox {
	t.Helper()
	identity := hybridSigner(t)
	id, err := IdentityOf(identity.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return certMailbox{id: id, identity: identity, work: hybridSigner(t)}
}

// An ssh-mldsa44-ed25519 identity certifies working keys of its own type and
// no other, and what they sign verifies under it alone, within its type's
// bound: a prekey statement, a message and a pass (PROTOCOL.md §4.1, §5, §8).
func TestAnMLDSA44Ed25519IdentityCertifies(t *testing.T) {
	b, other := hybridMailbox(t), hybridMailbox(t)
	if b.id.Type() != IdentityMLDSA44Ed25519 || len(b.id.Document()) != 1859 {
		t.Fatalf("a %s document of %d bytes", b.id.Type(), len(b.id.Document()))
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 3, now)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cert.Signer(b.work)
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{PrekeyNamespace(b.id.Address()), MessageNamespace(other.id.Address())} {
		msg := []byte("a statement\n")
		sig, err := Sign(signer, msg, ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) > SignatureBound(IdentityMLDSA44Ed25519) {
			t.Errorf("a signature of %d bytes, over its type's bound", len(sig))
		}
		t.Logf("%s: %d bytes", ns[:len(ns)-AddressLen], len(sig))
		if got, err := VerifyCertified(b.id, msg, sig, ns, now); err != nil || got.Serial() != 3 {
			t.Fatalf("a signature under its certificate: %v", err)
		}
		if _, err := VerifyCertified(other.id, msg, sig, ns, now); !errors.Is(err, ErrCertificate) {
			t.Errorf("it verified for another identity of the type: %v", err)
		}
	}

	auth, _, err := NewPass(signer, b.id.Address(), "dromas.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) > MaxPassAuthorization {
		t.Errorf("a pass of %d bytes, over MaxPassAuthorization", len(auth))
	}
	t.Logf("pass: %d bytes", len(auth))
	p, err := ParsePass(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(b.id, "dromas.test", now); err != nil {
		t.Errorf("its pass: %v", err)
	}

	// The working key is of the identity's type, whatever the other's.
	ed := newCertMailbox(t)
	if _, err := NewCertificate(b.id, b.identity, ed.work.PublicKey(), 4, now); err == nil {
		t.Error("an Ed25519 key was certified as the working key of an ssh-mldsa44-ed25519 identity")
	}
	if _, err := NewCertificate(ed.id, ed.identity, b.work.PublicKey(), 4, now); err == nil {
		t.Error("an ssh-mldsa44-ed25519 key was certified as the working key of an Ed25519 identity")
	}
	if _, err := NewCertificate(b.id, b.identity, b.identity.PublicKey(), 4, now); err == nil {
		t.Error("the identity key was certified as its own working key")
	}
}

// The Ed25519 half of an ssh-mldsa44-ed25519 key is held to Ed25519's
// checks: one of small order is a bad key.
func TestAnMLDSA44Ed25519KeyWithASmallOrderHalfIsRefused(t *testing.T) {
	wire := hybridSigner(t).PublicKey().Marshal()
	half := wire[len(wire)-32:]
	copy(half, append([]byte{1}, make([]byte, 31)...))
	if _, err := ParseIdentity(docOf(IdentityMLDSA44Ed25519, wire)); !errors.Is(err, ErrIdentityKey) {
		t.Errorf("a key whose Ed25519 half is of small order: %v", err)
	}
}
