package sshsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const ns = "irongall-msg-v1:test"

// rfc8032Seed is the secret key of RFC 8032 §7.1 TEST 1: a published test key.
var rfc8032Seed = []byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
}

type keyCase struct {
	name   string
	signer ssh.Signer
	raw    any // the crypto private key, for writing an OpenSSH key file
}

func keys(t testing.TB) []keyCase {
	t.Helper()
	var cs []keyCase
	add := func(name string, k any) {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, keyCase{name, s, k})
	}
	add("ed25519", ed25519.NewKeyFromSeed(rfc8032Seed))
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		add("ecdsa-"+c.Params().Name, k)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	add("rsa", k)
	return cs
}

func TestRoundTrip(t *testing.T) {
	msg := []byte("hello, irongall\n")
	for _, k := range keys(t) {
		t.Run(k.name, func(t *testing.T) {
			sig, err := Sign(k.signer, rand.Reader, msg, ns)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(k.signer.PublicKey(), msg, sig, ns); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if err := Verify(k.signer.PublicKey(), []byte("hello, irongall!"), sig, ns); err == nil {
				t.Error("verified a different message")
			}
			if err := Verify(k.signer.PublicKey(), msg, sig, ns+"x"); err == nil {
				t.Error("verified under a different namespace")
			}
		})
	}
}

func TestRSAAlgorithms(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("m")
	for algo, want := range map[string]bool{ssh.KeyAlgoRSASHA256: true, ssh.KeyAlgoRSASHA512: true, ssh.KeyAlgoRSA: false} {
		ms, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{algo})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(ms, rand.Reader, msg, ns)
		if (err == nil) != want {
			t.Fatalf("%s: Sign error = %v, want success %v", algo, err, want)
		}
		if !want {
			continue
		}
		if f := sigFormat(t, sig); f != algo {
			t.Errorf("signed with %s, want %s", f, algo)
		}
		if err := Verify(s.PublicKey(), msg, sig, ns); err != nil {
			t.Errorf("%s: %v", algo, err)
		}
	}
	// A MultiAlgorithmSigner gets its first algorithm; x/crypto's own RSA
	// signer lists rsa-sha2-256 first.
	sig, err := Sign(s, rand.Reader, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	if f, want := sigFormat(t, sig), s.(ssh.MultiAlgorithmSigner).Algorithms()[0]; f != want {
		t.Errorf("RSA algorithm %s, want the signer's first, %s", f, want)
	}
	// An AlgorithmSigner that is not a MultiAlgorithmSigner gets rsa-sha2-512.
	sig, err = Sign(algorithmOnly{s.(ssh.AlgorithmSigner)}, rand.Reader, msg, ns)
	if err != nil {
		t.Fatal(err)
	}
	if f := sigFormat(t, sig); f != ssh.KeyAlgoRSASHA512 {
		t.Errorf("default RSA algorithm %s, want rsa-sha2-512", f)
	}
	// An RSA signer that cannot choose its algorithm is refused.
	if _, err := Sign(plainSigner{s}, rand.Reader, msg, ns); err == nil {
		t.Error("signed with an RSA signer that is not an AlgorithmSigner")
	}
}

type algorithmOnly struct{ ssh.AlgorithmSigner }

type plainSigner struct{ s ssh.Signer }

func (p plainSigner) PublicKey() ssh.PublicKey { return p.s.PublicKey() }
func (p plainSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return p.s.Sign(r, data)
}

// TestRejectsSSHRSA builds an otherwise valid SHA-1 "ssh-rsa" signature, which
// x/crypto's RSA key would verify, and checks Verify refuses it.
func TestRejectsSSHRSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(k)
	msg := []byte("m")
	h := sha512Sum(msg)
	sig, err := s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, signedData(ns, "", "sha512", h), ssh.KeyAlgoRSA)
	if err != nil {
		t.Fatal(err)
	}
	blob := build(s.PublicKey().Marshal(), ns, "", "sha512", ssh.Marshal(sig), 1)
	if err := s.PublicKey().Verify(signedData(ns, "", "sha512", h), sig); err != nil {
		t.Fatalf("control: x/crypto should accept the ssh-rsa signature itself: %v", err)
	}
	if err := Verify(s.PublicKey(), msg, blob, ns); err == nil {
		t.Fatal("accepted an ssh-rsa (SHA-1) signature")
	}
}

func TestRejects(t *testing.T) {
	s, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(rfc8032Seed))
	other, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	msg := []byte("m")
	h := sha512Sum(msg)
	sign := func(namespace, reserved, alg string, hash []byte) []byte {
		sig, err := s.Sign(rand.Reader, signedData(namespace, reserved, alg, hash))
		if err != nil {
			t.Fatal(err)
		}
		return ssh.Marshal(sig)
	}
	good := sign(ns, "", "sha512", h)
	pk := s.PublicKey().Marshal()

	valid := build(pk, ns, "", "sha512", good, 1)
	if err := Verify(s.PublicKey(), msg, valid, ns); err != nil {
		t.Fatalf("control: %v", err)
	}

	sigWithJunk := ssh.Marshal(struct {
		Format string
		Blob   []byte
		Rest   []byte `ssh:"rest"`
	}{"ssh-ed25519", parseSig(t, good).Blob, []byte{0}})

	cases := map[string]struct {
		pub  ssh.PublicKey
		blob []byte
		ns   string
	}{
		"other key":                  {other.PublicKey(), valid, ns},
		"empty namespace":            {s.PublicKey(), build(pk, "", "", "sha512", sign("", "", "sha512", h), 1), ""},
		"version 2":                  {s.PublicKey(), build(pk, ns, "", "sha512", good, 2), ns},
		"version 0":                  {s.PublicKey(), build(pk, ns, "", "sha512", good, 0), ns},
		"trailing byte":              {s.PublicKey(), append(append([]byte{}, valid...), 0), ns},
		"truncated":                  {s.PublicKey(), valid[:len(valid)-1], ns},
		"bad magic":                  {s.PublicKey(), append([]byte("SSHSIH"), valid[6:]...), ns},
		"hash md5":                   {s.PublicKey(), build(pk, ns, "", "md5", sign(ns, "", "md5", h), 1), ns},
		"hash label swapped":         {s.PublicKey(), build(pk, ns, "", "sha256", good, 1), ns},
		"key swapped in blob":        {s.PublicKey(), build(other.PublicKey().Marshal(), ns, "", "sha512", good, 1), ns},
		"trailing data in signature": {s.PublicKey(), build(pk, ns, "", "sha512", sigWithJunk, 1), ns},
		"signed over a reserved one": {s.PublicKey(), build(pk, ns, "tag", "sha512", sign(ns, "tag", "sha512", h), 1), ns},
		"empty":                      {s.PublicKey(), nil, ns},
	}
	for name, c := range cases {
		if err := Verify(c.pub, msg, c.blob, c.ns); err == nil {
			t.Errorf("%s: verified", name)
		}
	}

	// A non-empty reserved field is ignored, as the specification says and as
	// OpenSSH does it: the key signed an empty one (TestReservedAsSSHKeygen).
	if err := Verify(s.PublicKey(), msg, build(pk, ns, "tag", "sha512", good, 1), ns); err != nil {
		t.Errorf("non-empty reserved: %v", err)
	}
	// sha256 is accepted.
	h256 := sha256Sum(msg)
	if err := Verify(s.PublicKey(), msg, build(pk, ns, "", "sha256", sign(ns, "", "sha256", h256), 1), ns); err != nil {
		t.Errorf("sha256: %v", err)
	}
}

// The reserved field is read as "ssh-keygen -Y verify" reads it: the blob's is
// skipped, and the data the key signed has an empty one. So a blob whose field
// holds bytes, over a signature of an empty one, verifies, and a signature
// made over a field that is not empty does not, in both verifiers.
func TestReservedAsSSHKeygen(t *testing.T) {
	s, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(rfc8032Seed))
	msg := []byte("irongall sshsig reserved\n")
	h := sha512Sum(msg)
	sign := func(reserved string) []byte {
		sig, err := s.Sign(rand.Reader, signedData(ns, reserved, "sha512", h))
		if err != nil {
			t.Fatal(err)
		}
		return ssh.Marshal(sig)
	}
	pk := s.PublicKey().Marshal()
	cases := []struct {
		name string
		blob []byte
		good bool
	}{
		{"field not empty, signed over an empty one", build(pk, ns, "tag", "sha512", sign(""), 1), true},
		{"signed over the field", build(pk, ns, "tag", "sha512", sign("tag"), 1), false},
	}
	for _, c := range cases {
		if err := Verify(s.PublicKey(), msg, c.blob, ns); (err == nil) != c.good {
			t.Errorf("%s: Verify: %v, want good %v", c.name, err, c.good)
		}
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed: the Go verdicts were checked, not ssh-keygen's")
	}
	dir := t.TempDir()
	signers := filepath.Join(dir, "signers")
	if err := os.WriteFile(signers, []byte("test "+string(ssh.MarshalAuthorizedKey(s.PublicKey()))), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		f := filepath.Join(dir, fmt.Sprintf("%d.sig", i))
		if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: c.blob}), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "test", "-n", ns, "-s", f)
		cmd.Stdin = bytes.NewReader(msg)
		if err := cmd.Run(); (err == nil) != c.good {
			t.Errorf("%s: ssh-keygen -Y verify: %v, want good %v", c.name, err, c.good)
		}
	}
}

func TestSignEmptyNamespace(t *testing.T) {
	s, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(rfc8032Seed))
	if _, err := Sign(s, rand.Reader, []byte("m"), ""); err == nil {
		t.Fatal("signed with an empty namespace")
	}
}

// TestSSHKeygen cross-checks against OpenSSH in both directions, for every key
// type and both hashes. Ed25519 signatures are deterministic, so for that key
// Go's signature must be byte-identical to ssh-keygen's.
func TestSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	msg := []byte("irongall sshsig cross-test\n")
	msgFile := filepath.Join(dir, "msg")
	if err := os.WriteFile(msgFile, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(keygen, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("ssh-keygen %s: %v: %s", strings.Join(args, " "), err, stderr.String())
		}
		return out
	}
	for _, k := range keys(t) {
		t.Run(k.name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKey(k.raw, "")
			if err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(dir, k.name)
			if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
				t.Fatal(err)
			}
			signers := filepath.Join(dir, k.name+".signers")
			line := "test " + string(ssh.MarshalAuthorizedKey(k.signer.PublicKey()))
			if err := os.WriteFile(signers, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}

			// ssh-keygen signs, we verify.
			for _, hashalg := range []string{"sha512", "sha256"} {
				armored := run(msg, "-q", "-Y", "sign", "-n", ns, "-f", keyFile, "-O", "hashalg="+hashalg)
				p, rest := pem.Decode(armored)
				if p == nil || p.Type != "SSH SIGNATURE" || len(rest) != 0 {
					t.Fatalf("unexpected ssh-keygen output %q", armored)
				}
				if err := Verify(k.signer.PublicKey(), msg, p.Bytes, ns); err != nil {
					t.Errorf("%s: Verify of ssh-keygen's signature: %v", hashalg, err)
				}
				if err := Verify(k.signer.PublicKey(), msg, p.Bytes, ns+"x"); err == nil {
					t.Errorf("%s: verified ssh-keygen's signature under another namespace", hashalg)
				}
				if k.name == "ed25519" && hashalg == "sha512" {
					ours, err := Sign(k.signer, rand.Reader, msg, ns)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ours, p.Bytes) {
						t.Error("Ed25519 signature differs from ssh-keygen's")
					}
				}
			}

			// We sign, ssh-keygen verifies.
			ours, err := Sign(k.signer, rand.Reader, msg, ns)
			if err != nil {
				t.Fatal(err)
			}
			sigFile := filepath.Join(dir, k.name+".sig")
			if err := os.WriteFile(sigFile, pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: ours}), 0o600); err != nil {
				t.Fatal(err)
			}
			run(msg, "-Y", "verify", "-f", signers, "-I", "test", "-n", ns, "-s", sigFile)
			cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "test", "-n", ns+"x", "-s", sigFile)
			cmd.Stdin = bytes.NewReader(msg)
			if cmd.Run() == nil {
				t.Error("control: ssh-keygen verified our signature under another namespace")
			}
		})
	}
}

func FuzzVerify(f *testing.F) {
	s, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(rfc8032Seed))
	msg := []byte("m")
	sig, err := Sign(s, rand.Reader, msg, ns)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sig)
	f.Add(sig[:20])
	f.Fuzz(func(t *testing.T, blob []byte) {
		// Ed25519 is deterministic and Go requires canonical R and S, so
		// exactly one blob verifies.
		if Verify(s.PublicKey(), msg, blob, ns) == nil && !bytes.Equal(blob, sig) {
			t.Fatalf("a different blob verified: %x", blob)
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	s, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(rfc8032Seed))
	f.Add([]byte("m"), ns)
	f.Fuzz(func(t *testing.T, msg []byte, namespace string) {
		sig, err := Sign(s, rand.Reader, msg, namespace)
		if namespace == "" {
			if err == nil {
				t.Fatal("signed with an empty namespace")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(s.PublicKey(), msg, sig, namespace); err != nil {
			t.Fatal(err)
		}
		if Verify(s.PublicKey(), append(msg, 0), sig, namespace) == nil {
			t.Fatal("verified a different message")
		}
	})
}

func sha512Sum(m []byte) []byte { h := sha512.Sum512(m); return h[:] }
func sha256Sum(m []byte) []byte { h := sha256.Sum256(m); return h[:] }

func build(pub []byte, namespace, reserved, hashAlg string, sig []byte, version uint32) []byte {
	var b []byte
	b = append(b, magicPreamble...)
	b = binary.BigEndian.AppendUint32(b, version)
	b = appendString(b, pub)
	b = appendString(b, []byte(namespace))
	b = appendString(b, []byte(reserved))
	b = appendString(b, []byte(hashAlg))
	b = appendString(b, sig)
	return b
}

func parseSig(t *testing.T, b []byte) *ssh.Signature {
	t.Helper()
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(b, sig); err != nil {
		t.Fatal(err)
	}
	return sig
}

func sigFormat(t *testing.T, blob []byte) string {
	t.Helper()
	r := reader(blob)
	r.take(10)
	for range 4 {
		r.string()
	}
	s, _ := r.string()
	return parseSig(t, s).Format
}
