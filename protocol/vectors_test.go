package protocol

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/edwards25519"
	"github.com/dromas-dev/dromas-client/sshsig"
	"golang.org/x/crypto/ssh"
)

const vectors = "../testdata/vectors"

func read(t testing.TB, name string) []byte {
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

// vectorKey returns a mailbox's RFC 8032 test key from input/<mailbox>.ed25519.
func vectorKey(t testing.TB, mailbox string) (ssh.Signer, ed25519.PublicKey) {
	t.Helper()
	s := bufio.NewScanner(bytes.NewReader(read(t, "input/"+mailbox+".ed25519")))
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
		t.Fatalf("%s: the seed does not give the public key", mailbox)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, lines[1]
}

func vectorIdentity(t *testing.T, mailbox string) *Identity {
	t.Helper()
	id, err := ParseIdentity(read(t, mailbox+"/identity.doc"))
	if err != nil {
		t.Fatalf("%s: %v", mailbox, err)
	}
	return id
}

// vectorTrip is A's trip: the revocation of its certificates A's identity
// signed, which puts A in working-key mode (PROTOCOL.md §5).
func vectorTrip(t *testing.T) *RevokedCertificates {
	t.Helper()
	a := vectorIdentity(t, "a")
	r, err := VerifyRevokedCertificates(a.Address(), a.Document(), read(t, "a/trip.txt"), read(t, "a/trip.sig"))
	if err != nil {
		t.Fatalf("a/trip: %v", err)
	}
	return r
}

// vectorHeld is the revocation of its certificates a reader holds for a
// vector mailbox, which gives its mode: A's trip for A, which is in
// working-key mode, and none for B and C, which are in identity mode.
func vectorHeld(t *testing.T, id *Identity) *RevokedCertificates {
	t.Helper()
	if id.Address() == vectorIdentity(t, "a").Address() {
		return vectorTrip(t)
	}
	return nil
}

// vectorRank is the serial of A's certificates: its clock at ./now, one above
// its trip.
func vectorRank(t *testing.T) uint64 {
	t.Helper()
	return vectorTrip(t).Through + 1
}

func TestVectorIdentities(t *testing.T) {
	for _, mailbox := range []string{"a", "b"} {
		id := vectorIdentity(t, mailbox)
		if got, want := id.Address().String(), strings.TrimSpace(string(read(t, mailbox+"/address"))); got != want {
			t.Errorf("%s: address %s, want %s", mailbox, got, want)
		}
		_, pub := vectorKey(t, mailbox)
		built, err := NewIdentity(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(built.Document(), read(t, mailbox+"/identity.doc")) {
			t.Errorf("%s: NewIdentity built a different document", mailbox)
		}
	}
}

// Mailbox C's identity is of the optional type, and everything a mailbox says is
// checked under it as under an Ed25519 one.
func TestVectorP256Identity(t *testing.T) {
	now := vectorNow(t)
	c := vectorIdentity(t, "c")
	if c.Type() != IdentityP256 || len(c.Document()) != 171 {
		t.Errorf("c: a %s identity of %d bytes", c.Type(), len(c.Document()))
	}
	if got, want := c.Address().String(), strings.TrimSpace(string(read(t, "c/address"))); got != want {
		t.Errorf("c: address %s, want %s", got, want)
	}
	built, err := IdentityOf(c.PublicKey())
	if err != nil || !bytes.Equal(built.Document(), read(t, "c/identity.doc")) {
		t.Errorf("c: IdentityOf built a different document: %v", err)
	}
	p, signer, err := VerifyPrekey(c, read(t, "c/prekey-1.txt"), read(t, "c/prekey-1.txt.sig"), now)
	if err != nil || p.Serial != 1 || !signer.Identity() || Admits(nil, signer) != nil {
		t.Fatalf("c/prekey-1.txt, signed by C's identity: %v", err)
	}
	// C's statement is not A's, and A's is not C's.
	a := vectorIdentity(t, "a")
	if _, _, err := VerifyPrekey(a, read(t, "c/prekey-1.txt"), read(t, "c/prekey-1.txt.sig"), now); err == nil {
		t.Error("C's statement verified for A")
	}
	if _, err := VerifySigned(c, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), PrekeyNamespace(a.Address()), now); !errors.Is(err, ErrCertificate) {
		t.Errorf("a signature under A's certificate, checked against C's identity: %v", err)
	}
}

func TestVectorBadIdentities(t *testing.T) {
	for _, f := range glob(t, "identity/*.doc") {
		doc, _ := os.ReadFile(f)
		name := filepath.Base(f)
		if strings.HasPrefix(name, "ok-") {
			continue // TestVectorP256Coordinates
		}
		_, err := ParseIdentity(doc)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// A server answers a format error with identity_mismatch, a key
		// error with bad_key, and a well-formed document of a type it does
		// not register with unsupported_key_type.
		keyCase := strings.HasPrefix(name, "small-order") || name == "non-canonical.doc" || name == "negative-zero.doc" || name == "off-curve.doc"
		want := ErrIdentityFormat
		switch {
		case keyCase:
			want = ErrIdentityKey
		case strings.HasPrefix(name, "unsupported-"):
			want = ErrIdentityType
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want it to wrap %v", name, err, want)
		}
		// Control: the key cases are well-formed documents, so the KEY check
		// is what refused them, and edwards25519 itself decodes the point,
		// so the check has to be ours. off-curve.doc is no point, so
		// edwards25519 refuses it, where ssh-keygen reads it as a key.
		if keyCase {
			m := identityForm.FindSubmatch(doc)
			if m == nil {
				t.Errorf("%s: control: not a well-formed document", name)
				continue
			}
			key, err := ssh.ParsePublicKey(mustB64(t, m[2]))
			if err != nil {
				t.Fatal(err)
			}
			raw := key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
			_, err = new(edwards25519.Point).SetBytes(raw)
			switch {
			case name == "off-curve.doc" && err == nil:
				t.Errorf("%s: control: edwards25519 decodes it, so it is a point", name)
			case name != "off-curve.doc" && name != "negative-zero.doc" && err != nil:
				t.Errorf("%s: control: edwards25519 rejects it already: %v", name, err)
			}
		}
	}
}

// A P-256 key is a point on the curve, and nothing more (PROTOCOL.md §4.1): the
// two ok- documents are points with a coordinate that OpenSSH refused up to
// 10.2p1, one of 128 bits or fewer and one of n - 1 or more, and every
// implementation takes each, as OpenSSH from 10.3p1 and the Go library do.
func TestVectorP256Coordinates(t *testing.T) {
	n := elliptic.P256().Params().N
	limit := new(big.Int).Sub(n, big.NewInt(1))
	docs := glob(t, "identity/ok-*.doc")
	if len(docs) != 2 {
		t.Fatalf("%d ok- identity documents, want 2", len(docs))
	}
	bounds := map[string]bool{}
	for _, f := range docs {
		doc, _ := os.ReadFile(f)
		name := filepath.Base(f)
		id, err := ParseIdentity(doc)
		if err != nil || id.Type() != IdentityP256 {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// Control: each still has a coordinate past one of OpenSSH's old
		// bounds, so the vector tests what its name says.
		pub := id.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey)
		for _, c := range []*big.Int{pub.X, pub.Y} {
			bounds["short"] = bounds["short"] || c.BitLen() <= n.BitLen()/2
			bounds["over"] = bounds["over"] || c.Cmp(limit) >= 0
		}
	}
	if !bounds["short"] || !bounds["over"] {
		t.Errorf("control: the ok- documents hold no coordinate past each of OpenSSH's old bounds: %v", bounds)
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

// vectorWorker returns a mailbox's working key as a signer under its kept
// certificate: what "ssh-keygen -Y sign -f work-cert.pub" signs with.
func vectorWorker(t *testing.T, mailbox string) ssh.Signer {
	t.Helper()
	work, _ := vectorKey(t, mailbox+"-work")
	cert, err := CheckCertificate(vectorIdentity(t, mailbox), vectorCertificate(t, mailbox+"/work-cert.pub"), vectorNow(t))
	if err != nil {
		t.Fatalf("%s/work-cert.pub: %v", mailbox, err)
	}
	s, err := cert.Signer(work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A's certificates are numbered above its trip and run as a client makes them
// for a server whose maximum is 45 days and the hour; B's and C's are
// certificates their identities made, good by every rule of their own, which
// no reader takes while their mailboxes are in identity mode.
func TestVectorCertificates(t *testing.T) {
	now := vectorNow(t)
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	for _, v := range []struct {
		id   *Identity
		file string
		mode error
	}{{a, "a/work-cert.pub", nil}, {b, "b/work-cert.pub", ErrIdentityMode}, {c, "c/work-cert.pub", ErrIdentityMode}} {
		cert, err := CheckCertificate(v.id, vectorCertificate(t, v.file), now)
		if err != nil {
			t.Errorf("%s: %v", v.file, err)
			continue
		}
		if cert.Serial() != vectorRank(t) || !cert.NotBefore().Equal(now.Add(-MaxSkew)) || cert.Lifetime() != testLifetime || !cert.SignsMessages(now) {
			t.Errorf("%s: serial %d, from %s for %s", v.file, cert.Serial(), cert.NotBefore(), cert.Lifetime())
		}
		if err := Admits(vectorHeld(t, v.id), &Signer{cert: cert}); !errors.Is(err, v.mode) || (v.mode == nil && err != nil) {
			t.Errorf("%s, in its mailbox's mode: %v, want %v", v.file, err, v.mode)
		}
	}
	if _, err := CheckCertificate(b, vectorCertificate(t, "a/work-cert.pub"), now); !errors.Is(err, ErrCertificate) {
		t.Errorf("B took A's certificate: %v", err)
	}
	trip := vectorTrip(t)
	st := read(t, "a/prekey-1.txt")
	for _, f := range glob(t, "cert/ok-*.pub") {
		name := strings.TrimSuffix(filepath.Base(f), ".pub")
		cert, err := CheckCertificate(a, vectorCertificate(t, "cert/"+name+".pub"), now)
		if err != nil {
			t.Errorf("%s: CheckCertificate: %v", name, err)
			continue
		}
		signer, err := VerifySigned(a, st, read(t, "cert/"+name+".sig"), PrekeyNamespace(a.Address()), now)
		if err != nil || Admits(trip, signer) != nil {
			t.Errorf("%s: VerifySigned: %v, with A's trip held: %v", name, err, Admits(trip, signer))
		}
		// The edges each is at: no ceiling at a reader, and the last date.
		switch name {
		case "ok-longer-than-a-server-takes":
			if cert.Lifetime() != testLifetime+time.Second {
				t.Errorf("%s runs %s", name, cert.Lifetime())
			}
		case "ok-ends-at-the-last-date":
			if !cert.NotAfter().Equal(LastDate) {
				t.Errorf("%s ends at %s", name, cert.NotAfter())
			}
		}
	}
	// Two certificates whose extensions are not in their one encoding: a
	// name given twice, which the library does not parse, and a value of one
	// empty string, which it writes back as no value, so the certificate is
	// not the bytes the identity signed. The signature that carries either
	// is refused before any rule of the table is read.
	unread := map[string]bool{"bad-extension-twice": true, "bad-extension-value-an-empty-string": true}
	for _, f := range glob(t, "cert/bad-*.pub") {
		name := strings.TrimSuffix(filepath.Base(f), ".pub")
		if unread[name] {
			if _, err := VerifySigned(a, st, read(t, "cert/"+name+".sig"), PrekeyNamespace(a.Address()), now); err == nil {
				t.Errorf("%s: VerifySigned took it", name)
			}
			delete(unread, name)
			continue
		}
		key := vectorCertificate(t, "cert/"+name+".pub")
		sig := read(t, "cert/"+name+".sig")
		want := ErrCertificate
		switch name {
		case "bad-ended":
			want = ErrCertificateEnded
		case "bad-not-begun":
			want = ErrCertificateNotBegun
		case "bad-at-the-trip":
			// Good by every rule of a certificate: A's trip covers it.
			signer, err := VerifySigned(a, st, sig, PrekeyNamespace(a.Address()), now)
			if err != nil || signer.Rank() != trip.Through || !errors.Is(Admits(trip, signer), ErrRevokedSigner) {
				t.Errorf("%s: %v, with A's trip held: %v", name, err, Admits(trip, signer))
			}
			continue
		}
		if _, err := CheckCertificate(a, key, now); !errors.Is(err, want) {
			t.Errorf("%s: CheckCertificate: %v, want %v", name, err, want)
		}
		if _, err := VerifySigned(a, st, sig, PrekeyNamespace(a.Address()), now); !errors.Is(err, want) {
			t.Errorf("%s: VerifySigned: %v, want %v", name, err, want)
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
	for name := range unread {
		t.Errorf("cert/%s is missing", name)
	}
	// The re-wrap: cert/bad-certifies-the-identity carries A's identity's own
	// signature, rank 0, which A's trip covers, with a certificate of the
	// identity's key above the trip in its key's place.
	own, err := Dearmor(read(t, "prekey/bad-signed-by-the-identity.txt.sig"))
	if err != nil {
		t.Fatal(err)
	}
	re := vectorCertificate(t, "cert/bad-certifies-the-identity.pub").(*ssh.Certificate)
	if !bytes.Equal(Armor(rewrap(t, own, re.Marshal())), read(t, "cert/bad-certifies-the-identity.sig")) || re.Serial <= trip.Through {
		t.Error("cert/bad-certifies-the-identity.sig is not the identity's own signature re-wrapped above A's trip")
	}
}

// A's trip is a revocation of its certificates through its clock at ./now
// less one, the identity's own signature, as this code makes it; what the
// identity signs itself is never ranked, so A's revocation and every
// revocation of its certificates verify with the trip held, which refuses the
// identity's signature on a statement, a pass or a message.
func TestVectorTrip(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	trip := vectorTrip(t)
	if trip.Through != uint64(now.Unix())-1 {
		t.Errorf("a/trip runs through %d, not A's clock at ./now less one", trip.Through)
	}
	signer, _ := vectorKey(t, "a")
	built, err := NewRevokedCertificates(a.Address(), trip.Through)
	if err != nil || !bytes.Equal(built.Statement(), read(t, "a/trip.txt")) {
		t.Fatalf("NewRevokedCertificates differs from a/trip.txt: %v", err)
	}
	if sig, err := SignRevokedCertificates(signer, built); err != nil || !bytes.Equal(sig, read(t, "a/trip.sig")) {
		t.Errorf("SignRevokedCertificates differs from a/trip.sig: %v", err)
	}
	if !errors.Is(Admits(trip, IdentitySigner()), ErrRevokedSigner) {
		t.Error("A's trip does not refuse its identity's rank")
	}
	if _, err := VerifyRevocation(a.Address(), a.Document(), read(t, "a/revoke.sig")); err != nil {
		t.Errorf("a/revoke.sig, with A's trip held: %v", err)
	}
	for _, name := range []string{"ok-through-4", "ok-through-the-highest"} {
		if _, err := VerifyRevokedCertificates(a.Address(), a.Document(), read(t, "revoked/"+name+".txt"), read(t, "revoked/"+name+".sig")); err != nil {
			t.Errorf("revoked/%s, with A's trip held: %v", name, err)
		}
	}
}

// cert/ok-reserved-field: A's working key's certificate with bytes in its
// reserved field, which a verifier ignores (draft-ietf-sshm-cert-01 §2.1.1),
// and a signature made under it over a/prekey-1.txt in A's prekey namespace.
// ssh-keygen writes the field empty, so they are made here, the same bytes
// each time: the nonce is a hash of the vector's name, and Ed25519 signs
// deterministically. The kept files are held to them, and
// DROMAS_WRITE_VECTORS=1 writes them.
func TestVectorsReservedField(t *testing.T) {
	a := vectorIdentity(t, "a")
	identity, _ := vectorKey(t, "a")
	seed, err := hex.DecodeString(strings.Fields(string(read(t, "input/a-work.ed25519")))[0])
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := time.Parse(time.RFC3339, "2026-10-09T23:00:00Z") // as generate.sh's V_OK
	before, _ := time.Parse(time.RFC3339, "2026-11-24T00:00:00Z")
	cert := &ssh.Certificate{
		Key:             work.PublicKey(),
		Serial:          vectorRank(t),
		CertType:        ssh.UserCert,
		KeyId:           CertificateKeyID,
		ValidPrincipals: []string{a.Address().String()},
		ValidAfter:      uint64(after.Unix()),  //nolint:gosec // a time in 2026
		ValidBefore:     uint64(before.Unix()), //nolint:gosec // a time in 2026
		Reserved:        []byte("not read"),
	}
	nonce := sha512.Sum512([]byte("dromas vector: cert/ok-reserved-field"))
	if err := cert.SignCert(bytes.NewReader(nonce[:32]), identity); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(cert, work)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(signer, read(t, "a/prekey-1.txt"), PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"cert/ok-reserved-field.pub": ssh.MarshalAuthorizedKey(cert), "cert/ok-reserved-field.sig": sig} {
		if os.Getenv("DROMAS_WRITE_VECTORS") != "" {
			if err := os.WriteFile(filepath.Join(vectors, name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(read(t, name), b) {
			t.Errorf("%s is not what this test makes", name)
		}
	}
}

// Each mailbox's statements verify, by the signer its mode takes: A's under
// its certificate, above its trip, and B's and C's by the identity; and each
// stands in its mailbox's order by (c, p).
func TestVectorPrekeys(t *testing.T) {
	now := vectorNow(t)
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	for _, v := range []struct {
		id     *Identity
		file   string
		sig    string
		serial uint64
		rank   uint64
	}{
		{a, "a/prekey-1.txt", "a/prekey-1.txt.sig", 1, vectorRank(t)},
		{a, "a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", 1, vectorRank(t)},
		{a, "a/prekey-2.txt", "a/prekey-2.txt.sig", 2, vectorRank(t)},
		{a, "prekey/outlives-its-certificate.txt", "prekey/outlives-its-certificate.txt.sig", 1, vectorRank(t) + 1},
		{b, "b/prekey-1.txt", "b/prekey-1.txt.sig", 1, 0},
		{c, "c/prekey-1.txt", "c/prekey-1.txt.sig", 1, 0},
	} {
		p, signer, err := VerifyPrekey(v.id, read(t, v.file), read(t, v.sig), now)
		if err != nil {
			t.Errorf("%s: %v", v.sig, err)
			continue
		}
		if p.Serial != v.serial || p.Type() != PostQuantum || p.Expired(now) || p.CheckLifetime(now) != nil || signer.Rank() != v.rank || signer.Identity() != (v.rank == 0) {
			t.Errorf("%s: serial %d type %s expired %v lifetime %v rank %d", v.sig, p.Serial, p.Type(), p.Expired(now), p.CheckLifetime(now), signer.Rank())
		}
		if err := Admits(vectorHeld(t, v.id), signer); err != nil {
			t.Errorf("%s, in its mailbox's mode: %v", v.sig, err)
		}
		if !bytes.Equal(p.Statement(), read(t, v.file)) {
			t.Errorf("%s: Statement does not reproduce the file", v.file)
		}
		if _, err := p.Recipient(); err != nil {
			t.Errorf("%s: %v", v.file, err)
		}
		o, err := PrekeyOrder(read(t, v.file), read(t, v.sig))
		if err != nil || o.Rank != v.rank || o.Serial != v.serial {
			t.Errorf("%s: PrekeyOrder %+v, %v", v.sig, o, err)
		}
		// A certificate's statement is checked at the verifier's clock: once its
		// certificate has ended, it no longer verifies.
		if cert := signer.Certificate(); cert != nil {
			if _, _, err := VerifyPrekey(v.id, read(t, v.file), read(t, v.sig), cert.NotAfter()); !errors.Is(err, ErrCertificateEnded) {
				t.Errorf("%s: verified after its certificate ended: %v", v.sig, err)
			}
		}
	}
	if _, _, err := VerifyPrekey(b, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), now); err == nil {
		t.Error("B accepted A's prekey")
	}
	// (c, p): a statement under A's later certificate passes A's prekey-2,
	// whose serial is higher under an earlier certificate.
	later, _ := PrekeyOrder(read(t, "prekey/outlives-its-certificate.txt"), read(t, "prekey/outlives-its-certificate.txt.sig"))
	two, _ := PrekeyOrder(read(t, "a/prekey-2.txt"), read(t, "a/prekey-2.txt.sig"))
	if !two.Less(later) || later.Less(two) {
		t.Errorf("(%d, %d) does not pass (%d, %d)", later.Rank, later.Serial, two.Rank, two.Serial)
	}
	// A statement may outlive the certificate it is signed under.
	_, signer, _ := VerifyPrekey(a, read(t, "prekey/outlives-its-certificate.txt"), read(t, "prekey/outlives-its-certificate.txt.sig"), now)
	if p, _ := ParsePrekey(read(t, "prekey/outlives-its-certificate.txt")); signer == nil || p == nil || !p.NotAfter.After(signer.Certificate().NotAfter()) {
		t.Error("control: prekey/outlives-its-certificate does not outlive its certificate")
	}
}

// Every prekey/ vector gets its verdict for the mailbox it names, A unless
// the name says otherwise, in that mailbox's mode.
func TestVectorBadPrekeys(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	// These fail at the signature or its certificate; every other bad-* is
	// well signed, so its format, or its signer in the mode, is what refuses it.
	signature := map[string]bool{"bad-wrong-namespace": true, "bad-signed-by-b": true, "bad-signed-by-a-bare-working-key": true}
	// These verify, and their mailbox's mode refuses their signer: A's
	// identity, rank 0, which A's trip covers, and B's and C's certificates,
	// which a mailbox in identity mode does not take.
	mode := map[string]struct {
		mailbox string
		want    error
	}{
		"bad-signed-by-the-identity":         {"a", ErrRevokedSigner},
		"bad-b-signed-under-its-certificate": {"b", ErrIdentityMode},
		"bad-c-signed-under-its-certificate": {"c", ErrIdentityMode},
	}
	for _, f := range glob(t, "prekey/*.txt") {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		st, _ := os.ReadFile(f)
		sig, _ := os.ReadFile(f + ".sig")
		if m, ok := mode[name]; ok {
			id := vectorIdentity(t, m.mailbox)
			_, signer, err := VerifyPrekey(id, st, sig, now)
			if err != nil || !errors.Is(Admits(vectorHeld(t, id), signer), m.want) {
				t.Errorf("%s: %v, in %s's mode: %v, want %v", name, err, m.mailbox, Admits(vectorHeld(t, id), signer), m.want)
			}
			delete(mode, name)
			continue
		}
		p, signer, err := VerifyPrekey(a, st, sig, now)
		switch {
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted, signed by rank %d", name, signer.Rank())
			}
			if !signature[name] {
				if _, err := VerifySigned(a, st, sig, PrekeyNamespace(a.Address()), now); err != nil {
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
		case name == "outlives-its-certificate": // TestVectorPrekeys
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case strings.HasPrefix(name, "unsupported-type"): // good in every other way: refused with its own error, never as one that does not verify
			if _, perr := ParsePrekey(st); !errors.Is(err, ErrPrekeyType) || !errors.Is(perr, ErrPrekeyType) {
				t.Errorf("%s: %v, and parsed %v, want ErrPrekeyType", name, err, perr)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
		if signer != nil && Admits(vectorTrip(t), signer) != nil {
			t.Errorf("%s: its signer is refused in A's mode: %v", name, Admits(vectorTrip(t), signer))
		}
	}
	for name := range mode {
		t.Errorf("prekey/%s is missing", name)
	}
}

// A prekey's type is its key's Bech32 human-readable part, the string read as
// age writes one: in lowercase, its checksum good, its data whole bytes. A
// well-formed key of a type this client lacks is ErrPrekeyType, and that is
// the last thing a statement is held to: one that fails anything else fails
// as a statement that does not verify.
func TestAPrekeyOfATypeThisClientLacks(t *testing.T) {
	unknown := strings.Split(string(read(t, "prekey/unsupported-type.txt")), "\n")[3]
	x25519 := strings.TrimSpace(string(read(t, "input/other.x25519")))
	for key, hrp := range map[string]string{
		strings.TrimSpace(string(read(t, "input/a-1.pq"))): "age1pq",
		x25519:  "age",
		unknown: "age1nosuchtype",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw": "abcdef", // BIP 173's own
		bech32Of("age1nosuchtype", "qq"):                "age1nosuchtype",
		bech32Of("age1nosuchtype", ""):                  "age1nosuchtype",
	} {
		if got, ok := bech32HRP(key); !ok || got != hrp {
			t.Errorf("%s: %q, %v, want %q", key, got, ok, hrp)
		}
	}
	for _, key := range []string{
		strings.ToUpper(unknown), // Bech32, but not as age writes it
		"age1NOSUCHTYPE" + unknown[len("age1nosuchtype"):],
		unknown[:len(unknown)-1] + "q", // the checksum
		unknown + "q",
		bech32Of("age1nosuchtype", "q"),  // five bits left over
		bech32Of("age1nosuchtype", "qp"), // two left over, not zero
		bech32Of("age1nosuchtype", "qb"), // b is not in the alphabet
		"age1nosuchtype1qqqqq", "1qqqqqqqq", "", "age1pq",
	} {
		if hrp, ok := bech32HRP(key); ok {
			t.Errorf("%s: taken, as %q", key, hrp)
		}
	}
	for key, want := range map[string]error{
		unknown:                        ErrPrekeyType,
		x25519:                         ErrPrekeyType,
		bech32Of("agefoo", "qq"):       ErrPrekeyType,
		bech32Of("age1nosuchtype", ""): ErrPrekeyType,
		bech32Of("age", "qq"):          ErrPrekeyType, // X25519's, which is no prekey type
		bech32Of("age1pq", "qq"):       nil,           // the prekey type, and not a key of it
		bech32Of("nosuchtype", "qq"):   nil,           // Bech32, and no age recipient
		strings.ToUpper(unknown):       nil,
	} {
		err := checkRecipient(&Prekey{Key: key})
		if err == nil || errors.Is(err, ErrPrekeyType) != (want != nil) {
			t.Errorf("%s: %v, want ErrPrekeyType: %v", key, err, want != nil)
		}
	}

	// The type is asked last: the same key in a statement that names another
	// mailbox, or that breaks its form, is a statement that does not verify.
	now := vectorNow(t)
	a, b := vectorIdentity(t, "a"), vectorIdentity(t, "b")
	w := vectorWorker(t, "a")
	for _, st := range []string{
		PrekeyTag + "\n" + b.Address().String() + "\n1\n" + unknown + "\n2026-11-12T00:00:00Z\n",
		PrekeyTag + "\n" + a.Address().String() + "\n1\n" + unknown + "\n2026-11-12T00:00:00z\n",
		PrekeyTag + "\n" + a.Address().String() + "\n01\n" + unknown + "\n2026-11-12T00:00:00Z\n",
	} {
		sig, err := Sign(w, []byte(st), PrekeyNamespace(a.Address()))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyPrekey(a, []byte(st), sig, now); err == nil || errors.Is(err, ErrPrekeyType) {
			t.Errorf("%q: %v, want a statement that does not verify", st, err)
		}
	}
}

// bech32Of is hrp and data, in Bech32's alphabet, with the checksum that makes
// them a Bech32 string: a test's way to write one whose data breaks a rule.
func bech32Of(hrp, data string) string {
	var values []byte
	for i := range len(hrp) {
		values = append(values, hrp[i]>>5)
	}
	values = append(values, 0)
	for i := range len(hrp) {
		values = append(values, hrp[i]&31)
	}
	for i := range len(data) {
		values = append(values, byte(strings.IndexByte(bech32Charset, data[i])))
	}
	chk := bech32Polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	out := hrp + "1" + data
	for i := range 6 {
		out += string(bech32Charset[chk>>(25-5*i)&31])
	}
	return out
}

// TestVectorSignatures checks Go's signatures are byte-identical to the
// ssh-keygen ones in the vectors: Ed25519 is deterministic, and a signature
// under a kept certificate carries that certificate's bytes. A signs in
// working-key mode, B in identity mode, and each identity signs its own
// revocations.
func TestVectorSignatures(t *testing.T) {
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	ia, _ := vectorKey(t, "a")
	ib, _ := vectorKey(t, "b")
	wa := vectorWorker(t, "a")
	for _, v := range []struct {
		signer ssh.Signer
		msg    string
		sig    string
		ns     string
	}{
		{wa, "a/prekey-1.txt", "a/prekey-1.txt.sig", PrekeyNamespace(a.Address())},
		{wa, "a/prekey-2.txt", "a/prekey-2.txt.sig", PrekeyNamespace(a.Address())},
		{wa, "a/pass.txt", "a/pass.sig", PassNamespace(a.Address())},
		{wa, "message/a-to-b.line", "message/a-to-b.sig", MessageNamespace(b.Address())},
		{wa, "message/a-to-c.line", "message/a-to-c.sig", MessageNamespace(c.Address())},
		{ia, "a/revoke.txt", "a/revoke.sig", RevokeNamespace(a.Address())},
		{ia, "a/trip.txt", "a/trip.sig", RevokedCertsNamespace(a.Address())},
		{ib, "b/prekey-1.txt", "b/prekey-1.txt.sig", PrekeyNamespace(b.Address())},
		{ib, "b/pass.txt", "b/pass.sig", PassNamespace(b.Address())},
		{ib, "message/b-to-c.line", "message/b-to-c.sig", MessageNamespace(c.Address())},
	} {
		got, err := Sign(v.signer, read(t, v.msg), v.ns)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, read(t, v.sig)) {
			t.Errorf("%s: Go's signature differs from ssh-keygen's:\n%s", v.sig, got)
		}
	}
	if err := Verify(a, read(t, "a/revoke.txt"), read(t, "a/revoke.sig"), RevokeNamespace(a.Address())); err != nil {
		t.Errorf("a/revoke.sig: %v", err)
	}
	if !bytes.Equal(RevocationStatement(a.Address()), read(t, "a/revoke.txt")) {
		t.Error("RevocationStatement differs from a/revoke.txt")
	}
}

// One signature in the forms sig/ holds: each ok-* is read as "ssh-keygen -Y
// verify" reads it and verifies, and each bad-* is refused (PROTOCOL.md §3.2).
// sh/sh_test.go holds the script to the same verdicts, and ssh-keygen too but
// for the ones it takes and a verifier here does not.
func TestVectorSignatureForms(t *testing.T) {
	now := vectorNow(t)
	a := vectorIdentity(t, "a")
	stmt := read(t, "a/prekey-1.txt")
	for _, f := range glob(t, "sig/*.sig") {
		name := "sig/" + filepath.Base(f)
		_, err := VerifySigned(a, stmt, read(t, name), PrekeyNamespace(a.Address()), now)
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

// Each identity key type states its own bound on a signature, and
// MaxSignature, what a verifier holds one to before it knows the type, is the
// largest of them. What a mailbox signs is held to its identity's: with that
// bound lowered, every verifier refuses the mailbox's signatures, a pass's
// included, and another type's mailbox is untouched (PROTOCOL.md §3.2).
func TestASignatureIsHeldToItsIdentitysBound(t *testing.T) {
	most := 0
	for _, ty := range IdentityTypes() {
		if SignatureBound(ty) <= 0 {
			t.Errorf("%s states no bound", ty)
		}
		most = max(most, SignatureBound(ty))
	}
	if most != MaxSignature || SignatureBound(IdentityEd25519) != 4096 || SignatureBound(IdentityP256) != 4096 {
		t.Errorf("the bounds are %d and %d, the most %d, and MaxSignature %d", SignatureBound(IdentityEd25519), SignatureBound(IdentityP256), most, MaxSignature)
	}
	if SignatureBound("no-such-key-type@dromas.invalid") != 0 {
		t.Error("a key type not defined here has a bound")
	}

	now := vectorNow(t)
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	pass := func(mailbox string) *Pass {
		p, err := ParsePass(strings.TrimSuffix(string(read(t, mailbox+"/pass.authorization")), "\n"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	pa, pb, pc := pass("a"), pass("b"), pass("c")
	onRecord := sha256.Sum256(vectorCertificate(t, "a/work-cert.pub").Marshal())
	bOnRecord, cOnRecord := sha256.Sum256(b.PublicKey().Marshal()), sha256.Sum256(c.PublicKey().Marshal())
	// Ed25519's: A's under its certificate, B's by its identity. Then C's, a
	// P-256 identity's.
	verdicts := func() []error {
		_, e1 := VerifySigned(a, read(t, "a/prekey-1.txt"), read(t, "a/prekey-1.txt.sig"), PrekeyNamespace(a.Address()), now)
		e2 := Verify(a, read(t, "a/revoke.txt"), read(t, "a/revoke.sig"), RevokeNamespace(a.Address()))
		_, e3 := pa.Verify(a, "dromas.example", now)
		_, e4 := pa.VerifyUnder(onRecord, "dromas.example", now)
		_, e5 := VerifySigned(b, read(t, "b/prekey-1.txt"), read(t, "b/prekey-1.txt.sig"), PrekeyNamespace(b.Address()), now)
		_, e6 := pb.VerifyUnder(bOnRecord, "dromas.example", now)
		_, e7 := VerifySigned(c, read(t, "c/prekey-1.txt"), read(t, "c/prekey-1.txt.sig"), PrekeyNamespace(c.Address()), now)
		_, e8 := pc.VerifyUnder(cOnRecord, "dromas.example", now)
		return []error{e1, e2, e3, e4, e5, e6, e7, e8}
	}
	for i, err := range verdicts() {
		if err != nil {
			t.Fatalf("control %d: %v", i, err)
		}
	}
	ed := identityTypes[IdentityEd25519]
	defer func() { identityTypes[IdentityEd25519] = ed }()
	lowered := ed
	lowered.bound = 396 // below every signature here
	identityTypes[IdentityEd25519] = lowered
	got := verdicts()
	for i, err := range got[:6] {
		if err == nil {
			t.Errorf("Ed25519 identity's signature %d was taken over its identity's bound", i)
		}
	}
	if !errors.Is(got[3], ErrPass) || !errors.Is(got[5], ErrPass) {
		t.Errorf("a pass over its identity's bound, checked under the key on record: %v, %v", got[3], got[5])
	}
	if got[6] != nil || got[7] != nil {
		t.Errorf("C's signatures, a P-256 identity's, were held to Ed25519's bound: %v, %v", got[6], got[7])
	}
}

// Each mailbox's pass is signed by the signer of its statements: A's under its
// certificate, B's and C's by the identity, each taken in its mailbox's mode.
func TestVectorPass(t *testing.T) {
	now := vectorNow(t)
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	const server = "dromas.example"
	ib, _ := vectorKey(t, "b")
	for _, v := range []struct {
		id, other *Identity
		mailbox   string
		signer    ssh.Signer // nil: an ECDSA signature, which differs each time it is made
		rank      uint64
	}{{a, b, "a", vectorWorker(t, "a"), vectorRank(t)}, {b, c, "b", ib, 0}, {c, a, "c", nil, 0}} {
		header := strings.TrimSuffix(string(read(t, v.mailbox+"/pass.authorization")), "\n")
		if v.signer != nil {
			got, notAfter, err := NewPass(v.signer, v.id.Address(), server, now)
			if err != nil {
				t.Fatal(err)
			}
			if got != header || !notAfter.Equal(now.Add(PassLifetime)) {
				t.Errorf("NewPass differs from %s/pass.authorization:\n%s", v.mailbox, got)
			}
		}
		if !bytes.Equal(PassStatement(v.id.Address(), server, now.Add(PassLifetime)), read(t, v.mailbox+"/pass.txt")) {
			t.Errorf("PassStatement differs from %s/pass.txt", v.mailbox)
		}
		p, err := ParsePass(header)
		if err != nil {
			t.Fatal(err)
		}
		if signer, err := p.Verify(v.id, server, now); err != nil || signer.Rank() != v.rank || Admits(vectorHeld(t, v.id), signer) != nil {
			t.Errorf("%s/pass.authorization: %v", v.mailbox, err)
		}
		if _, err := p.Verify(v.id, "another.example", now); !errors.Is(err, ErrPass) {
			t.Errorf("%s: a pass for one server was taken by another: %v", v.mailbox, err)
		}
		if _, err := p.Verify(v.other, server, now); !errors.Is(err, ErrPass) {
			t.Errorf("%s's pass was taken as another mailbox's: %v", v.mailbox, err)
		}
		if _, err := p.Verify(v.id, server, now.Add(PassLifetime)); !errors.Is(err, ErrPassExpired) {
			t.Errorf("%s: a pass was taken at the moment it runs out: %v", v.mailbox, err)
		}
	}
}

// Every pass/ vector is read as its name says (PROTOCOL.md §8): ok-* as
// the same three values as a/pass.authorization, written back as that pass,
// so it verifies as that pass does, and bad-* as no pass. A sender writes
// one of them.
func TestVectorPassForms(t *testing.T) {
	files := glob(t, "pass/*.authorization")
	if len(files) != 37 {
		t.Fatalf("%d pass/ vectors, want 37", len(files))
	}
	now, a := vectorNow(t), vectorIdentity(t, "a")
	header := strings.TrimSuffix(string(read(t, "a/pass.authorization")), "\n")
	want, err := ParsePass(header)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".authorization")
		v := string(read(t, "pass/"+filepath.Base(f)))
		if (v == header) != (name == "ok-as-a-sender-writes-it") {
			t.Errorf("%s: written as a sender writes a pass: %v", name, v == header)
		}
		p, err := ParsePass(v)
		switch {
		case strings.HasPrefix(name, "bad-"):
			if !errors.Is(err, ErrPass) {
				t.Errorf("%s: %v, want ErrPass", name, err)
			}
		case err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case p.Address != want.Address || !p.NotAfter.Equal(want.NotAfter) || !bytes.Equal(p.signature, want.signature):
			t.Errorf("%s: read as other values than a/pass.authorization", name)
		case p.Authorization() != header:
			t.Errorf("%s: written back as %q", name, p.Authorization())
		default:
			if _, err := p.Verify(a, "dromas.example", now); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// refusedCertificateRevoked is a reader's code at check 7 for a signer the
// sender's revocation of its certificates covers (PROTOCOL.md §12.3), the
// identity's rank 0 among them: the client's own, beside this package's codes.
const refusedCertificateRevoked = "certificate_revoked"

// plainVerdicts is what B makes of each plain/ vector at ./now, checks 1 to 6
// and then check 7's mode, with A's trip held: "" for a message that is
// delivered, or the code it is refused with.
var plainVerdicts = map[string]string{
	"accept-no-padding":                                  "",
	"accept-padded":                                      "",
	"accept-anything-after-the-signature":                "",
	"accept-every-field":                                 "",
	"accept-body-more-precise-than-binary64":             "",
	"refuse-signed-for-another-mailbox":                  RefusedSignature,
	"refuse-signed-by-the-identity":                      refusedCertificateRevoked,
	"refuse-certificate-at-the-trip":                     refusedCertificateRevoked,
	"refuse-identity-s-signature-re-wrapped":             RefusedSignature,
	"refuse-signed-by-a-bare-working-key":                RefusedSignature,
	"refuse-certificate-ended":                           RefusedSignature,
	"refuse-line-changed-after-signing":                  RefusedSignature,
	"refuse-another-mailbox-s-identity-document":         RefusedSignature,
	"refuse-from-is-not-the-identity":                    RefusedAttribution,
	"refuse-from-null":                                   RefusedAttribution,
	"accept-p256-sender":                                 "",
	"refuse-p256-sender-under-a-certificate":             RefusedSignature,
	"refuse-unsupported-key-type":                        RefusedKeyType,
	"refuse-from-is-not-the-identity-of-an-unknown-type": RefusedAttribution,
	"refuse-to-another-mailbox":                          RefusedAttribution,
	"refuse-no-identity":                                 RefusedIdentity,
	"refuse-identity-not-base64":                         RefusedIdentity,
	"refuse-identity-ending-in-a-line-feed":              RefusedIdentity,
	"refuse-identity-ending-in-a-nul":                    RefusedIdentity,
	"refuse-identity-of-small-order":                     RefusedIdentity,
	"refuse-identity-off-curve":                          RefusedIdentity,
	"refuse-identity-with-its-length-written-33":         RefusedIdentity,
	"refuse-no-line-feed":                                RefusedMessage,
	"refuse-no-signature":                                RefusedMessage,
	"refuse-blank-line-before-the-signature":             RefusedMessage,
	"refuse-begin-line-followed-by-a-nul":                RefusedMessage,
	"refuse-begin-line-holding-a-nul":                    RefusedMessage,
	"refuse-begin-line-preceded-by-a-nul":                RefusedMessage,
	"refuse-signature-first":                             RefusedMessage,
	"refuse-no-end-line":                                 RefusedMessage,
	"refuse-end-line-without-its-line-feed":              RefusedMessage,
	"refuse-end-line-followed-by-a-nul":                  RefusedMessage,
	"refuse-end-line-followed-by-a-byte-and-a-later-one": RefusedMessage,
	"refuse-crlf":                                        RefusedMessage,
	"refuse-envelope-on-two-lines":                       RefusedMessage,
	"accept-whitespace-in-the-signature":                 "",
	"refuse-signature-over-4096-bytes":                   RefusedSignature,
}

// verdictOf is what B makes of plaintext pt at now: OpenSigned's checks, then
// check 7's mode, the sender's held revocation of its certificates applied to
// its signer, which a reader makes with the read of the sender it already
// makes (PROTOCOL.md §12.3). A certificate from a sender in identity mode is
// bad_signature; a signer the revocation covers is certificate_revoked.
func verdictOf(t *testing.T, pt []byte, b *Identity, now time.Time) (*Signed, string) {
	t.Helper()
	m, err := OpenSigned(pt, b.Address(), now)
	if err != nil {
		var refused *EnvelopeError
		if !errors.As(err, &refused) {
			t.Fatalf("refused as %v, with no code", err)
		}
		return nil, refused.Code
	}
	switch err := Admits(vectorHeld(t, m.Sender), m.Signer); {
	case errors.Is(err, ErrIdentityMode):
		return m, RefusedSignature
	case errors.Is(err, ErrRevokedSigner):
		return m, refusedCertificateRevoked
	case err != nil:
		t.Fatal(err)
	}
	return m, ""
}

func TestVectorPlaintexts(t *testing.T) {
	now := vectorNow(t)
	a, b, c := vectorIdentity(t, "a"), vectorIdentity(t, "b"), vectorIdentity(t, "c")
	seen := 0
	for _, f := range glob(t, "plain/*.txt") {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		from, rank := a, vectorRank(t)
		if strings.Contains(name, "p256-sender") {
			from, rank = c, 0
		}
		want, known := plainVerdicts[name]
		if !known {
			t.Errorf("%s: unknown vector", name)
			continue
		}
		seen++
		pt, _ := os.ReadFile(f)
		m, got := verdictOf(t, pt, b, now)
		switch {
		case got != want:
			t.Errorf("%s: %q, want %q", name, got, want)
		case want == "" && (m.Sender.Address() != from.Address() || m.Envelope.From != from.Address() || m.Signer.Rank() != rank):
			t.Errorf("%s: delivered as from %s, signed by rank %d", name, m.Sender.Address(), m.Signer.Rank())
		}
		// The line that was checked is the first line as it arrived, byte
		// for byte: nothing is verified or read from a rebuilt copy.
		if m != nil && !bytes.HasPrefix(pt, m.Line) {
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
	// Each refusal by the mode passes checks 1 to 6, so check 7 is what
	// refuses it, and only in its sender's mode: in the other, each is taken.
	for name, held := range map[string]*RevokedCertificates{
		"refuse-signed-by-the-identity":          nil,
		"refuse-p256-sender-under-a-certificate": {Address: c.Address(), Through: 1},
	} {
		m, err := OpenSigned(read(t, "plain/"+name+".txt"), b.Address(), now)
		if err != nil {
			t.Errorf("%s: control: refused before check 7: %v", name, err)
			continue
		}
		if err := Admits(held, m.Signer); err != nil {
			t.Errorf("%s: control: refused in the other mode too: %v", name, err)
		}
	}
}

// Each message/ vector is what a client makes from the same keys, sealed to its
// recipient's prekey: A's under its certificate, B's by its identity; and each
// is delivered to its recipient in its sender's mode.
func TestVectorMessage(t *testing.T) {
	now := vectorNow(t)
	ib, _ := vectorKey(t, "b")
	for _, v := range []struct {
		from, to, name, key, stanza string
		signer                      ssh.Signer
		t                           KeyType
	}{
		{"a", "b", "a-to-b", "b-1.pq", "mlkem768x25519", vectorWorker(t, "a"), PostQuantum},
		{"a", "c", "a-to-c", "b-1.pq", "mlkem768x25519", vectorWorker(t, "a"), PostQuantum},
		{"b", "c", "b-to-c", "b-1.pq", "mlkem768x25519", ib, PostQuantum},
	} {
		from, to := vectorIdentity(t, v.from), vectorIdentity(t, v.to)
		// Go builds the same plaintext as the stock tools did: the line, the
		// signature by the sender's signer, and the padding for the
		// recipient's prekey.
		env := &Envelope{From: from.Address(), To: to.Address(), SentAt: now, MsgID: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b", Identity: from.Document(), Body: []byte(`"hello"`)}
		line, sig, err := SignEnvelope(env, v.signer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(line, read(t, "message/"+v.name+".line")) || !bytes.Equal(sig, read(t, "message/"+v.name+".sig")) {
			t.Errorf("%s: SignEnvelope differs from its .line and .sig:\n%s%s", v.name, line, sig)
		}
		pt, sealed := Plaintext(line, sig, v.t)
		m := read(t, "message/"+v.name+".age")
		if !bytes.Equal(pt, read(t, "message/"+v.name+".plain")) || sealed != len(m) {
			t.Errorf("%s: Plaintext differs from its .plain: %d bytes for a file of %d, want %d", v.name, len(pt), sealed, len(m))
		}
		if !bytes.HasPrefix(m, []byte("age-encryption.org/v1\n-> "+v.stanza+" ")) {
			t.Errorf("%s: the message is not an age file to one %s recipient", v.name, v.stanza)
		}
		if len(m) != PaddedSize(len(m)) {
			t.Errorf("%s: the message is %d bytes, not a whole number of blocks", v.name, len(m))
		}
		// Its recipient takes it, in its sender's mode.
		if opened, err := OpenSigned(pt, to.Address(), now); err != nil || opened.Sender.Address() != from.Address() || Admits(vectorHeld(t, from), opened.Signer) != nil {
			t.Errorf("%s: not delivered to %s: %v", v.name, v.to, err)
		}
		// And it decrypts, with the published test identity of its prekey
		// (C2SP's age testkit), to exactly that plaintext.
		ids, err := age.ParseIdentities(bytes.NewReader(read(t, "input/"+v.key+".key")))
		if err != nil {
			t.Fatal(err)
		}
		r, err := age.Decrypt(bytes.NewReader(m), ids...)
		if err != nil {
			t.Errorf("%s: %v", v.name, err)
			continue
		}
		if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, pt) {
			t.Errorf("%s: decrypts to other bytes than its .plain (%v)", v.name, err)
		}
	}
}

// The three ciphertexts are the files typage, a second age implementation,
// read: testdata/vectors/README.md names each by its SHA-256, and a file
// made again fails this until typage reads it and the README names it
// (#454 item 3).
func TestTheCiphertextsAreTheOnesTypageRead(t *testing.T) {
	t.Parallel()
	readme := string(read(t, "README.md"))
	named := regexp.MustCompile("`message/([ab]-to-[bc])\\.age` \\(sha256 `([0-9a-f]{64})`\\)").FindAllStringSubmatch(readme, -1)
	if files := glob(t, "message/*.age"); len(named) != len(files) || len(files) != 3 {
		t.Fatalf("the README names %d ciphertexts by their hash, and there are %d: want all three", len(named), len(files))
	}
	for _, m := range named {
		sum := sha256.Sum256(read(t, "message/"+m[1]+".age"))
		if got := hex.EncodeToString(sum[:]); got != m[2] {
			t.Errorf("message/%s.age is sha256 %s, and the README names %s as what typage read", m[1], got, m[2])
		}
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
			// Every refusal has its code: bad_envelope, but for these.
			want := map[string]string{
				"refuse-33-days-and-1s-old":  RefusedStale,
				"refuse-1-hour-and-1s-ahead": RefusedFuture,
				"refuse-from-not-signer":     RefusedAttribution,
				"refuse-from-null":           RefusedAttribution, // null is a member left out
				"refuse-to-another-mailbox":  RefusedAttribution,
			}[name]
			if want == "" {
				want = RefusedEnvelope // an uppercase from or to is no address at all
			}
			var ee *EnvelopeError
			if !errors.As(err, &ee) || ee.Code != want {
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
		w := sha512.Sum512([]byte("dromas vector: R plus the point of order 2"))
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
// own Ed25519 from 10.6p1 judges both the other way (PROTOCOL.md Appendix A). They
// are made here, the same bytes each time, and the kept files are held to
// them: DROMAS_WRITE_VECTORS=1 writes them.
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
		if os.Getenv("DROMAS_WRITE_VECTORS") != "" {
			if err := os.WriteFile(filepath.Join(vectors, v.name), sig, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(read(t, v.name), sig) {
			t.Errorf("%s is not what this test makes", v.name)
		}
	}
}
