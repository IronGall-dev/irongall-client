package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

// What a reader runs on bytes nobody has vouched for yet, before a signature
// verifies, is fuzzed here, each target seeded from the vectors (#49). Each
// holds the code to what it promises: no panic, a refusal is an error with no
// result beside it, and whatever else its doc comment says. Run one at a time:
//
//	go test -run '^$' -fuzz '^FuzzExamine$' -fuzztime 2m -parallel 1 ./protocol

// seeds adds every vector file that pattern matches, as one argument.
func seeds(f *testing.F, patterns ...string) {
	f.Helper()
	n := 0
	for _, p := range patterns {
		m, err := filepath.Glob(filepath.Join(vectors, p))
		if err != nil {
			f.Fatal(err)
		}
		for _, name := range m {
			b, err := os.ReadFile(name) //nolint:gosec // a vector of this repo
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
			n++
		}
	}
	if n == 0 {
		f.Fatalf("no vectors match %v", patterns)
	}
}

// fuzzNow is the vectors' clock.
func fuzzNow(f *testing.F) time.Time {
	f.Helper()
	now, err := ParseTime(strings.TrimSpace(string(read(f, "now"))))
	if err != nil {
		f.Fatal(err)
	}
	return now
}

// fuzzIdentity is a vector mailbox's identity.
func fuzzIdentity(f *testing.F, mailbox string) *Identity {
	f.Helper()
	id, err := ParseIdentity(read(f, mailbox+"/identity.doc"))
	if err != nil {
		f.Fatal(err)
	}
	return id
}

// splitPlaintext takes a plaintext only as an envelope line, its line feed
// the first in the plaintext, then a signature block from its BEGIN line
// through its first END line and the line feed after it, both cut from the
// plaintext as they are; otherwise it gives nothing.
func FuzzSplitPlaintext(f *testing.F) {
	seeds(f, "plain/*.txt", "message/*.plain")
	f.Fuzz(func(t *testing.T, p []byte) {
		line, sig, ok := splitPlaintext(p)
		if !ok {
			if line != nil || sig != nil {
				t.Fatalf("refused, with %q and %q beside it", line, sig)
			}
			return
		}
		end := "\n" + armorEnd + "\n"
		switch {
		case !bytes.HasPrefix(p, slices.Concat(line, sig)):
			t.Fatal("the parts are not the plaintext's own bytes, in order")
		case len(line) == 0 || bytes.IndexByte(line, '\n') != len(line)-1:
			t.Fatalf("the line %q is not everything through the first line feed", line)
		case !bytes.HasPrefix(sig, []byte(armorBegin)) || !bytes.HasSuffix(sig, []byte(end)):
			t.Fatalf("the block %q is not from a BEGIN line through an END line", sig)
		case bytes.Index(sig, []byte("\n"+armorEnd)) != len(sig)-len(end):
			t.Fatalf("the block %q runs past its first END line", sig)
		}
	})
}

// envelopeSender and objectFields read an envelope's line before anything
// is verified. objectFields takes only one JSON object with no name twice,
// as the protocol reads one, and leaves each member as its raw JSON;
// envelopeSender takes only a line objectFields takes, in UTF-8, and gives
// from as the string it holds and the identity document as the bytes whose
// one base64 encoding the line holds. A refusal is bad_envelope or
// bad_identity, with nothing beside it.
func FuzzEnvelopeSender(f *testing.F) {
	seeds(f, "envelope/*.json", "json/*.json", "message/*.line")
	f.Fuzz(func(t *testing.T, line []byte) {
		fields, ferr := objectFields(line)
		switch {
		case ferr != nil && fields != nil:
			t.Fatalf("objectFields refused, with %d fields beside it", len(fields))
		case ferr != nil && !isRefusal(ferr, RefusedEnvelope):
			t.Fatalf("objectFields refused as %v", ferr)
		case ferr == nil:
			if why := independentlyRead(line); why != "" {
				t.Fatalf("objectFields took a text the protocol does not read: %s", why)
			}
			for name, raw := range fields {
				if !jsontext.Value(raw).IsValid() {
					t.Fatalf("member %q is not a JSON value: %q", name, raw)
				}
			}
		}

		doc, from, err := envelopeSender(line)
		if err != nil {
			if doc != nil || from != "" {
				t.Fatalf("refused, with %q and %q beside it", doc, from)
			}
			if !isRefusal(err, RefusedEnvelope) && !isRefusal(err, RefusedIdentity) {
				t.Fatalf("refused as %v", err)
			}
			return
		}
		if ferr != nil || !utf8.Valid(line) {
			t.Fatalf("took a line objectFields refuses (%v), or one that is not UTF-8", ferr)
		}
		var want string
		if raw, ok := fields["from"]; ok && string(raw) != "null" && unmarshalString(raw, &want) != nil {
			t.Fatalf("took a from that is no string: %s", raw)
		}
		if from != want {
			t.Fatalf("from is %q, the line holds %q", from, want)
		}
		raw, ok := fields["identity"]
		if !ok {
			if doc != nil {
				t.Fatal("a document from a line with no identity member")
			}
			return
		}
		var b64 string
		if unmarshalString(raw, &b64) != nil || len(doc) == 0 || base64.StdEncoding.EncodeToString(doc) != b64 {
			t.Fatalf("the document %q is not the bytes whose one encoding the line holds, %s", doc, raw)
		}
	})
}

// ParseIdentity takes a document only in the one form every type shares: it
// gives back the document's own bytes, the address is their SHA-256, the
// key is of a type the protocol defines, and the document is that key
// written again; and an Ed25519 key only as a canonical point not of small
// order (edwardsKeyFault, which reads it apart from the function's own
// check). A refusal gives no identity.
func FuzzParseIdentity(f *testing.F) {
	seeds(f, "identity/*.doc", "a/identity.doc", "b/identity.doc", "c/identity.doc")
	f.Fuzz(func(t *testing.T, doc []byte) {
		id, err := ParseIdentity(doc)
		if err != nil {
			if id != nil {
				t.Fatal("refused, with an identity beside it")
			}
			if !errors.Is(err, ErrIdentityFormat) && !errors.Is(err, ErrIdentityKey) && !errors.Is(err, ErrIdentityType) {
				t.Fatalf("refused as %v", err)
			}
			return
		}
		key := id.PublicKey()
		written := "dromas-v1\n" + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n"
		switch {
		case !bytes.Equal(id.Document(), doc):
			t.Fatalf("the document is %q, given %q", id.Document(), doc)
		case id.Address() != Address(sha512.Sum384(doc)):
			t.Fatal("the address is not the document's SHA-256")
		case !slices.Contains(IdentityTypes(), key.Type()):
			t.Fatalf("took a key of the type %q", key.Type())
		case written != string(doc):
			t.Fatalf("the document %q is not its key written again, %q", doc, written)
		case key.Type() == ssh.KeyAlgoED25519 && edwardsKeyFault(key) != "":
			t.Fatalf("took an Ed25519 key that is %s", edwardsKeyFault(key))
		}
		again, err := ParseIdentity(id.Document())
		if err != nil || again.Address() != id.Address() {
			t.Fatalf("its own document is refused: %v", err)
		}
	})
}

// Dearmor takes a signature of at most MaxSignature bytes that begins with
// the BEGIN line, and gives a blob in the one form the checks after it take:
// so the blob armored again reads back as itself. A refusal gives no blob.
func FuzzDearmor(f *testing.F) {
	seeds(f, "sig/*.sig", "message/*.sig", "revoke/*.sig", "revoked/*.sig", "a/*.sig", "c/*.sig", "cert/*.sig")
	f.Fuzz(func(t *testing.T, armored []byte) {
		blob, err := Dearmor(armored)
		if err != nil {
			if blob != nil {
				t.Fatal("refused, with a blob beside it")
			}
			return
		}
		if len(armored) > MaxSignature || !bytes.HasPrefix(armored, []byte(strings.TrimSuffix(armorBegin, "\n"))) {
			t.Fatalf("took %d bytes beginning %q", len(armored), armored[:min(len(armored), 40)])
		}
		again, err := Dearmor(Armor(blob))
		if err != nil || !bytes.Equal(again, blob) {
			t.Fatalf("the blob armored again reads otherwise: %v", err)
		}
	})
}

// CheckCertificate takes only a user certificate its identity signed for a
// working key, under the key id the protocol names, with one principal, the
// mailbox's address, a serial from 1 to MaxSerial, no critical option, and valid
// at now, for at most MaxCertificateLifetime: its signature is the identity
// key's over the certificate's bytes (signedBytes, read apart from the
// library's check), and its working key an Ed25519 key that is a canonical
// point not of small order and not the identity key. A refusal is
// ErrCertificate or ErrCertificateTime, with no certificate beside it. Each
// key is tried against each vector identity, at the vectors' clock and at an
// offset; the seeds hold each vector certificate, and each with its validity
// moved a second after it was signed, which nothing but the signature
// refuses.
func FuzzCheckCertificate(f *testing.F) {
	now := fuzzNow(f)
	ids := []*Identity{fuzzIdentity(f, "a"), fuzzIdentity(f, "b"), fuzzIdentity(f, "c")}
	var files []string
	for _, p := range []string{"*/work-cert.pub", "cert/*.pub"} {
		m, err := filepath.Glob(filepath.Join(vectors, p))
		if err != nil {
			f.Fatal(err)
		}
		files = append(files, m...)
	}
	for _, name := range files {
		raw, err := os.ReadFile(name) //nolint:gosec // a vector of this repo
		if err != nil {
			f.Fatal(err)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			continue
		}
		f.Add(key.Marshal(), int64(0))
		if cert, ok := key.(*ssh.Certificate); ok {
			altered := *cert
			altered.ValidBefore--
			f.Add(altered.Marshal(), int64(0))
		}
	}
	f.Fuzz(func(t *testing.T, wire []byte, offset int64) {
		key, err := ssh.ParsePublicKey(wire)
		if err != nil {
			return
		}
		at := now.Add(time.Duration(offset%(100*24*3600)) * time.Second)
		for _, id := range ids {
			c, err := CheckCertificate(id, key, at)
			if err != nil {
				if c != nil {
					t.Fatal("refused, with a certificate beside it")
				}
				if !errors.Is(err, ErrCertificate) && !errors.Is(err, ErrCertificateTime) {
					t.Fatalf("refused as %v", err)
				}
				continue
			}
			cert, ok := key.(*ssh.Certificate)
			unix := uint64(max(at.Unix(), 0))
			switch {
			case !ok || cert.CertType != ssh.UserCert || cert.KeyId != CertificateKeyID:
				t.Fatal("took a key that is no user certificate under the protocol's key id")
			case cert.Serial == 0 || cert.Serial > MaxSerial || c.Serial() != cert.Serial:
				t.Fatalf("took the serial %d", cert.Serial)
			case len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != id.Address().String():
				t.Fatalf("took the principals %q for %s", cert.ValidPrincipals, id.Address())
			case len(cert.CriticalOptions) != 0:
				t.Fatal("took a critical option")
			case !bytes.Equal(cert.SignatureKey.Marshal(), id.PublicKey().Marshal()):
				t.Fatal("took a certificate another key signed")
			case id.PublicKey().Verify(signedBytes(cert), cert.Signature) != nil:
				t.Fatal("took a certificate whose signature is not the identity's over its bytes")
			case bytes.Equal(cert.Key.Marshal(), id.PublicKey().Marshal()):
				t.Fatal("took a certificate of the identity key itself")
			case cert.Key.Type() != ssh.KeyAlgoED25519 || edwardsKeyFault(cert.Key) != "":
				t.Fatalf("took a working key of type %s that is %s", cert.Key.Type(), edwardsKeyFault(cert.Key))
			case unix < cert.ValidAfter || unix >= cert.ValidBefore || cert.ValidBefore > unix+uint64(MaxCertificateLifetime/time.Second):
				t.Fatalf("took a certificate from %d to %d at %d", cert.ValidAfter, cert.ValidBefore, unix)
			}
		}
	})
}

// Examine, and OpenSigned with it, refuses with one of the closed set of
// codes and no message beside it, and always gives Findings. It gives a
// message only with a signature that verifies over the line as it arrived,
// by a working key the identity the envelope carries certified, for this mailbox
// at now, from that identity's address to this mailbox. Findings say who signed
// only when that signature verifies at its certificate's own start.
func FuzzExamine(f *testing.F) {
	now := fuzzNow(f)
	me := fuzzIdentity(f, "b").Address()
	seeds(f, "plain/*.txt", "message/a-to-b.plain")
	codes := []string{RefusedMessage, RefusedEnvelope, RefusedIdentity, RefusedKeyType, RefusedSignature, RefusedAttribution, RefusedStale, RefusedFuture}
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		m, found, err := Examine(plaintext, me, now)
		opened, oerr := OpenSigned(plaintext, me, now)
		if (err == nil) != (oerr == nil) || (m == nil) != (opened == nil) {
			t.Fatalf("Examine says %v, OpenSigned %v", err, oerr)
		}
		if found == nil {
			t.Fatal("no Findings")
		}
		if found.Signed && found.Identity == nil {
			t.Fatal("Findings say signed, by no identity")
		}
		if found.Signed {
			line, sig, _ := splitPlaintext(plaintext)
			id, perr := ParseIdentity(fuzzSender(line))
			if perr != nil || id.Address() != *found.Identity {
				t.Fatalf("Findings say signed by %s, which the envelope carries no document of", found.Identity)
			}
			began, berr := CertificateBegan(sig)
			if _, verr := VerifyCertified(id, line, sig, MessageNamespace(me), began); berr != nil || verr != nil {
				t.Fatalf("Findings say signed, and the signature does not verify at its certificate's start: %v %v", berr, verr)
			}
		}
		if err != nil {
			var refused *EnvelopeError
			if m != nil || !errors.As(err, &refused) || !slices.Contains(codes, refused.Code) {
				t.Fatalf("refused as %v, with %v beside it", err, m)
			}
			return
		}
		line, sig, ok := splitPlaintext(plaintext)
		switch {
		case !ok || !bytes.Equal(m.Line, line) || !bytes.Equal(m.Signature, sig):
			t.Fatal("the message's line or signature is not what arrived")
		case m.Sender.Address() != m.Envelope.From || m.Envelope.To != me || !bytes.Equal(m.Sender.Document(), fuzzSender(line)):
			t.Fatalf("a message from %s to %s, signed by %s", m.Envelope.From, m.Envelope.To, m.Sender.Address())
		case !found.Signed || *found.Identity != m.Sender.Address():
			t.Fatal("a message whose Findings do not say who signed it")
		}
		if _, err := VerifyCertified(m.Sender, line, sig, MessageNamespace(me), now); err != nil {
			t.Fatalf("a message whose signature does not verify: %v", err)
		}
		if cert, err := CheckCertificate(m.Sender, m.Certificate.PublicKey(), now); err != nil || cert.Serial() != m.Certificate.Serial() {
			t.Fatalf("a message under a certificate that does not hold now: %v", err)
		}
	})
}

// fuzzSender is the identity document an envelope's line carries, read as
// envelopeSender reads it, or nil.
func fuzzSender(line []byte) []byte {
	doc, _, err := envelopeSender(line)
	if err != nil {
		return nil
	}
	return doc
}

// VerifyRevocation and VerifyRevokedCertificates, given an address, a
// document, a statement and a signature: each gives a result only for a
// document that is an identity of that address, its SHA-256, whose own key
// signed, in that revocation's namespace, its fixed statement or a
// revocation of certificates in its exact form naming that address; and a
// refusal is ErrRevocation, ErrRevokedCertificates or ErrIdentityType, with
// nothing beside it. An address of any length but 32 bytes is the
// document's SHA-256. The seeds hold, beside the vectors, A's revocation and
// revocation of certificates of B's address, signed by A's identity in B's
// namespaces: all is right in them but the document's hash.
// ParseRevokedCertificates takes a statement only in its exact form, which
// it writes back as it was.
func FuzzRevocationVerifiers(f *testing.F) {
	docs := [][]byte{read(f, "a/identity.doc"), read(f, "c/identity.doc")}
	for _, doc := range docs {
		own := Address(sha512.Sum384(doc))
		for _, p := range []string{"revoke/*.sig", "c/revoke.sig"} {
			m, _ := filepath.Glob(filepath.Join(vectors, p))
			for _, name := range m {
				sig, _ := os.ReadFile(name) //nolint:gosec // a vector of this repo
				f.Add(own[:], doc, RevocationStatement(own), sig)
			}
		}
		m, _ := filepath.Glob(filepath.Join(vectors, "revoked", "*.txt"))
		for _, name := range m {
			st, _ := os.ReadFile(name) //nolint:gosec // a vector of this repo
			sig, _ := os.ReadFile(strings.TrimSuffix(name, ".txt") + ".sig")
			f.Add(own[:], doc, st, sig)
		}
	}
	signerA, _ := vectorKey(f, "a")
	b := Address(sha512.Sum384(read(f, "b/identity.doc")))
	certsOfB, err := NewRevokedCertificates(b, 4)
	if err != nil {
		f.Fatal(err)
	}
	for _, c := range []struct{ statement []byte }{{RevocationStatement(b)}, {certsOfB.Statement()}} {
		ns := RevokeNamespace(b)
		if bytes.HasPrefix(c.statement, []byte(RevokedCertsTag)) {
			ns = RevokedCertsNamespace(b)
		}
		sig, err := Sign(signerA, c.statement, ns)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b[:], read(f, "a/identity.doc"), c.statement, sig)
	}
	f.Fuzz(func(t *testing.T, addr, doc, statement, sig []byte) {
		a := Address(sha512.Sum384(doc))
		if len(addr) == len(a) {
			a = Address(addr)
		}
		hashed := Address(sha512.Sum384(doc)) == a
		id, err := VerifyRevocation(a, doc, sig)
		switch {
		case err == nil && !hashed:
			t.Fatal("a revocation taken with a document that does not hash to its address")
		case err != nil && id != nil:
			t.Fatal("a revocation refused, with an identity beside it")
		case err != nil && !errors.Is(err, ErrRevocation) && !errors.Is(err, ErrIdentityType):
			t.Fatalf("a revocation refused as %v", err)
		case err == nil && (id.Address() != a || Verify(id, RevocationStatement(a), sig, RevokeNamespace(a)) != nil):
			t.Fatal("a revocation taken that its identity did not sign")
		case err == nil && isCertificate(sig):
			t.Fatal("a revocation taken that a working key signed")
		}

		r, err := VerifyRevokedCertificates(a, doc, statement, sig)
		switch {
		case err == nil && !hashed:
			t.Fatal("a revocation of certificates taken with a document that does not hash to its address")
		case err != nil && r != nil:
			t.Fatal("a revocation of certificates refused, with one beside it")
		case err != nil && !errors.Is(err, ErrRevokedCertificates) && !errors.Is(err, ErrIdentityType):
			t.Fatalf("a revocation of certificates refused as %v", err)
		case err == nil && (r.Address != a || !bytes.Equal(r.Statement(), statement) || isCertificate(sig)):
			t.Fatalf("a revocation of certificates taken through %d of %s, from %q", r.Through, r.Address, statement)
		case err == nil:
			id, perr := ParseIdentity(doc)
			if perr != nil || Verify(id, statement, sig, RevokedCertsNamespace(a)) != nil {
				t.Fatal("a revocation of certificates taken that its identity did not sign")
			}
		}

		p, err := ParseRevokedCertificates(statement)
		switch {
		case err != nil && p != nil:
			t.Fatal("a statement refused, with a revocation beside it")
		case err != nil && !errors.Is(err, ErrRevokedCertificates):
			t.Fatalf("a statement refused as %v", err)
		case err == nil && (!bytes.Equal(p.Statement(), statement) || p.Through == 0 || p.Through > MaxSerial):
			t.Fatalf("the statement %q reads as through %d", statement, p.Through)
		}
	})
}

// edwardsKeyFault says what an Ed25519 key is that a protocol key may not
// be, read apart from ParseIdentity's own check: not a point, a point not in
// its canonical encoding, or one of small order, which 8 times itself, by a
// scalar multiplication rather than doublings, makes the identity. It is ""
// for a key that is none of these.
func edwardsKeyFault(key ssh.PublicKey) string {
	crypto, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return "no key"
	}
	raw, ok := crypto.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return "no Ed25519 key"
	}
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return "no point"
	}
	if !bytes.Equal(p.Bytes(), raw) {
		return "not canonically encoded"
	}
	var b [32]byte
	b[0] = 8
	eight, err := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	if new(edwards25519.Point).ScalarMult(eight, p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return "of small order"
	}
	return ""
}

// signedBytes is what a certificate's signature is over: the certificate
// written without its signature, as the format lays it out
// (draft-ietf-sshm-cert-01 §2.1), read apart from the library's check.
func signedBytes(cert *ssh.Certificate) []byte {
	c := *cert
	c.Signature = nil
	out := c.Marshal()
	return out[:len(out)-4] // the signature's length, of none
}

// isCertificate reports whether a signature's key is a certificate, as a
// working key's is.
func isCertificate(sig []byte) bool {
	blob, err := Dearmor(sig)
	if err != nil {
		return false
	}
	var s struct {
		Version   uint32
		PublicKey []byte
		Rest      []byte `ssh:"rest"`
	}
	rest, ok := bytes.CutPrefix(blob, []byte("SSHSIG"))
	if !ok || ssh.Unmarshal(rest, &s) != nil {
		return false
	}
	key, err := ssh.ParsePublicKey(s.PublicKey)
	if err != nil {
		return false
	}
	_, ok = key.(*ssh.Certificate)
	return ok
}

// Unmarshal takes only a JSON text that keeps PROTOCOL.md §3.3's rules, read
// here apart from its own reading: one object and nothing after it, UTF-8
// with no surrogate or noncharacter in a name or a string, no name twice in
// any object, nested at most MaxDepth deep, and no number past binary64. Each
// kind of answer a client reads is tried, and a request as a server reads it.
func FuzzUnmarshal(f *testing.F) {
	seeds(f, "json/*.json", "answer/*.json", "envelope/*.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		kinds := make([]func() any, 0, len(answerTypes)+1)
		for _, k := range answerTypes {
			kinds = append(kinds, k)
		}
		kinds = append(kinds, func() any { return new(ACLDocument) })
		why := independentlyRead(data)
		for _, kind := range kinds {
			for _, request := range []bool{false, true} {
				v := kind()
				parse := Unmarshal
				if request {
					parse = UnmarshalRequest
				}
				if err := parse(data, v); err == nil && why != "" {
					t.Fatalf("%T took a text the protocol does not read: %s", v, why)
				}
			}
		}
	})
}

// ReadStanzas reads a header only as age reads it: it errs, with nothing
// beside it, exactly where age.ExtractHeader does, and otherwise each stanza
// age lists is sorted once: as many native stanzas as age lists of a type a
// prekey has, each of one of those types, and Other only where a stanza age
// lists is neither native nor of grease's type.
func FuzzReadStanzas(f *testing.F) {
	seeds(f, "message/*.age")
	f.Fuzz(func(t *testing.T, ct []byte) {
		st, err := ReadStanzas(ct)
		hdr, herr := age.ExtractHeader(bytes.NewReader(ct))
		if err != nil {
			if st.Native != nil || st.Other {
				t.Fatalf("an error with a result beside it: %+v, %v", st, err)
			}
			if herr == nil {
				var noMatch *age.NoIdentityMatchError
				if _, derr := age.DecryptHeader(hdr, nobody{}); errors.As(derr, &noMatch) {
					t.Fatalf("refused a header age reads: %v", err)
				}
			}
			return
		}
		if herr != nil {
			t.Fatalf("read a header age does not: %v", herr)
		}
		var noMatch *age.NoIdentityMatchError
		if _, derr := age.DecryptHeader(hdr, nobody{}); !errors.As(derr, &noMatch) {
			t.Fatalf("read a header age's decryption does not: %v", derr)
		}
		native, other := 0, false
		for _, typ := range noMatch.StanzaTypes {
			switch {
			case typ == string(PostQuantum):
				native++
			case !grease.MatchString(typ):
				other = true
			}
		}
		if len(st.Native) != native || other && !st.Other {
			t.Fatalf("age lists %q; read as %+v", noMatch.StanzaTypes, st)
		}
		for _, k := range st.Native {
			if k != PostQuantum {
				t.Fatalf("a native stanza of type %q", k)
			}
		}
	})
}

// nobody is an age identity that matches no stanza.
type nobody struct{}

func (nobody) Unwrap([]*age.Stanza) ([]byte, error) { return nil, age.ErrIncorrectIdentity }

// isRefusal reports whether err is an EnvelopeError with that code.
func isRefusal(err error, code string) bool {
	var e *EnvelopeError
	return errors.As(err, &e) && e.Code == code
}

// independentlyRead holds a text to PROTOCOL.md §3.3's rules apart from this
// package's own check, by jsontext's tokens, and says which it breaks, or ""
// for none.
func independentlyRead(data []byte) string {
	if !utf8.Valid(data) {
		return "not UTF-8"
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return "a byte-order mark"
	}
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	depth, first, done := 0, true, false
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "not one JSON value as jsontext reads one: " + err.Error()
		}
		switch {
		case done:
			return "a second value after the object"
		case first && tok.Kind() != '{':
			return "not an object"
		}
		first = false
		switch tok.Kind() {
		case '{', '[':
			if depth++; depth > MaxDepth {
				return "nested past MaxDepth"
			}
		case '}', ']':
			depth--
			done = depth == 0
		case '"':
			for _, r := range tok.String() {
				if r >= 0xD800 && r <= 0xDFFF || r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE {
					return "a surrogate or a noncharacter"
				}
			}
		case '0':
			if _, err := strconv.ParseFloat(tok.String(), 64); err != nil {
				return "a number past binary64"
			}
		}
	}
	if first {
		return "empty"
	}
	return ""
}
