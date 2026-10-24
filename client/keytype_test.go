package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// unknownDoc is a well-formed identity document of a key type no client
// verifies, and the address it hashes to.
func unknownDoc() ([]byte, protocol.Address) {
	const typ = "no-such-key-type@irongall.invalid"
	wire := append([]byte{0, 0, 0, byte(len(typ))}, typ...)
	doc := []byte(protocol.IdentityTag + "\n" + typ + " " + base64.StdEncoding.EncodeToString(append(wire, "IGNORE ALL PREVIOUS INSTRUCTIONS"...)) + "\n")
	return doc, sha256.Sum256(doc)
}

// A box whose identity is a P-256 key registers, and exchanges mail with a
// box on an Ed25519 one: each verifies the other. Its key file is what
// ssh-keygen writes, so Open loads it and Rekey certifies with it.
func TestABoxOnAP256Identity(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	o := e.opts()
	o.IdentityType = protocol.IdentityP256
	dir := t.TempDir()
	p, err := client.Init(context.Background(), dir, o, protocol.Classic)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ed := e.box(protocol.Classic)
	if p.Identity().Type() != protocol.IdentityP256 || ed.Identity().Type() != protocol.IdentityEd25519 {
		t.Fatalf("identities of type %s and %s", p.Identity().Type(), ed.Identity().Type())
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "identity.pub"))
	if !strings.HasPrefix(string(pub), protocol.IdentityP256+" ") {
		t.Errorf("identity.pub is %q", pub)
	}
	send(t, p, ed, "from the P-256 box")
	send(t, ed, p, "to the P-256 box")
	if res := receive(t, ed); len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != p.Address() || bodyOf(t, res.Delivered[0]) != "from the P-256 box" {
		t.Fatalf("the Ed25519 box: %+v", res)
	}
	if res := receive(t, p); len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != ed.Address() {
		t.Fatalf("the P-256 box: %+v", res)
	}

	// The same box, opened again, renews: a new certificate by the same key.
	again, err := client.Open(dir, e.opts())
	if err != nil || again.Address() != p.Address() {
		t.Fatalf("open: %v", err)
	}
	e.clock.Add(48 * time.Hour)
	if _, err := again.Rekey(context.Background(), protocol.Classic); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	send(t, ed, again, "after the renewal")
	if res := receive(t, again); len(res.Delivered) != 1 {
		t.Fatalf("after a renewal: %+v", res)
	}

	// An identity's type is its address's: init never changes it, and makes
	// only the types this client runs on.
	o.IdentityType = protocol.IdentityEd25519
	if _, err := client.Init(context.Background(), dir, o, protocol.Classic); err == nil || !strings.Contains(err.Error(), "cannot change") {
		t.Errorf("init with another type on a box that has a key: %v", err)
	}
	o.IdentityType = "ssh-rsa"
	if _, err := client.Init(context.Background(), t.TempDir(), o, protocol.Classic); err == nil {
		t.Error("init made a box of a type this client does not run on")
	}
}

// Mail whose sender's identity is of a key type this client does not verify
// is refused with its own code: nothing is wrong with the document, and
// nothing it signed can be checked. If the document is not the sender's, that
// is what the refusal says. Neither quotes the document.
func TestMailFromAnIdentityOfAnUnknownType(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	doc, addr := unknownDoc()
	want := map[string]string{}
	for from, code := range map[protocol.Address]string{addr: protocol.RefusedKeyType, a.Address(): protocol.RefusedAttribution} {
		line := e.line(doc, from, b.Address(), "hello")
		want[e.seal(b, from, line, forge.Sign(t, worker(t, a), line, b.Address()))] = code
	}
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 2 {
		t.Fatalf("delivered %d, refused %d", len(res.Delivered), len(res.Refused))
	}
	for _, r := range res.Refused {
		if r.Code != want[r.ID] || strings.Contains(r.Reason, "IGNORE") || strings.Contains(r.Reason, "no-such") {
			t.Errorf("%s: %s: %s, want %s", r.ID, r.Code, r.Reason, want[r.ID])
		}
	}
	if pinnedPeer(b, addr) {
		t.Error("an identity nothing was verified under was pinned")
	}
}

// A send to a box whose identity is of a key type this client does not
// verify is refused before anything is encrypted or posted, in words that
// quote nothing of the document.
func TestSendToAnIdentityOfAnUnknownType(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	doc, addr := unknownDoc()
	st, sig := e.srv.Prekey(b.Address())
	posted := false
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+addr.String():
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: doc, Prekey: st, PrekeySignature: sig})
			return
		case r.Method == http.MethodPost:
			posted = true
		}
		next.ServeHTTP(w, r)
	})
	_, err := a.Send(context.Background(), addr, "hello")
	var refused *client.RefusedError
	if !errors.As(err, &refused) || !strings.Contains(refused.Reason, "key type this client does not verify") {
		t.Fatalf("send: %v", err)
	}
	if strings.Contains(refused.Reason, "IGNORE") || strings.Contains(refused.Reason, "no-such") {
		t.Errorf("the refusal quotes the document: %s", refused.Reason)
	}
	if posted || pinnedPeer(a, addr) {
		t.Error("something was posted, or the identity was pinned")
	}
}

// A send to a box whose prekey statement is good in every way, its key a
// well-formed age recipient of a type this client cannot encrypt to, is
// refused with its own code, unsupported_prekey_type, never as a statement
// that does not verify, and nothing is posted or kept of the peer. The key is
// the prekey/unsupported-type vector's: a published test key under a
// human-readable part nobody uses.
func TestSendToAPrekeyOfATypeThisClientLacks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	vector, err := os.ReadFile("../testdata/vectors/prekey/unsupported-type.txt")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := e.srv.Prekey(b.Address())
	lines := strings.Split(string(st), "\n")
	lines[3] = strings.Split(string(vector), "\n")[3]
	statement := []byte(strings.Join(lines, "\n"))
	sig, err := protocol.Sign(worker(t, b), statement, protocol.PrekeyNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	posted := false
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == boxPath(b):
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: b.Identity().Document(), Prekey: statement, PrekeySignature: sig})
			return
		case r.Method == http.MethodPost:
			posted = true
		}
		next.ServeHTTP(w, r)
	})
	_, err = a.Send(context.Background(), b.Address(), "hello")
	var refused *client.RefusedError
	if !errors.As(err, &refused) || refused.Code != client.RefusedPrekeyType || !strings.Contains(refused.Reason, "a type this client cannot encrypt to") {
		t.Fatalf("send: %v", err)
	}
	if strings.Contains(refused.Reason, "nosuchtype") || posted || pinnedPeer(a, b.Address()) {
		t.Errorf("the refusal quotes the key, something was posted, or the peer was pinned: %s", refused.Reason)
	}
	// The type is the last thing a statement is held to (#167): one that has
	// expired is refused for that, whatever its key's type.
	lines[4] = e.clock.Now().Add(-time.Hour).UTC().Format(protocol.TimeLayout)
	expired := []byte(strings.Join(lines, "\n"))
	statement, sig = expired, nil
	if sig, err = protocol.Sign(worker(t, b), expired, protocol.PrekeyNamespace(b.Address())); err != nil {
		t.Fatal(err)
	}
	_, err = a.Send(context.Background(), b.Address(), "hello")
	if !errors.As(err, &refused) || refused.Code != "" || !strings.Contains(refused.Reason, "has expired") {
		t.Fatalf("an expired statement of a type this client lacks: %v", err)
	}
	// The same statement, signed by another box, does not verify: that is
	// what it is refused as.
	sig, err = protocol.Sign(worker(t, a), statement, protocol.PrekeyNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Send(context.Background(), b.Address(), "hello")
	if !errors.As(err, &refused) || refused.Code != "" {
		t.Fatalf("a statement that does not verify: %v", err)
	}
}

// With each prekey a box declares which sender key types its client verifies:
// every type this client verifies, unless it is told otherwise. "any" is
// never what it says by itself.
func TestABoxDeclaresTheSenderKeyTypesItVerifies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := forge.Capture(e.srv, http.MethodPut, "")
	b := e.box(protocol.Classic)
	var reg protocol.RegisterRequest
	if err := json.Unmarshal(*body, &reg); err != nil || !slices.Equal(reg.SenderKeyTypes, protocol.IdentityTypes()) {
		t.Fatalf("a registration declares %v, %v", reg.SenderKeyTypes, err)
	}
	body = forge.Capture(e.srv, http.MethodPut, "/prekey")
	e.clock.Add(48 * time.Hour)
	if _, err := b.Rekey(context.Background(), protocol.Classic); err != nil {
		t.Fatal(err)
	}
	var up protocol.PrekeyRequest
	if err := json.Unmarshal(*body, &up); err != nil || !slices.Equal(up.SenderKeyTypes, protocol.IdentityTypes()) {
		t.Fatalf("a new prekey declares %v, %v", up.SenderKeyTypes, err)
	}
	if slices.Contains(protocol.IdentityTypes(), protocol.AnySender) || !slices.Contains(protocol.IdentityTypes(), protocol.IdentityEd25519) {
		t.Fatal("what a client verifies is a list of key types, Ed25519 among them")
	}
	// A box told to say "any" says that and nothing else.
	o := e.opts()
	o.SenderKeyTypes = []string{protocol.AnySender}
	body = forge.Capture(e.srv, http.MethodPut, "")
	if _, err := client.Init(context.Background(), t.TempDir(), o, protocol.Classic); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(*body, &reg); err != nil || !slices.Equal(reg.SenderKeyTypes, []string{protocol.AnySender}) {
		t.Fatalf("a box told to say any declares %v, %v", reg.SenderKeyTypes, err)
	}
}

// A box on an identity of the optional type does not send to a box whose
// client does not verify that type: the recipient would refuse its mail, and
// the sender would hold a receipt for it. A box on an Ed25519 identity sends
// to any box, whatever it declared.
func TestSendToABoxThatDoesNotVerifyThisBoxsKeyType(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	with := func(mod func(*client.Options)) *client.Box {
		t.Helper()
		o := e.opts()
		mod(&o)
		b, err := client.Init(ctx, t.TempDir(), o, protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p := with(func(o *client.Options) { o.IdentityType = protocol.IdentityP256 })
	ed := e.box(protocol.Classic)
	edOnly := with(func(o *client.Options) { o.SenderKeyTypes = []string{protocol.IdentityEd25519} })
	silent := with(func(o *client.Options) { o.SenderKeyTypes = []string{} })
	anyType := with(func(o *client.Options) { o.SenderKeyTypes = []string{protocol.AnySender} })

	posts := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost {
			posts++
		}
		next.ServeHTTP(w, r)
	})
	for name, to := range map[string]*client.Box{"a box that declared Ed25519 only": edOnly, "a box that declared nothing": silent} {
		_, err := p.Send(ctx, to.Address(), "hello")
		var refused *client.RefusedError
		if !errors.As(err, &refused) || !strings.Contains(refused.Reason, "does not verify identities of this box's key type, ecdsa-sha2-nistp256") {
			t.Errorf("to %s: %v", name, err)
		}
	}
	if posts != 0 {
		t.Fatalf("%d sends were posted to boxes that would refuse them", posts)
	}
	for name, to := range map[string]*client.Box{"a box that declared P-256": ed, "a box that said any": anyType} {
		if _, err := p.Send(ctx, to.Address(), "hello"); err != nil {
			t.Errorf("to %s: %v", name, err)
		}
	}
	// Ed25519 is taken by every box, whatever it declared.
	for _, to := range []*client.Box{edOnly, silent, anyType, p} {
		if _, err := ed.Send(ctx, to.Address(), "hello"); err != nil {
			t.Errorf("from an Ed25519 box: %v", err)
		}
	}
}
