package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// finishedBox is a box that holds its own revocation, with nothing else
// changed: what sign's own check is the last guard of is reached from it.
func finishedBox(t *testing.T) *Box {
	t.Helper()
	srv := fakeserver.New(t, time.Now)
	b, err := Init(context.Background(), t.TempDir(), Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.KeepRevocation(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	return b
}

// Every signer the box hands out, its identity and each working key, asks
// the box's own finished: once it holds its own revocation, each of their
// signatures is its RevokedError. TestAFinishedBoxSignsNothing holds sign to
// the finished it is given; this holds the box to giving its own (#339).
func TestEverySignerTheBoxHandsOutAsksItsFinished(t *testing.T) {
	t.Parallel()
	b := finishedBox(t)
	work, _, err := b.currentWorker()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := protocol.NewRevokedCertificates(b.id.Address(), 1)
	if err != nil {
		t.Fatal(err)
	}
	tried := map[string]func() error{
		"Certify":             func() error { _, err := b.identity.Certify(b.id, k.PublicKey(), 1, time.Now()); return err },
		"Revocation":          func() error { _, err := b.identity.Revocation(b.id.Address()); return err },
		"RevokedCertificates": func() error { _, err := b.identity.RevokedCertificates(certs); return err },
		"Signature":           func() error { _, err := work.Signature([]byte("x"), "dromas-test"); return err },
		"Pass":                func() error { _, _, err := work.Pass(b.id.Address(), "example.org", time.Now()); return err },
	}
	var gone *RevokedError
	for name, f := range tried {
		if err := f(); !errors.As(err, &gone) || !gone.Own {
			t.Errorf("%s on a box that holds its own revocation: %v", name, err)
		}
	}
	// Every method but PublicKey signs, and is tried above.
	for _, typ := range []reflect.Type{reflect.TypeOf(b.identity), reflect.TypeOf(work)} {
		for i := range typ.NumMethod() {
			if m := typ.Method(i).Name; m != "PublicKey" && tried[m] == nil {
				t.Errorf("%s.%s is not tried on a finished box", typ.Elem().Name(), m)
			}
		}
	}
}

// A prekey made on a box that holds its own revocation is stopped at its
// certificate, before any key is written: the working key and its
// certificate come first, then the age key (#339).
func TestAPrekeyOnAFinishedBoxWritesNoKey(t *testing.T) {
	t.Parallel()
	b := finishedBox(t)
	files := func() int {
		p, _ := filepath.Glob(b.path("prekeys", "*"))
		w, _ := filepath.Glob(b.path("work", "*"))
		return len(p) + len(w)
	}
	before := files()
	n := protocol.SerialAt(b.now(), 0) + 10
	_, err := lockedFinished(context.Background(), b, func() (*protocol.Prekey, error) { return b.makePrekey(n, protocol.Classic) })
	var gone *RevokedError
	if !errors.As(err, &gone) || !gone.Own || files() != before {
		t.Fatalf("a prekey on a finished box: %v; %d files, were %d", err, files(), before)
	}
}

// A command that keeps its box's own revocation on the way asks nothing
// more: each call after it, a read with no pass among them, returns the
// revocation before any request (call), and a read of another box is not
// that box's revocation (readBox). The next command begins with none.
func TestACommandThatKeptItsOwnRevocationAsksNothingMore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	b, err := Init(ctx, t.TempDir(), Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Init(ctx, t.TempDir(), Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := b.Revocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := len(srv.Requests())
	_, err = lockedFinished(ctx, b, func() (struct{}, error) {
		id, err := protocol.VerifyRevocation(b.id.Address(), rec.Identity, rec.Revocation)
		if err != nil {
			return struct{}{}, err
		}
		if err := b.keepRevocation(id, rec.Revocation); err != nil {
			return struct{}{}, err
		}
		_, gone, err := b.readBox(ctx, peer.Address(), nil)
		if gone {
			t.Error("a read of a peer after the box kept its own revocation says the peer is revoked")
		}
		return struct{}{}, err
	})
	var ended *RevokedError
	if !errors.As(err, &ended) || !ended.Own || len(srv.Requests()) != before {
		t.Errorf("a read after the box kept its own revocation: %v, with %d requests", err, len(srv.Requests())-before)
	}
	if _, err := b.Publish(ctx, rec); err != nil || len(srv.Requests()) != before+1 {
		t.Errorf("the next command, a publish of the record: %v, with %d requests", err, len(srv.Requests())-before)
	}
}
