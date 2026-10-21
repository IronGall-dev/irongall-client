package client_test

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// What a box does with its own revocations: a renewal asks for them every
// time, a box that holds its own revocation of its address signs nothing
// more, a certificate it revoked signs no mail, the remedy reads once and
// goes on past a server it cannot use, and a clock far ahead deletes no key
// that mail waits for.

// ownRevocation signs a revocation of a's certificates through serial T with
// its identity.
func ownRevocation(t *testing.T, a *client.Box, T uint64) *protocol.Revocations {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := protocol.NewRevokedCertificates(a.Address(), T)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(id, certs)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: a.Identity().Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
}

// publishAt publishes rec at base alone, as another machine of the box's
// identity would: the box itself keeps nothing.
func publishAt(t *testing.T, base string, rec *protocol.Revocations) {
	t.Helper()
	if _, err := client.Publish(context.Background(), client.Options{Base: base}, rec); err != nil {
		t.Fatal(err)
	}
}

// A revocation of the box's certificates that its server holds and the box
// does not, through a serial far past its clock (a slipped digit, or a
// remedy on another machine): the renewal reads it from its server's answer
// and numbers above it at the first attempt.
func TestARenewalNumbersAboveARevocationItDidNotHold(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	x := numberOf(t, a) + 10*365*86400
	publishAt(t, e.srv.URL, ownRevocation(t, a, x))
	e.clock.Add(time.Minute)
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatalf("the renewal after a revocation through %d it did not hold: %v", x, err)
	}
	if n := numberOf(t, a); n <= x {
		t.Errorf("renewed at %d, at or below the revocation through %d", n, x)
	}
}

// The remedy on a clock three hours fast revokes through a serial that far
// ahead. The box restored from its identity on a machine whose clock is
// right holds no such revocation: its first renewal asks, and is taken.
func TestARestoredBoxRenewsAboveAFastRemedy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	o := e.opts()
	o.Now = func() time.Time { return e.clock.Now().Add(3 * time.Hour) }
	fast, err := client.Open(a.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	r, err := fast.RenewAndRevoke(ctx, "")
	if r == nil || r.Revoked == nil {
		t.Fatalf("the remedy 3 h ahead: %+v, %v", r, err)
	}
	restored := restoreWith(t, e, a, e.clock.Now)
	e.clock.Add(time.Minute)
	if _, err := restored.Rekey(ctx, ""); err != nil {
		t.Fatalf("the restored box's first renewal: %v", err)
	}
	if n := numberOf(t, restored); n <= r.Revoked.Through {
		t.Errorf("the restored box renewed at %d, under the revocation through %d", n, r.Revoked.Through)
	}
}

// Its own server failing only the read of the box: the remedy revokes and
// renews there all the same.
func TestTheRemedyGoesOnWhenItsServerDoesNotAnswerTheRead(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	inUse := numberOf(t, a)
	reads := 0
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(a) && reads == 0 {
			reads++
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Unread == nil || r.Prekey == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) {
		t.Fatalf("the remedy past an unanswered read: %+v, %v", r, err)
	}
	if !heldCertsOf(t, e, a).Revokes(inUse) || numberOf(t, a) != r.Below {
		t.Errorf("the server holds %+v, the box is at %d, the remedy made %d", heldCertsOf(t, e, a), numberOf(t, a), r.Below)
	}
}

// Its own server serves a statement ordered before what the box published (a
// rollback): a plain renewal refuses, and the remedy goes on.
func TestTheRemedyGoesOnPastARollback(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	first := numberOf(t, a)
	old, oldSig := statement(t, a, first, ".txt"), statement(t, a, first, ".txt.sig")
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	inUse := numberOf(t, a)
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(a) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: a.Identity().Document(), Prekey: old, PrekeySignature: oldSig})
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx, ""); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("a plain renewal served a rollback: %v", err)
	}
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Unread == nil || !strings.Contains(r.Unread.Error(), "rollback") || r.Revoked == nil || !r.Revoked.Revokes(inUse) || r.NotRenewed != nil {
		t.Fatalf("the remedy served a rollback: %+v, %v", r, err)
	}
}

// The box's own server holds a revocation through T and leaves it out of its
// first read of the box, then answers the remedy's record conflict: the
// remedy reads again, keeps T's, which covers more than its own, publishes
// nothing more, and numbers above T (PROTOCOL.md §6.3a).
func TestTheRemedyAsksAgainAfterItsServerAnswersConflict(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	T := numberOf(t, a) + 7200
	publishAt(t, e.srv.URL, ownRevocation(t, a, T))
	reads, puts := 0, 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/revocations") {
			puts++
		}
		if r.Method == http.MethodGet && r.URL.Path == boxPath(a) && reads == 0 {
			reads++
			e.serve(w, r, next, func(b *protocol.BoxResponse) { b.RevokedCertificates, b.RevokedCertificatesSignature = nil, nil })
			return
		}
		next.ServeHTTP(w, r)
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Revoked == nil || r.Revoked.Through != T || r.NotRevoked != nil || r.Below != T+1 || r.Prekey == nil || puts != 1 {
		t.Fatalf("the remedy, T %d hidden from the first read: %+v, %v, %d publishes", T, r, err, puts)
	}
}

// A conflict whose server shows no revocation that verifies, at either read,
// stops the remedy: nothing is published again and nothing is renewed, since
// a renewal under a certificate the server holds revoked would be refused.
func TestTheRemedyStopsAtAConflictThatShowsNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	publishAt(t, e.srv.URL, ownRevocation(t, a, numberOf(t, a)+7200))
	var puts, renewals atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/revocations"):
			puts.Add(1)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey"):
			renewals.Add(1)
		case r.Method == http.MethodGet && r.URL.Path == boxPath(a):
			e.serve(w, r, next, func(b *protocol.BoxResponse) { b.RevokedCertificates, b.RevokedCertificatesSignature = nil, nil })
			return
		}
		next.ServeHTTP(w, r)
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || client.Code(r.NotRevoked) != protocol.CodeConflict || r.NotRenewed == nil || r.Prekey != nil || puts.Load() != 1 || renewals.Load() != 0 {
		t.Fatalf("the remedy at a conflict that shows nothing: %+v, %v; %d publishes, %d renewals", r, err, puts.Load(), renewals.Load())
	}
}

// One remedy reads its server's box once: the read carries both the
// statement it serves and what it holds of the box's revocations.
func TestTheRemedyReadsItsBoxOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	var reads atomic.Int32
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(a) {
			reads.Add(1)
		}
		return false
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Revoked == nil || r.Prekey == nil {
		t.Fatalf("the remedy: %+v, %v", r, err)
	}
	if reads.Load() != 1 {
		t.Errorf("the box's own read %d times", reads.Load())
	}
}

// command is one of a box's commands, by its method's name.
type command struct {
	name string
	f    func() error
}

// finishedCommands are every exported command that takes the box's lock,
// as a box that holds its own revocation runs them: those that would ask a
// server or carry a pass, which are refused, and those that still run.
// TestEveryLockingCommandIsTriedFinished holds the two lists to the code.
func finishedCommands(ctx context.Context, a, b *client.Box, rec *protocol.Revocations) (refused, run []command) {
	refused = []command{
		{"Adopt", func() error { _, err := a.Adopt(ctx, "key"); return err }},
		{"Leave", func() error { return a.Leave(ctx) }},
		{"Resolve", func() error { _, err := a.Resolve(ctx, b.Address()); return err }},
		{"Receive", func() error { _, err := a.Receive(ctx); return err }},
		{"Rekey", func() error { _, err := a.Rekey(ctx, ""); return err }},
		{"RevokeEarlier", func() error { _, err := a.RevokeEarlier(ctx); return err }},
		{"RenewAndRevoke", func() error { _, err := a.RenewAndRevoke(ctx, ""); return err }},
		{"SendWith", func() error {
			_, err := a.SendWith(ctx, b.Address(), "from a finished box", client.Fields{})
			return err
		}},
		{"SendJSON", func() error {
			_, err := a.SendJSON(ctx, b.Address(), []byte(`{"from":"a finished box"}`), client.Fields{})
			return err
		}},
		{"Allow", func() error { _, err := a.Allow(ctx, b.Address()); return err }},
		{"Block", func() error { _, err := a.Block(ctx, b.Address()); return err }},
		{"SyncACL", func() error { return a.SyncACL(ctx) }},
	}
	run = []command{
		{"Ask", func() error { _, err := a.Ask(ctx, a.Address()); return err }},
		{"KeepRevocation", func() error { _, _, err := a.KeepRevocation(rec); return err }},
		{"Publish", func() error { _, err := a.Publish(ctx, rec); return err }},
		{"Flush", func() error { _, err := a.Flush(ctx); return err }},
		{"SetAlias", func() error { return a.SetAlias("peer", b.Address()) }},
		{"RemoveAlias", func() error { return a.RemoveAlias("peer") }},
		{"RemoveQuarantined", func() error { _, err := a.RemoveQuarantined(ctx, nil); return err }},
		{"SetPolicy", func() error { return a.SetPolicy(client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}) }},
		{"RebuildAllowed", func() error { _, err := a.RebuildAllowed(); return err }},
		{"SetPrekeyLifetime", func() error { return a.SetPrekeyLifetime(ctx, protocol.PrekeyLifetime) }},
	}
	return refused, run
}

// signed is what the box's keys have signed: its working keys, certificates
// and prekey statements, and the pass it keeps.
func signed(t *testing.T, a *client.Box) []string {
	t.Helper()
	var names []string
	for _, d := range []string{"work", "prekeys"} {
		es, err := os.ReadDir(filepath.Join(a.Dir(), d))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			names = append(names, d+"/"+e.Name())
		}
	}
	if has(a, "pass") {
		names = append(names, "pass")
	}
	return names
}

// A box that holds its own revocation is finished (PROTOCOL.md §6.3). Every
// command that would ask a server or carry a pass is refused, with the box's
// own RevokedError, before anything is asked. None of them signs anything,
// by any path, and the pass the box kept is gone. A send writes nothing, and
// a flush moves what waits to outbox/failed/. What carries no pass still
// goes: asking about and keeping a revocation, the record (the one the box
// holds) published again, and a change to the box's own files alone. No
// call in all of it carries a pass.
func TestABoxThatKeepsItsOwnRevocationSignsNothingMore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, b, a, "to a box about to be finished")
	says(e, protocol.CodeUnavailable, http.MethodPost, "/messages")
	if _, err := a.Send(ctx, b.Address(), "waits in the outbox"); err == nil {
		t.Fatal("a send was taken by a server that is down")
	}
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	says(e, protocol.CodeUnavailable, http.MethodPut, "/revocations")
	if _, err := a.Revoke(ctx, rec); err == nil {
		t.Fatal("the revocation was taken by a server that is down")
	}
	e.srv.SetMiddle(nil)
	if _, _, err := a.KeepRevocation(rec); err != nil { // as revocation publish does once any server took it
		t.Fatal(err)
	}
	if st, err := a.Status(); err != nil || !st.Revoked {
		t.Fatalf("status: %+v, %v", st, err)
	}
	before := signed(t, a)
	if slices.Contains(before, "pass") {
		t.Error("the pass the box kept outlives its own revocation")
	}
	var calls, passes atomic.Int32
	watch(e, func(_ http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			passes.Add(1)
		}
		return false
	})
	refused, run := finishedCommands(ctx, a, b, rec)
	var gone *client.RevokedError
	for _, c := range refused {
		name, f := c.name, c.f
		calls.Store(0)
		e.clock.Add(2 * time.Second)
		if err := f(); !errors.As(err, &gone) || !gone.Own || calls.Load() != 0 {
			t.Errorf("%s: %v, with %d calls to the server", name, err, calls.Load())
		}
	}
	if waiting, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P")); len(waiting) != 1 {
		t.Errorf("%d entries in the outbox, want the one that waited: a send writes nothing", len(waiting))
	}
	for _, c := range run {
		name, f := c.name, c.f
		calls.Store(0)
		err := f()
		if name == "Flush" {
			if !errors.As(err, &gone) || !gone.Own || calls.Load() != 0 {
				t.Errorf("a flush: %v, with %d calls to the server", err, calls.Load())
			}
			continue
		}
		if err != nil || name != "Ask" && name != "Publish" && calls.Load() != 0 {
			t.Errorf("%s: %v, with %d calls to the server", name, err, calls.Load())
		}
	}
	if waiting, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P")); len(waiting) != 0 {
		t.Errorf("%d entries left in the outbox", len(waiting))
	}
	if failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", "*.P")); len(failed) != 1 {
		t.Errorf("%d entries in outbox/failed/, want the one it can never deliver", len(failed))
	}
	if again, err := a.Revocation(); err != nil || !bytes.Equal(again.Revocation, rec.Revocation) {
		t.Errorf("the record of a finished box: %v, not the one it holds", err)
	}
	if _, err := a.Revoke(ctx, rec); err != nil { // published again: its server takes it
		t.Errorf("published again: %v", err)
	}
	if after := signed(t, a); !slices.Equal(after, before) {
		t.Errorf("signed while finished: %v, then %v", before, after)
	}
	if passes.Load() != 0 {
		t.Errorf("%d calls of a finished box carried a pass", passes.Load())
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Errorf("its reader delivered %d", len(res.Delivered))
	}
}

// Every exported command that takes the box's lock is one of
// finishedCommands', so a new one is tried on a finished box too.
func TestEveryLockingCommandIsTriedFinished(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	refused, run := finishedCommands(context.Background(), nil, nil, nil)
	tried := func(name string) bool {
		return slices.ContainsFunc(append(refused, run...), func(c command) bool { return c.name == name })
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || fn.Body == nil {
				continue
			}
			if takesTheLock(fn.Body) && !tried(fn.Name.Name) {
				t.Errorf("%s takes the box's lock and is not tried on a finished box: add it to finishedCommands", fn.Name.Name)
			}
		}
	}
}

// takesTheLock reports whether body calls one of the functions that take
// the box's lock.
func takesTheLock(body *ast.BlockStmt) bool {
	takes := false
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch x := c.Fun.(type) {
		case *ast.Ident:
			name = x.Name
		case *ast.SelectorExpr:
			name = x.Sel.Name
		case *ast.IndexExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				name = id.Name
			}
		}
		takes = takes || slices.Contains([]string{"locked", "lockedFinished", "lockedDo", "lockedFinishedDo"}, name)
		return true
	})
	return takes
}

// The renewal's own read is what shows the box its address revoked: its
// server holds the revocation, published from elsewhere, and the box does
// not. The box keeps the revocation and signs nothing more, this renewal
// included, the revocation learned inside the command: no certificate and no
// prekey statement, and no key made for one (#227).
func TestARenewalThatMeetsItsOwnRevocationSignsNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	publishAt(t, e.srv.URL, rec) // as another machine of the box's owner would
	before, number, begun := signed(t, a), numberOf(t, a), begunAt(t, a)
	e.clock.Add(2 * time.Second)
	_, err = a.Rekey(ctx, "")
	if st, serr := a.Status(); serr != nil || !st.Revoked {
		t.Fatalf("the box did not keep its own revocation: %+v, %v", st, serr)
	}
	var gone *client.RevokedError
	if !errors.As(err, &gone) || !gone.Own || numberOf(t, a) != number || begunAt(t, a) != begun || !slices.Equal(signed(t, a), slices.DeleteFunc(before, func(n string) bool { return n == "pass" })) {
		t.Errorf("a renewal that met its own revocation: %v; serial %d -> %d; a prekey begun at %d -> %d; signed %v -> %v", err, number, numberOf(t, a), begun, begunAt(t, a), before, signed(t, a))
	}
}

// A box restored from its identity alone, whose owner kept its revocation
// record, runs init: it signs nothing, no certificate and no prekey
// statement, and calls no server (#256).
func TestInitOfABoxThatHoldsItsOwnRevocationSignsNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := client.Open(dir, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.KeepRevocation(rec); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	watch(e, func(http.ResponseWriter, *http.Request) bool {
		calls.Add(1)
		return false
	})
	_, err = client.Init(ctx, dir, e.opts(), protocol.Classic)
	made, _ := filepath.Glob(filepath.Join(dir, "work", "*"))
	stmts, _ := filepath.Glob(filepath.Join(dir, "prekeys", "*"))
	var gone *client.RevokedError
	if !errors.As(err, &gone) || !gone.Own || calls.Load() != 0 || len(made) != 0 || len(stmts) != 0 {
		t.Errorf("init of a box that holds its own revocation: %v; %d requests; it made %v and %v", err, calls.Load(), made, stmts)
	}
}

// A box whose revocation its own server holds, opened against a server that
// never saw it: it registers nothing there and sends nothing.
func TestABoxRevokedAtItsServerSignsNothingAtAnother(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Revoke(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.KeepRevocation(rec); err != nil {
		t.Fatal(err)
	}
	other := fakeserver.New(t, e.clock.Now)
	o := e.opts()
	o.Base = other.URL
	elsewhere, err := client.Open(a.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	var gone *client.RevokedError
	if _, err := elsewhere.Rekey(ctx, ""); !errors.As(err, &gone) {
		t.Fatalf("a renewal at a server that never saw the revocation: %v", err)
	}
	c, err := client.Init(ctx, t.TempDir(), client.Options{Base: other.URL, Now: e.clock.Now}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := elsewhere.Send(ctx, c.Address(), "from a revoked address"); !errors.As(err, &gone) {
		t.Errorf("a send there: %v", err)
	}
}

// After the remedy, while its renewal waits, the box holds the certificate it
// signs under revoked: it signs no mail under it, the entry waits, and goes
// once the renewal is taken, whatever its server took. Here the server
// answered the revocation as taken and kept nothing, so it would take the
// box's pass and mail under that certificate still, and was down for the
// renewal: only the box's own hold keeps the mail back.
func TestASendInTheRemedysWindowWaitsForTheRenewal(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, reader := e.box(protocol.Classic), e.box(protocol.Classic)
	inUse := numberOf(t, a)
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == boxPath(a)+"/revocations":
			fakeserver.WriteJSON(w, http.StatusOK, struct{}{})
			return true
		case r.Method == http.MethodPut && r.URL.Path == boxPath(a)+"/prekey":
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if r == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) || r.NotRenewed == nil {
		t.Fatalf("remedy: %+v %v", r, err)
	}
	e.srv.SetMiddle(nil)
	if s, err := a.Send(ctx, reader.Address(), "sent in the remedy's window"); s != nil || err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("a send in the window: %+v, %v", s, err)
	}
	if res := receive(t, reader); len(res.Delivered)+len(res.Refused) != 0 {
		t.Fatalf("its reader got %d and refused %d", len(res.Delivered), len(res.Refused))
	}
	if _, err := a.Receive(ctx); err != nil {
		t.Fatalf("the drain that sends the waiting renewal: %v", err)
	}
	if _, err := a.Flush(ctx); err != nil {
		t.Fatalf("the flush after it: %v", err)
	}
	if res := receive(t, reader); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Errorf("its reader delivered %d and refused %d", len(res.Delivered), len(res.Refused))
	}
}

// A clock far ahead is stopped at its pass, and deletes no key that mail
// waits for: here the mail was sealed to a prekey retired since, and the
// drain at a clock 70 days ahead is refused before its list.
func TestAFastClockDeletesNoKeyMailWaitsFor(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "sealed to the prekey about to retire")
	e.clock.Add(2 * time.Second)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	keys, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	off := 70 * 24 * time.Hour
	fast, err := client.Open(b.Dir(), e.skewed(&off))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fast.Receive(ctx); err == nil {
		t.Fatal("a drain at a clock 70 days ahead went through")
	}
	if after, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey")); len(after) < len(keys) {
		t.Fatalf("%d prekeys before the drain at a fast clock, %d after", len(keys), len(after))
	}
	off = 0
	res, err := fast.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Errorf("once the clock is right: %v, delivered %d, refused %d", err, len(res.Delivered), len(res.Refused))
	}
}

// A record that carries the address's revocation beside a revocation of its
// certificates through a lower serial than the one held: the address's is
// kept, and the lower part changes nothing (PROTOCOL.md §6.3a).
func TestAnAddressRevocationBesideALowerRevocationOfCertificates(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, s := e.box(protocol.Classic), e.box(protocol.Classic)
	n := numberOf(t, a)
	publishAt(t, e.srv.URL, ownRevocation(t, a, n+10))
	both := ownRevocation(t, a, n+5)
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	both.Revocation = rec.Revocation
	if _, err := client.Publish(ctx, e.opts(), both); err != nil {
		t.Fatalf("the address's revocation beside a lower revocation of certificates: %v", err)
	}
	var gone *client.RevokedError
	if _, err := s.Ask(ctx, a.Address()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send(ctx, a.Address(), "to a revoked address"); !errors.As(err, &gone) {
		t.Errorf("a send to it: %v", err)
	}
}
