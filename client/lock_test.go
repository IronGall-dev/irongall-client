package client_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// holdState holds box b's lock as another command of it would: its state
// file, open in bbolt. The function it returns lets go.
func holdState(t *testing.T, b *client.Box) func() {
	t.Helper()
	db, err := bolt.Open(filepath.Join(b.Dir(), "state"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("the box's lock is not free: %v", err)
	}
	return func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}
}

// Every command that writes the box holds its lock from start to end, and
// one that finds it held waits, says so once, and runs once it is free:
// two commands of a box never share its files (#62, #83, #96). The commands
// are lockingCommands', which TestEveryLockingCommandIsTriedFinished holds
// to the code.
func TestEveryCommandWaitsForTheLock(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	refused, run := lockingCommands(context.Background(), nil, nil, nil, "")
	for i, c := range append(refused, run...) {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			a, peer := e.box(protocol.Classic), e.box(protocol.Classic)
			rec, err := peer.Revocation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := a.SetAlias(t.Context(), "peer", peer.Address()); err != nil { // so RemoveAlias has one to remove
				t.Fatal(err)
			}
			var waited atomic.Int32
			told := make(chan struct{}, 1)
			opt := e.opts()
			opt.Waiting = func() {
				waited.Add(1)
				select {
				case told <- struct{}{}:
				default:
				}
			}
			x, err := client.Open(a.Dir(), opt)
			if err != nil {
				t.Fatal(err)
			}
			refused, run := lockingCommands(t.Context(), x, peer, rec, e.srv.AdoptKey("acct"))
			f := append(refused, run...)[i].f
			release := holdState(t, a) // another command's
			done := make(chan error, 1)
			go func() { done <- f() }()
			// Released once the command says it waits, never after a guessed
			// time: on a slow runner a command can take longer than any fixed
			// pause to reach the lock (KeepRevocation, windows-11-arm).
			select {
			case err := <-done:
				t.Fatalf("ran while another command held the lock: %v", err)
			case <-told:
			case <-time.After(10 * time.Second):
				t.Fatal("never said it waits for the lock")
			}
			release()
			if err := <-done; err != nil {
				t.Fatalf("once the lock was free: %v", err)
			}
			if n := waited.Load(); n != 1 {
				t.Errorf("Waiting was told %d times, want once", n)
			}
			holdState(t, a)() // released: free at once
		})
	}
}

// A box with no state file, restored or made before there was one, makes it
// at its first command, beside its place and linked in, and commands that
// make it at once all run: a link replaces nothing another made first. Both
// makers race: Open's, and a command's own once the file is gone after its
// box was opened (#327).
func TestTheStateFileIsMadeAtTheFirstCommand(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	e := newEnv(t)
	b := e.box(protocol.Classic)
	for _, maker := range []string{"Open", "a command"} {
		for i := range 10 {
			if err := os.Remove(filepath.Join(b.Dir(), "state")); err != nil {
				t.Fatal(err)
			}
			var boxes []*client.Box
			if maker == "a command" {
				for range 8 {
					x, err := client.Open(b.Dir(), e.opts())
					if err != nil {
						t.Fatal(err)
					}
					boxes = append(boxes, x)
				}
				if err := os.Remove(filepath.Join(b.Dir(), "state")); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for k := range 8 {
				wg.Go(func() {
					<-start
					x, err := (*client.Box)(nil), error(nil)
					if maker == "Open" {
						x, err = client.Open(b.Dir(), e.opts())
					} else {
						x = boxes[k]
					}
					if err == nil {
						_, err = x.Receive(context.Background())
					}
					errs <- err
				})
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("%s, run %d: a command that made the state file with others: %v", maker, i, err)
				}
			}
			holdState(t, b)()
			entries, err := os.ReadDir(b.Dir())
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range entries {
				if strings.HasPrefix(f.Name(), ".tmp-") {
					t.Fatalf("%s, run %d: left %s", maker, i, f.Name())
				}
			}
		}
	}
}

// A state file of no bytes, which this client never leaves, is refused by a
// command and a reading alike, and left as it is: bbolt would make a
// database in it in place, which a cut can leave faulting every process
// after (#323). Once it is deleted, the next command makes it.
func TestAnEmptyStateFileIsRefusedAndLeftAsItIs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	state := filepath.Join(b.Dir(), "state")
	if err := os.Truncate(state, 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Receive(ctx); err == nil || !strings.Contains(err.Error(), "state file is empty") {
		t.Errorf("a command on an empty state file: %v", err)
	}
	if _, err := b.Status(ctx); err == nil || !strings.Contains(err.Error(), "state file is empty") {
		t.Errorf("a reading of an empty state file: %v", err)
	}
	if after, err := os.Stat(state); err != nil || after.Size() != 0 || !os.SameFile(before, after) {
		t.Fatalf("the empty state file after: %v, %v", after, err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Receive(ctx); err != nil {
		t.Fatalf("a command once the empty file was deleted: %v", err)
	}
}

// One Box shared by goroutines runs one command or reading at a time: a
// reading of one goroutine waits for another's command, as a reading of
// another process does, and never reads inside it (#329).
func TestABoxSharedByGoroutinesRunsOneAtATime(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "landed while another goroutine reads")
	var read atomic.Int32
	done := make(chan error, 1)
	client.SetStep(func(name string) {
		if name != "delivery written" || !read.CompareAndSwap(0, 1) {
			return
		}
		go func() { _, err := b.Status(ctx); done <- err }()
		select {
		case err := <-done:
			read.Store(2)
			done <- err
		case <-time.After(300 * time.Millisecond):
		}
	})
	t.Cleanup(func() { client.SetStep(nil) })
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("%+v", res)
	}
	if err := <-done; err != nil || read.Load() != 1 {
		t.Fatalf("a reading beside a command of the same Box: it ran inside it %v, %v", read.Load() == 2, err)
	}

	// Many at once, one goroutine receiving, one setting an alias and two
	// reading, none failing: readings of one Box at once would share its
	// fields, each closing the state file another reads. Two commands are
	// ordered by the state file's lock as well as by the slot, so no test
	// tells the slot's half for commands: it is there so that what orders
	// their writes of the Box's fields is Go's, which the race detector does
	// not stand in for (it takes file I/O as synchronization). Run under
	// -race at every push (client AGENTS.md).
	stop := make(chan struct{})
	readErr := make(chan error, 3)
	var readers sync.WaitGroup
	readers.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := b.SetAlias(ctx, "sender", a.Address()); err != nil {
				readErr <- err
				return
			}
		}
	})
	for range 2 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := b.Status(ctx); err != nil {
					readErr <- err
					return
				}
			}
		})
	}
	for i := range 5 {
		send(t, a, b, "round")
		if _, err := b.Receive(ctx); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	close(stop)
	readers.Wait()
	close(readErr)
	if err := <-readErr; err != nil {
		t.Fatalf("a reading beside the rounds: %v", err)
	}
}

// waits are the entries that wait for box b's lock, each a reading or a
// command, by its name: every exported function and Box method that takes the
// lock or reads the box, and every Box method that calls one of those (Send,
// Revoke). TestEveryEntryThatWaitsIsTriedWithItsContext holds the list to the
// code. c is a peer, rec c's revocation, and opt the options b was opened
// with.
func waits(b, c *client.Box, rec *protocol.Revocations, opt client.Options) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"Status":             func(ctx context.Context) error { _, err := b.Status(ctx); return err },
		"RefusedMail":        func(ctx context.Context) error { _, err := b.RefusedMail(ctx); return err },
		"NotMade":            func(ctx context.Context) error { _, err := b.NotMade(ctx); return err },
		"Revocation":         func(ctx context.Context) error { _, err := b.Revocation(ctx); return err },
		"CertificatesRecord": func(ctx context.Context) error { _, err := b.CertificatesRecord(ctx); return err },
		"ACLPending":         func(ctx context.Context) error { _, err := b.ACLPending(ctx); return err },
		"SetAlias":           func(ctx context.Context) error { return b.SetAlias(ctx, "carol", c.Address()) },
		"RemoveAlias":        func(ctx context.Context) error { return b.RemoveAlias(ctx, "carol") },
		"SetPolicy": func(ctx context.Context) error {
			return b.SetPolicy(ctx, client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll})
		},
		"KeepRevocation":    func(ctx context.Context) error { _, _, err := b.KeepRevocation(ctx, rec); return err },
		"RebuildAllowed":    func(ctx context.Context) error { _, err := b.RebuildAllowed(ctx); return err },
		"RemoveRefused":     func(ctx context.Context) error { _, err := b.RemoveRefused(ctx, nil); return err },
		"SetPrekeyLifetime": func(ctx context.Context) error { return b.SetPrekeyLifetime(ctx, protocol.PrekeyLifetime) },
		"Receive":           func(ctx context.Context) error { _, err := b.Receive(ctx); return err },
		"Hold":              func(ctx context.Context) error { _, err := b.Hold(ctx, time.Second); return err },
		"Await":             func(ctx context.Context) error { return b.Await(ctx, time.Now().Add(2*time.Second), nil) },
		"Rekey":             func(ctx context.Context) error { _, err := b.Rekey(ctx, ""); return err },
		"RevokeEarlier":     func(ctx context.Context) error { _, err := b.RevokeEarlier(ctx); return err },
		"RenewAndRevoke":    func(ctx context.Context) error { _, err := b.RenewAndRevoke(ctx, ""); return err },
		"Send":              func(ctx context.Context) error { _, err := b.Send(ctx, c.Address(), "waits"); return err },
		"SendWith": func(ctx context.Context) error {
			_, err := b.SendWith(ctx, c.Address(), "waits", client.Fields{})
			return err
		},
		"SendJSON": func(ctx context.Context) error {
			_, err := b.SendJSON(ctx, c.Address(), []byte(`{"waits":true}`), client.Fields{})
			return err
		},
		"Flush":   func(ctx context.Context) error { _, err := b.Flush(ctx); return err },
		"Allow":   func(ctx context.Context) error { _, err := b.Allow(ctx, c.Address()); return err },
		"Block":   func(ctx context.Context) error { _, err := b.Block(ctx, c.Address()); return err },
		"SyncACL": func(ctx context.Context) error { return b.SyncACL(ctx) },
		"Adopt":   func(ctx context.Context) error { _, err := b.Adopt(ctx, "key"); return err },
		"Leave":   func(ctx context.Context) error { return b.Leave(ctx) },
		"Resolve": func(ctx context.Context) error { _, err := b.Resolve(ctx, c.Address()); return err },
		"Ask":     func(ctx context.Context) error { _, err := b.Ask(ctx, c.Address()); return err },
		"Publish": func(ctx context.Context) error { _, err := b.Publish(ctx, rec); return err },
		"Revoke":  func(ctx context.Context) error { _, err := b.Revoke(ctx, rec); return err },
		"client.Init": func(ctx context.Context) error {
			_, err := client.Init(ctx, b.Dir(), opt, protocol.Classic)
			return err
		},
	}
}

// Every entry that waits for a box's lock is one of waits', and every one of
// waits' is one that waits, so each is tried with its context (#406 item 2):
// an exported function or Box method that takes the lock or reads the box
// (locked, lockedFinished, lockedDo, lockedFinishedDo, reading), and a Box
// method that calls one of those on its own box, whatever it does first.
func TestEveryEntryThatWaitsIsTriedWithItsContext(t *testing.T) {
	t.Parallel()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		name string
		recv string // the Box method's receiver, or "" for a function
		body *ast.BlockStmt
	}
	var entries []entry
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
			if !ok || !fn.Name.IsExported() || fn.Body == nil {
				continue
			}
			switch {
			case fn.Recv == nil:
				entries = append(entries, entry{"client." + fn.Name.Name, "", fn.Body})
			case len(fn.Recv.List[0].Names) == 1 && types.ExprString(fn.Recv.List[0].Type) == "*Box":
				entries = append(entries, entry{fn.Name.Name, fn.Recv.List[0].Names[0].Name, fn.Body})
			}
		}
	}
	wait := map[string]bool{}
	for _, e := range entries {
		wait[e.name] = calls(e.body, "", "locked", "lockedFinished", "lockedDo", "lockedFinishedDo", "reading")
	}
	for grew := true; grew; {
		grew = false
		for _, e := range entries {
			if e.recv == "" || wait[e.name] {
				continue
			}
			for name, w := range wait {
				if w && !strings.HasPrefix(name, "client.") && calls(e.body, e.recv, name) {
					wait[e.name], grew = true, true
					break
				}
			}
		}
	}
	tried := waits(nil, nil, nil, client.Options{})
	for name, w := range wait {
		if _, ok := tried[name]; w && !ok {
			t.Errorf("%s waits for the box's lock and is not tried with its context: add it to waits", name)
		}
	}
	for name := range tried {
		if !wait[name] {
			t.Errorf("waits tries %s, which waits for no lock", name)
		}
	}
}

// calls reports whether body calls one of names, as a function or a method,
// or, where recv is given, as a method of recv alone.
func calls(body *ast.BlockStmt, recv string, names ...string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fun := c.Fun
		if x, ok := fun.(*ast.IndexExpr); ok {
			fun = x.X
		}
		if x, ok := fun.(*ast.IndexListExpr); ok {
			fun = x.X
		}
		name := ""
		switch x := fun.(type) {
		case *ast.Ident:
			if recv == "" {
				name = x.Name
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); recv == "" || ok && id.Name == recv {
				name = x.Sel.Name
			}
		}
		found = found || name != "" && slices.Contains(names, name)
		return true
	})
	return found
}

// endsWithItsContext runs each of waits with a context of 200 ms while what
// it waits for is held, and fails the test unless each ended with it.
func endsWithItsContext(t *testing.T, held string, waits map[string]func(context.Context) error) {
	t.Helper()
	for name, f := range waits {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		start := time.Now()
		err := f(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Errorf("%s while %s: %v after %v", name, held, err, time.Since(start))
		}
	}
}

// writtenNothing fails the test if b keeps an alias, or c's revocation,
// which waits would have written had a wait not ended.
func writtenNothing(t *testing.T, b, c *client.Box) {
	t.Helper()
	if as, err := b.Aliases(); err != nil || len(as) != 0 {
		t.Errorf("an alias was written after its wait ended: %+v, %v", as, err)
	}
	if held, err := b.Ask(t.Context(), c.Address()); err != nil || held.Revoked {
		t.Errorf("a revocation was kept after its wait ended: %+v, %v", held, err)
	}
}

// A wait for the box's lock ends with the caller's context, at every entry
// that waits, and what it would have written is not written (#330).
func TestAWaitForTheLockEndsWithItsContext(t *testing.T) {
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	client.SetLockPatience(t, 3*time.Second) // a wait that ignores its context fails at this, not at two minutes
	e := newEnv(t)
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
	rec, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release := holdState(t, b)
	defer release()
	endsWithItsContext(t, "the lock is held", waits(b, c, rec, e.opts()))
	release()
	release = func() {}
	writtenNothing(t, b, c)
}

// So does a wait for the Box's slot, which a command of another goroutine
// sharing the Box holds, at every entry (claim; #330). Each entry takes the
// slot before the state file, so the slot's is the wait timed: holdState,
// above, times only the file's (#380).
func TestAWaitForTheSlotEndsWithItsContext(t *testing.T) {
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	client.SetLockPatience(t, 3*time.Second) // a wait that ignores its context ends at this, refused, not at two minutes
	e := newEnv(t)
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
	rec, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// A Receive of b on another goroutine holds b's slot while the server
	// holds its list.
	in, out := make(chan struct{}), make(chan struct{})
	listed := sync.OnceFunc(func() { close(in) })
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages" {
			listed()
			<-out
		}
		next.ServeHTTP(w, r)
	})
	done := make(chan error, 1)
	go func() { _, err := b.Receive(context.Background()); done <- err }()
	<-in
	endsWithItsContext(t, "another goroutine's command holds the slot", waits(b, c, rec, e.opts()))
	close(out)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(nil)
	writtenNothing(t, b, c)
}

// A command that waits for the box's lock goes before readings that come
// after it, however they overlap: two readings back to back held a Receive
// back past its patience, since a flock gives a waiting writer no preference
// (#344). Each reading is had too: one refused would leave the Receive alone
// (#452). Where the system has no gate there is no preference to hold.
func TestAWaitingCommandGoesBeforeReadingsThatOverlap(t *testing.T) {
	if !client.HasGate(t) {
		t.Skip("this system has no gate (gate_other.go): a waiting writer has no preference here")
	}
	client.SetLockPatience(t, 5*time.Second)
	e := newEnv(t)
	b := e.box(protocol.Classic)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var refused atomic.Int64
	for range 2 {
		r, err := client.Open(b.Dir(), e.opts())
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := r.Status(context.Background()); err != nil {
					refused.Add(1)
				}
			}
		})
	}
	stopped := sync.OnceFunc(func() { close(stop); wg.Wait() })
	defer stopped()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	_, err := b.Receive(context.Background())
	took := time.Since(start)
	stopped() // every reading's error counted
	if err != nil || took > 2*time.Second {
		t.Fatalf("a Receive beside two readings back to back: %v after %v", err, took)
	}
	if n := refused.Load(); n != 0 {
		t.Errorf("%d readings beside the Receive were refused", n)
	}
}

// Two commands of one box keeping two revocations of one address's
// certificates at once keep the higher (#83): with no lock, both read before
// either wrote, and the last rename won whatever its serial.
func TestTwoProcessesKeepTheHigherSerial(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	e := newEnv(t)
	a := e.box(protocol.Classic)
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rec := func(through uint64) *protocol.Revocations {
		certs, err := protocol.NewRevokedCertificates(a.Address(), through)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := protocol.SignRevokedCertificates(id, certs)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.Revocations{Identity: a.Identity().Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
	}
	low, high := rec(200), rec(300)
	for i := range 30 {
		b := e.box(protocol.Classic) // neither record held yet
		p1, err := client.Open(b.Dir(), e.opts())
		if err != nil {
			t.Fatal(err)
		}
		p2, err := client.Open(b.Dir(), e.opts())
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; _, _, _ = p1.KeepRevocation(t.Context(), high) })
		wg.Go(func() { <-start; _, _, _ = p2.KeepRevocation(t.Context(), low) })
		close(start)
		wg.Wait()
		if _, h, err := b.KeepRevocation(t.Context(), low); err != nil || h.Certificates == nil || h.Certificates.Through != 300 {
			t.Fatalf("run %d: after verifying through 300, holds %+v (%v)", i, h, err)
		}
	}
}

// A reading of the box, status, opens its state file read-only: it waits
// while a command holds it, says so once, and reads once it is free; one
// that waits past the box's patience is refused, never read half written.
// Readings at once share it.
func TestStatusWaitsForACommandThatWrites(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	release := holdState(t, b)
	told := make(chan struct{}, 1)
	opt := e.opts()
	opt.Waiting = func() { told <- struct{}{} }
	x, err := client.Open(b.Dir(), opt)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := x.Status(t.Context()); done <- err }()
	select {
	case <-told:
	case err := <-done:
		t.Fatalf("status read the box while a command held it: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("status neither waited nor read")
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("status once the box was free: %v", err)
	}

	client.SetLockPatience(t, 300*time.Millisecond)
	release = holdState(t, b)
	if _, err := x.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "held its lock") {
		t.Fatalf("status past the box's patience: %v", err)
	}
	release()

	ro, err := bolt.Open(filepath.Join(b.Dir(), "state"), 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close() //nolint:errcheck // read only
	if _, err := x.Status(t.Context()); err != nil {
		t.Fatalf("status beside another reading: %v", err)
	}
}
