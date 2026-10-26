package client_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Mail from a sender the box has not allowed passes every check and is held:
// acked, kept in held/, never delivered. allow delivers what it held, and
// the sender's next mail lands in inbox/.
func TestMailFromASenderNotAllowedIsHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "first")
	send(t, a, b, "second")
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Held) != 2 || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("a stranger's mail: %+v, %d left on the server", res, e.srv.Count(b.Address()))
	}
	if inbox, _ := filepath.Glob(filepath.Join(b.Dir(), "inbox", "*.json")); len(inbox) != 0 {
		t.Fatalf("inbox/ holds %v", inbox)
	}
	st, err := b.Status(t.Context())
	if err != nil || st.Held != 2 || !strings.Contains(strings.Join(st.Attention, "\n"), "2 held in held/") {
		t.Fatalf("status: %+v, %v", st, err)
	}
	held, err := b.HeldMail()
	if err != nil || len(held) != 1 || held[0].From != a.Address() || len(held[0].IDs) != 2 || held[0].FirstSentAt == "" {
		t.Fatalf("held: %+v, %v", held, err)
	}
	moved, err := b.Allow(ctx, a.Address())
	if err != nil || len(moved) != 2 || bodyOf(t, moved[0])+bodyOf(t, moved[1]) != "firstsecond" && bodyOf(t, moved[0])+bodyOf(t, moved[1]) != "secondfirst" {
		t.Fatalf("allow: %+v, %v", moved, err)
	}
	if left, _ := filepath.Glob(filepath.Join(b.Dir(), "held", "*.json")); len(left) != 0 {
		t.Fatalf("held/ still holds %v", left)
	}
	if inbox, _ := filepath.Glob(filepath.Join(b.Dir(), "inbox", "*.json")); len(inbox) != 2 {
		t.Fatalf("inbox/ holds %v", inbox)
	}
	send(t, a, b, "third")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 || bodyOf(t, res.Delivered[0]) != "third" {
		t.Fatalf("mail from a sender allowed: %+v", res)
	}
	// Under the default policy the server was told nothing: the box blocks
	// nobody and lets every sender reach it, which is the server's own
	// default.
	if e.srv.ACL(b.Address()) != nil {
		t.Fatalf("an ACL reached the server: %+v", e.srv.ACL(b.Address()))
	}
}

// Writing to a box allows it, so its reply lands in inbox/; so does naming
// it, and un-naming it is not blocking it.
func TestWritingOrNamingAPeerAllowsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, c := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, b, a, "hello")
	send(t, a, b, "the reply")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("a reply from a box written to: %+v", res)
	}
	if err := b.SetAlias(t.Context(), "carol", c.Address()); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveAlias(t.Context(), "carol"); err != nil {
		t.Fatal(err)
	}
	send(t, c, b, "from a box once named")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("mail from a box named, then un-named: %+v", res)
	}
	// An alias written by hand, which allowed never heard of, allows too.
	d := e.heldBox(protocol.Classic)
	f, err := os.OpenFile(filepath.Join(b.Dir(), "aliases"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("dan " + d.Address().String() + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	send(t, d, b, "named by hand")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("mail from a box an alias written by hand names: %+v", res)
	}
}

// Block deletes what held/ keeps from a sender and tells the server, which
// deletes what it holds from it and refuses its sends: final, so the
// sender's client moves the message to outbox/failed/. Blocking wins over
// allowing.
func TestBlockDropsASendersMailHereAndAtTheServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "held")
	receive(t, b)
	send(t, a, b, "waiting on the server")
	if _, err := b.Allow(ctx, a.Address()); err != nil { // and blocking still wins
		t.Fatal(err)
	}
	n, err := b.Block(ctx, a.Address())
	if err != nil || n != 0 {
		t.Fatalf("block: %d, %v", n, err) // allow moved the held one to inbox/ already
	}
	acl := e.srv.ACL(b.Address())
	if acl == nil || !acl.Deny.Has(a.Address()) || !acl.Allow.Any || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("the server holds %+v and %d messages", acl, e.srv.Count(b.Address()))
	}
	_, err = a.Send(ctx, b.Address(), "refused")
	if client.Code(err) != protocol.CodeSenderNotAllowed || !strings.Contains(err.Error(), "moved to outbox/failed/") {
		t.Fatalf("a send to a box that blocked its sender: %v", err)
	}
	if failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", "*.P")); len(failed) != 1 {
		t.Fatalf("outbox/failed/ holds %v", failed)
	}

	// What held/ keeps from a sender goes when it is blocked.
	c := e.heldBox(protocol.Classic)
	send(t, c, b, "from c")
	receive(t, b)
	if n, err := b.Block(ctx, c.Address()); err != nil || n != 1 {
		t.Fatalf("block c: %d, %v", n, err)
	}
	if left, _ := filepath.Glob(filepath.Join(b.Dir(), "held", "*.json")); len(left) != 0 {
		t.Fatalf("held/ still holds %v", left)
	}
	if blocked, err := b.Blocked(); err != nil || len(blocked) != 2 {
		t.Fatalf("blocked: %v, %v", blocked, err)
	}
}

// Mail from a blocked sender that the server still delivers, its ACL not
// yet taken, is dropped by the box itself, and the drain says so.
func TestABoxDropsMailFromASenderItBlockedWhateverItsServerDoes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "sent before the block")
	if err := os.WriteFile(filepath.Join(b.Dir(), "blocked"), []byte(a.Address().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.HasSuffix(r.URL.Path, "/acl") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Blocked) != 1 || len(res.Held)+len(res.Delivered) != 0 || res.ACLErr == nil || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("a drain with the sender blocked here only: %+v", res)
	}
	if st, err := b.Status(t.Context()); err != nil || !strings.Contains(strings.Join(st.Attention, "\n"), "holds no ACL this box sent") {
		t.Fatalf("status: %+v, %v", st, err)
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); res.ACLErr != nil || !e.srv.ACL(b.Address()).Deny.Has(a.Address()) {
		t.Fatalf("the next drain sends the ACL: %+v", res)
	}
}

// "unknown inbox" lands every sender's mail in inbox/, as a box did before
// it could hold any.
func TestAPolicyCanLandEverySendersMailInInbox(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if err := os.WriteFile(filepath.Join(b.Dir(), "policy"), []byte("# every sender\nunknown inbox\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	send(t, a, b, "to an open box")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("%+v", res)
	}
}

// Under "server allowed" the server refuses every sender the box has not
// allowed, and learns who those are: a send to a new address tells it
// before the message is posted, so the reply is not refused.
func TestUnderServerAllowedTheServerRefusesTheRest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, stranger := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
		t.Fatal(err)
	}
	var calls []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") || r.Method == http.MethodPost {
			calls = append(calls, r.Method)
		}
		next.ServeHTTP(w, r)
	})
	send(t, b, a, "hello")
	if strings.Join(calls, " ") != "PUT POST" {
		t.Fatalf("the calls of a send to a new address: %v", calls)
	}
	acl := e.srv.ACL(b.Address())
	if acl == nil || acl.Allow.Any || !acl.Allow.Has(a.Address()) || acl.Allow.Len() != 1 {
		t.Fatalf("the server holds %+v", acl)
	}
	send(t, a, b, "the reply")
	if _, err := stranger.Send(ctx, b.Address(), "refused"); client.Code(err) != protocol.CodeSenderNotAllowed {
		t.Fatalf("a stranger's send: %v", err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("%+v", res)
	}
	// A second send to the same address sends no ACL: nothing changed.
	calls = nil
	send(t, b, a, "again")
	if strings.Join(calls, " ") != "POST" {
		t.Fatalf("the calls of a send to an allowed address: %v", calls)
	}
	// Back to "server all": the server lets everyone in again.
	if err := b.SetPolicy(t.Context(), client.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncACL(ctx); err != nil {
		t.Fatal(err)
	}
	if acl := e.srv.ACL(b.Address()); !acl.Allow.Any || acl.Deny.Len() != 0 {
		t.Fatalf("the server holds %+v", acl)
	}
}

// An ACL replaces whatever the server holds, whoever sent it: a box whose
// record of what its server took is gone, as on a second machine of the
// box, sends the ACL its files say in one PUT, with no If-Match and no read
// first, and keeps the server's answer.
func TestAnACLReplacesWhatTheServerHolds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, a.Address()); err != nil {
		t.Fatal(err)
	}
	b.SetRecord(t, "acl.json", nil) // as on a second machine
	var calls []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.HasSuffix(r.URL.Path, "/acl") {
			calls = append(calls, r.Method+" If-Match:"+r.Header.Get("If-Match"))
		}
		next.ServeHTTP(w, r)
	})
	c := e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, c.Address()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ", ") != "PUT If-Match:" {
		t.Fatalf("the calls of the ACL: %q", calls)
	}
	acl := e.srv.ACL(b.Address())
	if acl.Deny.Len() != 2 || !acl.Deny.Has(a.Address()) || !acl.Deny.Has(c.Address()) {
		t.Fatalf("the server holds %+v", acl)
	}
	var took protocol.ACLDocument
	data, _ := stateOf(b, "acl.json")
	if err := protocol.Unmarshal(data, &took); err != nil || len(took.Deny) != 2 {
		t.Fatalf("the ACL kept: %s, %v", data, err)
	}
}

// An ACL another writer put at the server, another machine of the box or
// whoever holds its pass, is read at the box's next renewal and replaced by
// the box's own, which Receive reports; until then nothing asks the server
// about it, neither a drain nor a send. A renewal that finds the box's own
// reads it and sends nothing (dromas-dev/dromas-client#360).
func TestARenewalReplacesAnACLAnotherWriterPut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, a.Address()); err != nil {
		t.Fatal(err)
	}
	own := e.srv.ACL(b.Address())
	var calls []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.URL.Path == "/v1/"+b.Address().String()+"/acl" {
			calls = append(calls, r.Method)
		}
		next.ServeHTTP(w, r)
	})
	took := func() string {
		t.Helper()
		data, _ := stateOf(b, "acl.json")
		return string(data)
	}
	kept := took()

	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || res.ACLReplaced || res.ACLErr != nil || strings.Join(calls, " ") != "GET" {
		t.Fatalf("a renewal that finds the box's own ACL: %+v, calls %v", res, calls)
	}

	// Another writer pauses the box. A drain and a send ask nothing of it.
	pause := &protocol.ACL{Deny: protocol.ACLList{Any: true}}
	e.srv.PutACL(b.Address(), pause)
	calls = nil
	if res := receive(t, b); res.Renewed != nil || res.ACLReplaced {
		t.Fatalf("a drain with no renewal due: %+v", res)
	}
	send(t, b, a, "a send while paused")
	if len(calls) != 0 || !e.srv.ACL(b.Address()).SameLists(pause) {
		t.Fatalf("a drain and a send called %v, and the server holds %+v", calls, e.srv.ACL(b.Address()))
	}

	// The next renewal reads it, and puts the box's own in its place.
	e.clock.Add(25 * time.Hour)
	res := receive(t, b)
	if res.Renewed == nil || !res.ACLReplaced || res.ACLErr != nil || strings.Join(calls, " ") != "GET PUT" {
		t.Fatalf("the renewal after another writer's ACL: %+v, calls %v", res, calls)
	}
	if !e.srv.ACL(b.Address()).SameLists(own) || took() != kept {
		t.Fatalf("the server holds %+v, the box keeps %s; want %+v, %s", e.srv.ACL(b.Address()), took(), own, kept)
	}
}

// A renewal that reads another writer's ACL and whose PUT of the box's own
// the server does not take keeps what the server holds as the ACL it took
// (#377): status says the box's ACL is pending, a reply is judged against
// the ACL the server holds, and the next recv, with no renewal, sends the
// box's own and says it replaced another writer's, once. So for a pause and
// for a deny list of addresses, which the box's files could say, and which
// recv reports by the mark checkACL keeps beside it. Control: the PUT taken,
// replaced and reported at the renewal.
func TestARenewalWhosePUTIsNotTakenLeavesTheBoxsACLPending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, other := range []struct {
		name string
		acl  func(d protocol.Address) *protocol.ACL
	}{
		{"a pause", func(protocol.Address) *protocol.ACL { return &protocol.ACL{Deny: protocol.ACLList{Any: true}} }},
		{"a deny list", func(d protocol.Address) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{d})}
		}},
	} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, the PUT not taken %v", other.name, fail), func(t *testing.T) {
				e := newEnv(t)
				a, b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
				if _, err := b.Block(ctx, c.Address()); err != nil {
					t.Fatal(err)
				}
				own, theirs := e.srv.ACL(b.Address()), other.acl(d.Address())
				e.srv.PutACL(b.Address(), theirs)
				var mu sync.Mutex
				failing := fail
				var calls []string
				e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					if !strings.HasSuffix(r.URL.Path, "/acl") {
						next.ServeHTTP(w, r)
						return
					}
					mu.Lock()
					calls = append(calls, r.Method)
					refuse := failing && r.Method == http.MethodPut
					mu.Unlock()
					if refuse {
						fakeserver.WriteJSON(w, protocol.CodeUnavailable.Status(), protocol.Problem{Type: protocol.CodeUnavailable.TypeURI(), Code: protocol.CodeUnavailable, Status: int64(protocol.CodeUnavailable.Status())})
						return
					}
					next.ServeHTTP(w, r)
				})
				took := func() []string {
					mu.Lock()
					defer mu.Unlock()
					out := calls
					calls = nil
					return out
				}
				e.clock.Add(25 * time.Hour)
				res := receive(t, b)
				if got := took(); res.Renewed == nil || strings.Join(got, " ") != "GET PUT" {
					t.Fatalf("the renewal: %+v, calls %v", res, got)
				}
				if !fail {
					if !res.ACLReplaced || res.ACLErr != nil || !e.srv.ACL(b.Address()).SameLists(own) {
						t.Fatalf("control: the renewal's PUT taken: %+v; the server holds %+v", res, e.srv.ACL(b.Address()))
					}
					return
				}
				pending, perr := b.ACLPending(ctx)
				st, serr := b.Status(ctx)
				const what = "this box's server held an ACL another writer put there"
				if res.ACLReplaced || res.ACLErr == nil || !strings.Contains(res.ACLErr.Error(), what) || !pending || perr != nil || serr != nil || !strings.Contains(strings.Join(st.Attention, "\n"), what) {
					t.Fatalf("the renewal whose PUT was refused: replaced %v, its error %v; pending %v (%v); attention %q (%v)", res.ACLReplaced, res.ACLErr, pending, perr, st.Attention, serr)
				}
				// A reply is judged against the ACL the server holds: under
				// the pause none is admitted, and the send waits for the ACL.
				_, sendErr := b.Send(ctx, a.Address(), "while the server holds another writer's ACL")
				if waits := sendErr != nil; waits != (other.name == "a pause") {
					t.Fatalf("a send while the PUT is refused: %v", sendErr)
				}
				took()
				mu.Lock()
				failing = false // the server takes PUTs again
				mu.Unlock()
				again := receive(t, b)
				if got := took(); again.Renewed != nil || !again.ACLReplaced || again.ACLErr != nil || strings.Join(got, " ") != "PUT" || !e.srv.ACL(b.Address()).SameLists(own) {
					t.Fatalf("the next recv: %+v, calls %v; the server holds %+v, the box's own is %+v", again, got, e.srv.ACL(b.Address()), own)
				}
				if pending, _ := b.ACLPending(ctx); pending {
					t.Fatal("the box's ACL is pending after the server took it")
				}
				if res := receive(t, b); res.ACLReplaced || len(took()) != 0 {
					t.Fatalf("the replacement is reported again: %+v", res)
				}
			})
		}
	}
}

// Where the ACL a box's files say is not the one its server last took, the
// error of the sync that did not send it and status say what changed, never
// that the box's ACL changed where its server's did: another writer's ACL a
// renewal's read found (TestARenewalWhosePUTIsNotTakenLeavesTheBoxsACLPending),
// none taken from the box, the box's own lists changed, or an ACL a restore
// adopted that holds what no file of the box says.
func TestWhatChangedInAnACLNotTakenIsSaid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct{ name, what string }{
		{"none taken", "this box's server holds no ACL this box sent"},
		{"its lists changed", "this box's lists have changed since its server last took its ACL"},
		{"an adopted ACL holding what no file says", "the ACL this box adopted from its server when it was restored holds what no file of the box says"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			b, d, x := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
			var refusing atomic.Bool
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if refusing.Load() && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") {
					forge.Refuse(w, protocol.CodeUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			})
			box := b
			switch c.name {
			case "its lists changed":
				if _, err := b.Block(ctx, d.Address()); err != nil {
					t.Fatal(err)
				}
			case "an adopted ACL holding what no file says":
				e.srv.PutACL(b.Address(), &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(true, []protocol.Address{d.Address()})})
				box = restore(t, e, b)
				e.clock.Add(time.Minute)
				if _, err := box.Rekey(ctx, ""); err != nil {
					t.Fatal(err)
				}
			}
			refusing.Store(true)
			var err error
			if c.name == "an adopted ACL holding what no file says" {
				err = box.SyncACL(ctx)
			} else {
				_, err = box.Block(ctx, x.Address())
			}
			st, serr := box.Status(ctx)
			if err == nil || !strings.Contains(err.Error(), c.what) || serr != nil || !strings.Contains(strings.Join(st.Attention, "\n"), c.what) {
				t.Fatalf("the sync not taken: %v; status %q, %v; want each to say %q", err, st.Attention, serr, c.what)
			}
		})
	}
}

// The read of its server's ACL that a renewal owes is made only once the
// server's ACL is answered and what it showed is kept: a list of the box's
// that cannot be read, a read the server does not answer, or a fault of the
// box at the keep after it leave the read owed, and the next recv, with no
// renewal due, makes it, once, replaces another writer's ACL and says so. A
// restore's adoption read that fails leaves it owed too, and its own mark
// has the next sync read the server's ACL either way.
func TestAnACLReadNotMadeIsOwedToTheNextRecv(t *testing.T) {
	ctx := context.Background()
	full := &os.PathError{Op: "write", Path: "state", Err: syscall.ENOSPC}
	for _, fault := range []string{"a list that cannot be read", "no answer to the read", "a fault of the box at the keep", "no answer to a restore's adoption read"} {
		t.Run(fault, func(t *testing.T) {
			e := newEnv(t)
			b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
			if _, err := b.Block(ctx, c.Address()); err != nil {
				t.Fatal(err)
			}
			own := e.srv.ACL(b.Address())
			x := b
			if fault == "no answer to a restore's adoption read" {
				x = restore(t, e, b)
				e.clock.Add(time.Minute) // a restore's first recv renews
			} else {
				e.srv.PutACL(b.Address(), &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{d.Address()})})
				e.clock.Add(25 * time.Hour)
			}
			var armed atomic.Bool
			client.SetWriteFault(t, func() error {
				if armed.CompareAndSwap(true, false) {
					return full
				}
				return nil
			})
			var mu sync.Mutex
			failing := true
			var calls []string
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.URL.Path != boxPath(b)+"/acl" {
					next.ServeHTTP(w, r)
					return
				}
				mu.Lock()
				calls = append(calls, r.Method)
				refuse := failing && r.Method == http.MethodGet && (fault == "no answer to the read" || fault == "no answer to a restore's adoption read")
				keep := failing && r.Method == http.MethodGet && fault == "a fault of the box at the keep"
				mu.Unlock()
				if refuse {
					fakeserver.WriteJSON(w, protocol.CodeUnavailable.Status(), protocol.Problem{Type: protocol.CodeUnavailable.TypeURI(), Code: protocol.CodeUnavailable, Status: int64(protocol.CodeUnavailable.Status())})
					return
				}
				next.ServeHTTP(w, r)
				armed.Store(keep) // the box's next write keeps what this read showed
			})
			took := func() string {
				mu.Lock()
				defer mu.Unlock()
				s := strings.Join(calls, " ")
				calls = nil
				return s
			}
			blocked := filepath.Join(x.Dir(), "blocked")
			if fault == "a list that cannot be read" {
				if err := os.WriteFile(blocked, []byte("not an address\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			res, err := x.Receive(ctx)
			if res == nil || res.Renewed == nil {
				t.Fatalf("the recv whose renewal's read was not made: %+v, %v", res, err)
			}
			t.Logf("the recv at the renewal: ACL %v, %v; calls %q", res.ACLErr, err, took())
			mu.Lock()
			failing = false
			mu.Unlock()
			if fault == "a list that cannot be read" {
				if err := os.WriteFile(blocked, []byte(c.Address().String()+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			e.clock.Add(time.Minute)
			again := receive(t, x)
			want, replaced := "GET PUT", true
			if fault == "no answer to a restore's adoption read" {
				want, replaced = "GET", false // its lists are the server's: nothing to send
			}
			if got := took(); again.Renewed != nil || got != want || again.ACLReplaced != replaced || again.ACLErr != nil || !e.srv.ACL(b.Address()).SameLists(own) {
				t.Fatalf("the next recv: renewed %v, calls %q, want %q; replaced %v, its ACL's error %v; the server holds %+v, the box's own is %+v", again.Renewed != nil, got, want, again.ACLReplaced, again.ACLErr, e.srv.ACL(b.Address()), own)
			}
			if res := receive(t, x); res.ACLReplaced || took() != "" {
				t.Fatalf("the recv after it: %+v", res)
			}
		})
	}
}

// A box whose renewal's PUT was not taken, and which its server then forgot,
// with the ACL another writer put there, says it replaced nothing when the
// registration that brings it back sends its own: the server held no ACL by
// then, and the registration drops the mark with the ACL kept (sendRenewal;
// #377).
func TestARegistrationDropsTheMarkOfAnotherWritersACL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, c.Address()); err != nil {
		t.Fatal(err)
	}
	own := e.srv.ACL(b.Address())
	e.srv.PutACL(b.Address(), &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{d.Address()})})
	var failing atomic.Bool
	failing.Store(true)
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if failing.Load() && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") {
			fakeserver.WriteJSON(w, protocol.CodeUnavailable.Status(), protocol.Problem{Type: protocol.CodeUnavailable.TypeURI(), Code: protocol.CodeUnavailable, Status: int64(protocol.CodeUnavailable.Status())})
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || res.ACLErr == nil {
		t.Fatalf("the renewal whose PUT was refused: %+v", res)
	}
	failing.Store(false)
	e.srv.Forget(b.Address())
	e.clock.Add(time.Minute)
	res := receive(t, b)
	if res.Renewed == nil || res.ACLErr != nil || res.ACLReplaced || !e.srv.ACL(b.Address()).SameLists(own) {
		t.Fatalf("the recv that registered the box again: renewed %v, its ACL's error %v, replaced %v; the server holds %+v, the box's own is %+v", res.Renewed != nil, res.ACLErr, res.ACLReplaced, e.srv.ACL(b.Address()), own)
	}
}

// A box restored from its identity alone adopts the ACL its server holds, by
// each way a restore goes (init, prekey renew, and a recv that renews), so its
// first renewal finds the two alike and the server's blocks stay; the heal
// still replaces an ACL another writer puts there after (#366). A box
// restored with one of its lists beside the identity adopts nothing: its
// files are its ACL, and its first renewal puts it.
func TestARestoredBoxAdoptsItsServersACL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lost := func(t *testing.T, e *env) (b, blocked, allowed *client.Box, own *protocol.ACL) {
		t.Helper()
		a, b, c := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
		if _, err := b.Block(ctx, a.Address()); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Allow(ctx, c.Address()); err != nil {
			t.Fatal(err)
		}
		if err := b.SetPolicy(ctx, client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
			t.Fatal(err)
		}
		if err := b.SyncACL(ctx); err != nil {
			t.Fatal(err)
		}
		own = e.srv.ACL(b.Address())
		if own == nil || own.Allow.Any || !own.Allow.Has(c.Address()) || !own.Deny.Has(a.Address()) {
			t.Fatalf("the lost box's ACL: %+v", own)
		}
		return b, a, c, own
	}
	for _, how := range []string{"init", "prekey renew", "recv"} {
		t.Run(how, func(t *testing.T) {
			e := newEnv(t)
			b, a, c, own := lost(t, e)
			r := restore(t, e, b)
			e.clock.Add(time.Minute)
			var err error
			switch how {
			case "init":
				_, err = client.Init(ctx, r.Dir(), e.opts(), "")
			case "prekey renew":
				_, err = r.Rekey(ctx, "")
			case "recv":
				var res *client.Result
				res, err = r.Receive(ctx)
				if err == nil && (res.Renewed == nil || res.ACLReplaced || res.ACLErr != nil) {
					t.Fatalf("the recv that restored the box: %+v", res)
				}
			}
			if err != nil {
				t.Fatalf("the restore: %v", err)
			}
			e.clock.Add(25 * time.Hour)
			if res := receive(t, r); res.Renewed == nil || res.ACLReplaced || res.ACLErr != nil || !e.srv.ACL(b.Address()).SameLists(own) {
				t.Fatalf("the restored box's first renewal: %+v; the server holds %+v, the lost box's was %+v", res, e.srv.ACL(b.Address()), own)
			}
			blocked, _ := r.Blocked()
			allowed, _ := r.Allowed()
			policy, _ := r.Policy()
			if !slices.Equal(blocked, []protocol.Address{a.Address()}) || !slices.Equal(allowed, []protocol.Address{c.Address()}) || policy != (client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}) {
				t.Fatalf("the restored box's lists: blocked %v, allowed %v, %+v", blocked, allowed, policy)
			}

			// Another writer pauses the box: the next renewal replaces it.
			e.srv.PutACL(b.Address(), &protocol.ACL{Deny: protocol.ACLList{Any: true}})
			e.clock.Add(25 * time.Hour)
			if res := receive(t, r); res.Renewed == nil || !res.ACLReplaced || !e.srv.ACL(b.Address()).SameLists(own) {
				t.Fatalf("the renewal after another writer's ACL: %+v; the server holds %+v", res, e.srv.ACL(b.Address()))
			}
		})
	}

	// Each of the three files alone, as the lost box wrote it (#441 item 2),
	// and the ACL it makes: under the default policy, which admits all,
	// allowed changes nothing; policy alone admits only the allowed, who are
	// none.
	for _, kept := range []struct {
		file string
		want func(own *protocol.ACL) *protocol.ACL
	}{
		{"allowed", func(*protocol.ACL) *protocol.ACL { return &protocol.ACL{Allow: protocol.ACLList{Any: true}} }},
		{"blocked", func(own *protocol.ACL) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: own.Deny}
		}},
		{"policy", func(*protocol.ACL) *protocol.ACL { return &protocol.ACL{} }},
	} {
		t.Run("with its "+kept.file+" file", func(t *testing.T) {
			e := newEnv(t)
			b, _, _, own := lost(t, e)
			r := restore(t, e, b)
			data, err := os.ReadFile(filepath.Join(b.Dir(), kept.file))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.Dir(), kept.file), data, 0o600); err != nil {
				t.Fatal(err)
			}
			e.clock.Add(time.Minute)
			if _, err := r.Rekey(ctx, ""); err != nil {
				t.Fatal(err)
			}
			for _, f := range []string{"allowed", "blocked", "policy"} {
				if _, err := os.Stat(filepath.Join(r.Dir(), f)); f != kept.file && !errors.Is(err, os.ErrNotExist) {
					t.Errorf("a box restored with its %s file wrote %s: %v", kept.file, f, err)
				}
			}
			e.clock.Add(25 * time.Hour)
			if res := receive(t, r); res.Renewed == nil || !res.ACLReplaced || !e.srv.ACL(b.Address()).SameLists(kept.want(own)) {
				t.Fatalf("the first renewal of a box restored with its %s file: %+v; the server holds %+v", kept.file, res, e.srv.ACL(b.Address()))
			}
		})
	}
}

// What a restored box adopts and no file of it says, a pause (a deny of
// AnyAddress) or addresses beside an allow of AnyAddress, goes with the first
// ACL the box sends, and recv reports that as the heal's acl_replaced, once:
// whether a later recv's sync sends it, a send's sync, or the renewal of the
// recv that restored the box (#366).
func TestARestoredBoxReportsWhatItDidNotAdopt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, held := range []struct {
		name string
		acl  func(a, c protocol.Address) *protocol.ACL
	}{
		{"a pause", func(a, _ protocol.Address) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(true, []protocol.Address{a})}
		}},
		{"an address beside allow *", func(a, c protocol.Address) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.NewACLList(true, []protocol.Address{c}), Deny: protocol.NewACLList(false, []protocol.Address{a})}
		}},
	} {
		for _, how := range []string{"recv after prekey renew", "send after prekey renew", "recv"} {
			t.Run(held.name+", "+how, func(t *testing.T) {
				e := newEnv(t)
				a, b, c := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
				e.srv.PutACL(b.Address(), held.acl(a.Address(), c.Address()))
				r := restore(t, e, b)
				e.clock.Add(time.Minute)
				if how != "recv" {
					if _, err := r.Rekey(ctx, ""); err != nil {
						t.Fatal(err)
					}
				}
				if how == "send after prekey renew" {
					send(t, r, c, "a send whose sync replaces the adopted ACL")
				}
				res := receive(t, r)
				own := &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{a.Address()})}
				if !res.ACLReplaced || res.ACLErr != nil || !e.srv.ACL(b.Address()).SameLists(own) {
					t.Fatalf("the recv after the restore: %+v; the server holds %+v", res, e.srv.ACL(b.Address()))
				}
				if blocked, _ := r.Blocked(); !slices.Equal(blocked, []protocol.Address{a.Address()}) {
					t.Fatalf("the restored box blocks %v", blocked)
				}
				if res := receive(t, r); res.ACLReplaced {
					t.Fatalf("the replacement is reported again: %+v", res)
				}
			})
		}
	}
}

// A server that answers box_changed to an ACL (the box changed while it
// handled the request) is sent it again, as it is: the write is not lost to
// a race.
func TestAnACLIsSentAgainWhenTheBoxChanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	var once sync.Once
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		raced := false
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") {
			once.Do(func() { raced = true })
		}
		if raced {
			fakeserver.WriteJSON(w, protocol.CodeBoxChanged.Status(), protocol.Problem{Type: protocol.CodeBoxChanged.TypeURI(), Code: protocol.CodeBoxChanged, Status: int64(protocol.CodeBoxChanged.Status())})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Block(ctx, a.Address()); err != nil {
		t.Fatalf("block when the box changed once: %v", err)
	}
	if acl := e.srv.ACL(b.Address()); !acl.Deny.Has(a.Address()) {
		t.Fatalf("the server holds %+v", acl)
	}
}

// A policy or a list that cannot be read stops the drain before anything is
// acked, and status says so: it is never read as the default.
func TestAPolicyThatCannotBeReadStopsTheDrain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "waits")
	for name, text := range map[string]string{"policy": "unknown deliver\n", "allowed": "not an address\n", "blocked": strings.ToUpper(a.Address().String()) + "\n"} {
		if err := os.WriteFile(filepath.Join(b.Dir(), name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		var refused *client.RefusedError
		if _, err := b.Receive(context.Background()); !errors.As(err, &refused) || e.srv.Count(b.Address()) != 1 {
			t.Fatalf("a drain with %s %q: %v, %d left", name, text, err, e.srv.Count(b.Address()))
		}
		if st, err := b.Status(t.Context()); err != nil || !strings.Contains(strings.Join(st.Attention, "\n"), "neither sends nor receives") {
			t.Fatalf("status with %s %q: %+v, %v", name, text, st, err)
		}
		if err := os.Remove(filepath.Join(b.Dir(), name)); err != nil {
			t.Fatal(err)
		}
	}
	if res := receive(t, b); len(res.Held) != 1 {
		t.Fatalf("%+v", res)
	}
}

// RebuildAllowed adds back what aliases and sent/ show, for an allowed file
// that was lost, and keeps what the file lists.
func TestRebuildAllowed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, b, a, "to a")
	if err := b.SetAlias(t.Context(), "carol", c.Address()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir(), "allowed"), []byte(d.Address().String()), 0o600); err != nil { // no line end, as a person may write it
		t.Fatal(err)
	}
	n, err := b.RebuildAllowed(t.Context())
	if err != nil || n != 2 {
		t.Fatalf("rebuild: %d, %v", n, err)
	}
	if allowed, err := b.Allowed(); err != nil || len(allowed) != 3 {
		t.Fatalf("allowed: %v, %v", allowed, err)
	}
	if n, err := b.RebuildAllowed(t.Context()); err != nil || n != 0 {
		t.Fatalf("a second rebuild: %d, %v", n, err)
	}
}

// A sender the box blocks is never allowed: allow is refused, naming the
// block, and its held mail stays where it is (#179).
func TestAllowingABlockedSenderDoesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "held, then its sender blocked by hand")
	if res := receive(t, b); len(res.Held) != 1 {
		t.Fatalf("held %d", len(res.Held))
	}
	if err := os.WriteFile(filepath.Join(b.Dir(), "blocked"), []byte(a.Address().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved, err := b.Allow(ctx, a.Address())
	inbox, _ := filepath.Glob(filepath.Join(b.Dir(), "inbox", "*.json"))
	held, _ := filepath.Glob(filepath.Join(b.Dir(), "held", "*.json"))
	allowed, _ := b.Allowed()
	if err == nil || !strings.Contains(err.Error(), "is blocked") || len(moved) != 0 || len(inbox) != 0 || len(held) != 1 || slices.Contains(allowed, a.Address()) {
		t.Fatalf("allow of a blocked sender: %v, moved %d, inbox %d, held %d, allowed %v", err, len(moved), len(inbox), len(held), allowed)
	}
}

// A send waits for the box's ACL only when the one its server last took would
// refuse the reply (#180): with none taken the server refuses no sender, so
// the send posts and says the ACL was not taken; with one taken under server
// allowed, a send to a peer it does not allow waits.
func TestASendWaitsOnTheACLOnlyWhenTheReplyWouldBeRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	refuseACL := func() {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") {
				code := protocol.CodeTooLarge
				fakeserver.WriteJSON(w, code.Status(), protocol.Problem{Type: code.TypeURI(), Code: code, Status: int64(code.Status())})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	refuseACL()
	if _, err := b.Block(ctx, c.Address()); err == nil {
		t.Fatal("the server took the ACL it refuses")
	}
	s, err := b.Send(ctx, a.Address(), "to a peer, with no ACL taken")
	if err != nil || s.ACLErr == nil || e.srv.Count(a.Address()) != 1 {
		t.Fatalf("a send with the ACL refused and none taken: %+v, %v; posted %d", s, err, e.srv.Count(a.Address()))
	}
	e.srv.SetMiddle(nil)
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncACL(ctx); err != nil || !e.srv.ACL(b.Address()).Allow.Has(a.Address()) {
		t.Fatalf("the ACL under server allowed: %v", err)
	}
	refuseACL()
	if _, err := b.Send(ctx, d.Address(), "to a peer the ACL taken does not allow"); err == nil || e.srv.Count(d.Address()) != 0 {
		t.Fatalf("a send whose reply the ACL taken would refuse: %v; posted %d", err, e.srv.Count(d.Address()))
	}
}

// A line of the box's address lists that starts with "#" is a comment, as in
// its policy file: it stops no drain and no send (#181). One after an address
// on its line is still no address.
func TestACommentInTheAddressListsStopsNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, a, b, "waiting")
	if err := os.WriteFile(filepath.Join(b.Dir(), "blocked"), []byte("# senders of spam, 2026-10\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Receive(ctx); err != nil {
		t.Fatalf("recv with a comment in blocked: %v", err)
	}
	if _, err := b.Send(ctx, a.Address(), "an answer"); err != nil {
		t.Fatalf("send with a comment in blocked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir(), "blocked"), []byte(a.Address().String()+" # spam\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Blocked(); err == nil {
		t.Fatal("an address with a comment after it was read as an address")
	}
}
