package client_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Mail from a sender the box has not allowed passes every check and is held:
// acked, kept in held/, never delivered. allow delivers what it held, and
// the sender's next mail lands in inbox/.
func TestMailFromASenderNotAllowedIsHeld(t *testing.T) {
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
	st, err := b.Status()
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
	e := newEnv(t)
	a, b, c := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, b, a, "hello")
	send(t, a, b, "the reply")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Held) != 0 {
		t.Fatalf("a reply from a box written to: %+v", res)
	}
	if err := b.SetAlias("carol", c.Address()); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveAlias("carol"); err != nil {
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
	if st, err := b.Status(); err != nil || !strings.Contains(strings.Join(st.Attention, "\n"), "ACL has changed") {
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
	ctx := context.Background()
	e := newEnv(t)
	a, b, stranger := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if err := b.SetPolicy(client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
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
	if acl == nil || acl.Allow.Any || !acl.Allow.Has(a.Address()) || acl.Allow.Len() != 1 || acl.Version != 1 {
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
	if err := b.SetPolicy(client.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncACL(ctx); err != nil {
		t.Fatal(err)
	}
	if acl := e.srv.ACL(b.Address()); !acl.Allow.Any || acl.Version != 2 {
		t.Fatalf("the server holds %+v", acl)
	}
}

// A server that holds a later ACL than the box last saw, sent from another
// machine of the box, is asked for its version, and the box's goes above it.
func TestAnACLGoesAboveTheVersionTheServerHolds(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, a.Address()); err != nil {
		t.Fatal(err)
	}
	b.SetRecord(t, "acl.json", nil) // as on a second machine
	c := e.heldBox(protocol.Classic)
	if _, err := b.Block(ctx, c.Address()); err != nil {
		t.Fatal(err)
	}
	acl := e.srv.ACL(b.Address())
	if acl.Version != 2 || !acl.Deny.Has(a.Address()) || !acl.Deny.Has(c.Address()) {
		t.Fatalf("the server holds %+v", acl)
	}
	var took protocol.ACLDocument
	data, _ := stateOf(b, "acl.json")
	if err := protocol.Unmarshal(data, &took); err != nil || *took.Version != 2 {
		t.Fatalf("the ACL kept: %s, %v", data, err)
	}
}

// A server that answers box_changed to an ACL (the box changed while it
// handled the request) is sent it again, as one that holds a later version
// is: the write is not lost to a race.
func TestAnACLIsSentAgainWhenTheBoxChanged(t *testing.T) {
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
		if st, err := b.Status(); err != nil || !strings.Contains(strings.Join(st.Attention, "\n"), "neither sends nor receives") {
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
	e := newEnv(t)
	a, b, c, d := e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic), e.heldBox(protocol.Classic)
	send(t, b, a, "to a")
	if err := b.SetAlias("carol", c.Address()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir(), "allowed"), []byte(d.Address().String()), 0o600); err != nil { // no line end, as a person may write it
		t.Fatal(err)
	}
	n, err := b.RebuildAllowed()
	if err != nil || n != 2 {
		t.Fatalf("rebuild: %d, %v", n, err)
	}
	if allowed, err := b.Allowed(); err != nil || len(allowed) != 3 {
		t.Fatalf("allowed: %v, %v", allowed, err)
	}
	if n, err := b.RebuildAllowed(); err != nil || n != 0 {
		t.Fatalf("a second rebuild: %d, %v", n, err)
	}
}

// A sender the box blocks is never allowed: allow is refused, naming the
// block, and its held mail stays where it is (#179).
func TestAllowingABlockedSenderDoesNothing(t *testing.T) {
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
	if err := b.SetPolicy(client.Policy{Unknown: client.LandHeld, Server: client.AdmitAllowed}); err != nil {
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
