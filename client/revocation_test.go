package client_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A mailbox is revoked by its identity's own signature, and by nothing else. So
// a client takes "revoked" from a server only with the revocation in hand,
// keeps it once it has verified, and takes no server's word against it
// afterwards. These tests play the operator both ways: one that says revoked
// where nothing is, and one that hides a revocation that exists.

// revoke publishes b's own revocation, as its owner would.
func revoke(t *testing.T, e *env, b *client.Mailbox) *protocol.Revocations {
	t.Helper()
	rec, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if a, err := client.Revoke(context.Background(), e.opts(), rec); err != nil || a != b.Address() {
		t.Fatalf("revoke: %v", err)
	}
	return rec
}

// says answers every request matching method and path suffix with a problem
// of this code, as an operator can at will, and lets the rest through.
func says(e *env, code protocol.Code, method, suffix string) {
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) {
			fakeserver.WriteJSON(w, code.Status(), protocol.Problem{Type: code.TypeURI(), Code: code, Status: int64(code.Status())})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func keptRevocation(a *client.Mailbox, of protocol.Address) bool {
	_, ok := stateOf(a, "peers/"+of.String()+"/revoke.sig")
	return ok
}

func failed(a *client.Mailbox, to protocol.Address) int {
	m, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", to.String()+".*.P"))
	return len(m)
}

func isRevoked(err error, a protocol.Address, own bool) bool {
	var gone *client.RevokedError
	return errors.As(err, &gone) && gone.Address == a && gone.Own == own
}

// A server that says a mailbox is revoked, and has no revocation to show, has
// revoked nothing: the message stays in the outbox and goes when the server
// lets it.
func TestAServersWordRevokesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, where := range []struct{ name, method, suffix string }{
		{"at the read of the mailbox", http.MethodGet, ""},
		{"at the send", http.MethodPost, "/messages"},
	} {
		t.Run(where.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			says(e, protocol.CodeRevoked, where.method, "/v1/"+b.Address().String()+where.suffix)
			_, err := a.Send(ctx, b.Address(), "to a mailbox the server calls revoked")
			if err == nil || isRevoked(err, b.Address(), false) || !strings.Contains(err.Error(), "kept in the outbox") || !strings.Contains(err.Error(), "no revocation") {
				t.Fatalf("send: %v", err)
			}
			if keptRevocation(a, b.Address()) || failed(a, b.Address()) != 0 {
				t.Fatal("a server's word was kept as a revocation, or ended the message")
			}
			e.srv.SetMiddle(nil)
			if rs, err := a.Flush(ctx); err != nil || len(rs) != 1 {
				t.Fatalf("flush once the server stopped saying so: %v", err)
			}
			if res := receive(t, b); len(res.Delivered) != 1 {
				t.Fatal("the message never arrived")
			}
		})
	}
}

// No answer proved checks, and never believes, ends a message for good: each
// is final only once the mailbox holds a revocation that verifies (PROTOCOL.md
// §12.5). Both sets are the code's own (#414 item 2).
func TestNoAnswerProvedIsUndeliverable(t *testing.T) {
	t.Parallel()
	if len(client.ProvedCodes()) == 0 || len(client.Undeliverable()) == 0 {
		t.Fatalf("proved checks %v, and %v end a message", client.ProvedCodes(), client.Undeliverable())
	}
	for _, c := range client.ProvedCodes() {
		if slices.Contains(client.Undeliverable(), c) {
			t.Errorf("%s, which proved checks and never believes, ends a message for good", c)
		}
	}
}

// A server that answers a post with any answer about a revocation that
// proved checks, and holds no revocation to show, has revoked nothing: the
// message stays in the outbox, the mailbox holds no revocation of its own, and
// the message goes once the server stops saying so. The answers are the
// code's own (provedCodes); at 403 sender_revoked the mailbox reads itself, once
// (PROTOCOL.md §12.5; #414 item 2).
func TestAServersWordAtAPostEndsNoMessage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range client.ProvedCodes() {
		t.Run(string(c), func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			post := postTo(b)
			var own atomic.Int32
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodPost && r.URL.Path == post {
					forge.Refuse(w, c)
					return
				}
				if r.Method == http.MethodGet && r.URL.Path == mailboxPath(a) {
					own.Add(1)
				}
				next.ServeHTTP(w, r)
			})
			_, err := a.Send(ctx, b.Address(), "from a mailbox the server says is revoked")
			if err == nil || finishedOwn(err) || !strings.Contains(err.Error(), "kept in the outbox") {
				t.Errorf("send: %v", err)
			}
			if n := own.Load(); c == protocol.CodeSenderRevoked && n != 1 {
				t.Errorf("the mailbox read itself %d times after the 403, want 1", n)
			}
			if st, serr := a.Status(ctx); serr != nil || st.Revoked || keptRevocation(a, b.Address()) {
				t.Errorf("a server's word was kept as a revocation: %+v, %v", st, serr)
			}
			if failed(a, b.Address()) != 0 {
				t.Error("a server's word ended the message: it is in outbox/failed/")
			}
			e.srv.SetMiddle(nil)
			if rs, err := a.Flush(ctx); err != nil || len(rs) != 1 {
				t.Fatalf("flush once the server stopped saying so: %v", err)
			}
			if res := receive(t, b); len(res.Delivered) != 1 {
				t.Fatal("the message never arrived")
			}
		})
	}
}

// What a server may show in place of a revocation, each of it signed by
// someone: none of it is the identity's own signature over that address's
// statement, so none of it revokes.
func TestWhatIsNotARevocationRevokesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	ofC, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byWorker, err := protocol.Sign(worker(t, b), protocol.RevocationStatement(b.Address()), protocol.RevokeNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	asPrekey, err := protocol.Sign(worker(t, b), protocol.RevocationStatement(b.Address()), protocol.PrekeyNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	doc := b.Identity().Document()
	for name, shown := range map[string]protocol.Revocations{
		"another mailbox's revocation":                             *ofC,
		"another mailbox's signature with this mailbox's document": {Identity: doc, Revocation: ofC.Revocation},
		"this mailbox's working key, under its own certificate":    {Identity: doc, Revocation: byWorker},
		"a signature in another namespace":                         {Identity: doc, Revocation: asPrekey},
		"a document and no signature":                              {Identity: doc},
		"nothing":                                                  {},
	} {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && r.URL.Path == "/v1/"+b.Address().String() {
				fakeserver.WriteJSON(w, http.StatusGone, protocol.Problem{Type: protocol.CodeRevoked.TypeURI(), Code: protocol.CodeRevoked, Status: http.StatusGone, Record: &shown})
				return
			}
			next.ServeHTTP(w, r)
		})
		_, err := a.Send(ctx, b.Address(), name)
		if err == nil || isRevoked(err, b.Address(), false) || !strings.Contains(err.Error(), "kept in the outbox") {
			t.Errorf("%s: %v", name, err)
		}
		if keptRevocation(a, b.Address()) {
			t.Fatalf("%s: kept as a revocation", name)
		}
	}
	e.srv.SetMiddle(nil)
	if rs, err := a.Flush(ctx); err != nil || len(rs) != 6 {
		t.Fatalf("flush: %d sent, %v", len(rs), err)
	}
}

// A revocation that verifies is final: the message can never be delivered,
// the revocation is kept, and a server that later serves the mailbox as if
// nothing had happened is not asked and not believed.
func TestARevocationIsCheckedAndSticks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	send(t, a, b, "pins B") // A holds B's identity and prekey from before
	revoke(t, e, b)

	_, err := a.Send(ctx, b.Address(), "after the revocation")
	if !isRevoked(err, b.Address(), false) || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("send to a revoked mailbox: %v", err)
	}
	if !keptRevocation(a, b.Address()) || failed(a, b.Address()) != 1 {
		t.Fatal("the revocation was not kept, or the message not moved to outbox/failed/")
	}

	// From here the server may say what it likes: A asks it nothing about B.
	var asked atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.Contains(r.URL.Path, b.Address().String()) {
			asked.Add(1)
		}
		next.ServeHTTP(w, r)
	})
	_, err = a.Send(ctx, b.Address(), "again")
	if !isRevoked(err, b.Address(), false) || asked.Load() != 0 {
		t.Fatalf("a second send: %v, after %d requests naming B", err, asked.Load())
	}
	if failed(a, b.Address()) != 2 {
		t.Fatal("the second message did not move to outbox/failed/")
	}
}

// A message from a mailbox that is then revoked is refused when it is read, whenever
// it was signed: nobody can vouch for when a signature was made. The server
// is asked once for each sender in a drain, and what it answered is kept, so
// a server that later hides the revocation and delivers that sender's messages is
// not believed.
func TestAMessageFromARevokedSenderIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	send(t, a, b, "delivered before anyone revoked")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("the first message was not delivered")
	}
	send(t, a, b, "waiting, one")
	send(t, a, b, "waiting, two")
	revoke(t, e, a)

	var lookups atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if _, ok := forge.ReadOf(r); ok {
			lookups.Add(1)
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 2 || res.Refused[0].Code != client.RefusedRevoked || res.Refused[1].Code != client.RefusedRevoked {
		t.Fatalf("a message from a revoked sender: %+v", res)
	}
	if lookups.Load() != 1 || !keptRevocation(b, a.Address()) || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("%d lookups for one sender; kept: %v; left on the server: %d", lookups.Load(), keptRevocation(b, a.Address()), e.srv.Count(b.Address()))
	}

	// The operator hides the revocation and delivers a message A's working key
	// signed, which its certificate still covers.
	forge.Hides(e.t, e.srv)
	line := e.line(a.Identity().Document(), a.Address(), b.Address(), "signed with a key that still verifies")
	e.seal(b, line, forge.Sign(t, worker(t, a), line, b.Address()))
	res = receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("after the server hid the revocation: %+v", res)
	}
}

// A drain reads each sender's mailbox once, however many of its messages it
// holds, from senders this mailbox holds no revocation of (PROTOCOL.md §12.3 check
// 8), whatever the read answered: a mailbox served, no such mailbox, or "revoked"
// with nothing that verifies (#447). The read marks the sender answered
// (readMailbox), and judge reads none it has marked. Above, the sender is
// revoked, so judge asks nothing after its first message, marked or not
// (#384).
func TestADrainReadsEachSendersMailboxOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	to, a, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	none, unproved := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	for range 3 {
		send(t, a, to, "from a")
	}
	for range 2 {
		send(t, c, to, "from c")
		send(t, none, to, "from a mailbox its server says it holds none of")
		send(t, unproved, to, "from a mailbox its server says is revoked, showing nothing")
	}
	op := watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		switch x, _ := forge.ReadOf(r); x {
		case none.Address():
			return answer(w, protocol.CodeNoSuchMailbox)
		case unproved.Address():
			return answer(w, protocol.CodeRevoked)
		}
		return false
	})
	if res := receive(t, to); len(res.Delivered) != 9 {
		t.Fatalf("delivered %d of 9", len(res.Delivered))
	}
	for name, from := range map[string]*client.Mailbox{
		"three messages, its mailbox served":      a,
		"two, its mailbox served":                 c,
		"two, no such mailbox":                    none,
		"two, revoked with nothing that verifies": unproved,
	} {
		if n := op.count(http.MethodGet, mailboxPath(from)); n != 1 {
			t.Errorf("a sender of %s: its mailbox read %d times, want 1", name, n)
		}
	}
}

// problemBad returns the answer/problem-bad-* vectors: bodies that are no
// problem as PROTOCOL.md §3.3 reads one, and so no code at all.
func problemBad(t *testing.T) []string {
	t.Helper()
	bad, _ := filepath.Glob("../testdata/vectors/answer/problem-bad-*.json")
	if len(bad) == 0 {
		t.Fatal("no answer/problem-bad-* vectors")
	}
	return bad
}

// outOfForm are answers that are none: a 304 to a request that sent no
// If-None-Match, and a code under a status that is not its own (#98).
var outOfForm = []struct {
	name  string
	write func(http.ResponseWriter)
}{
	{"a bare 304", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotModified) }},
	{"500 not_revoked", func(w http.ResponseWriter) { misstatused(w, http.StatusInternalServerError, protocol.CodeNotRevoked) }},
	{"429 no_such_mailbox", func(w http.ResponseWriter) { misstatused(w, http.StatusTooManyRequests, protocol.CodeNoSuchMailbox) }},
	{"429 revoked", func(w http.ResponseWriter) { misstatused(w, http.StatusTooManyRequests, protocol.CodeRevoked) }},
}

// misstatused writes a problem of code under status, which is not its own.
func misstatused(w http.ResponseWriter, status int, code protocol.Code) {
	fakeserver.WriteJSON(w, status, protocol.Problem{Type: code.TypeURI(), Code: code, Status: int64(status)})
}

// A server that gives no answer about a sender has not said the sender is
// fine. The drain stops, the message stays where it is, and the next drain
// asks again.
func TestNoAnswerAboutASenderStopsTheDrain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	send(t, a, b, "waits for an answer")
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == a.Address() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	res, err := b.Receive(context.Background())
	if err == nil || len(res.Delivered) != 0 || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1 {
		t.Fatalf("a drain with no answer: %v, %+v, %d left on the server", err, res, e.srv.Count(b.Address()))
	}
	if q, _ := os.ReadDir(filepath.Join(b.Dir(), "refused")); len(q) != 0 {
		t.Fatal("a message nobody could judge was kept in refused/")
	}
	// Nor has a 2xx whose body is no mailbox, as PROTOCOL.md §3.3 reads one.
	bad, _ := filepath.Glob("../testdata/vectors/answer/mailbox-bad-*.json")
	if len(bad) == 0 {
		t.Fatal("no answer/mailbox-bad-* vectors")
	}
	for _, f := range bad {
		body, err := os.ReadFile(f) //nolint:gosec // a test vector
		if err != nil {
			t.Fatal(err)
		}
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
				return
			}
			next.ServeHTTP(w, r)
		})
		res, err := b.Receive(context.Background())
		if err == nil || len(res.Delivered) != 0 || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1 {
			t.Errorf("%s served as the answer: %v, %+v, %d left on the server", filepath.Base(f), err, res, e.srv.Count(b.Address()))
		}
	}
	// Nor has a 404 whose body is no problem as PROTOCOL.md §3.3 reads one,
	// though its code says not_revoked before the member that breaks it.
	for _, f := range problemBad(t) {
		body, _ := os.ReadFile(f) //nolint:gosec // a test vector
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(body)
				return
			}
			next.ServeHTTP(w, r)
		})
		res, err := b.Receive(context.Background())
		if err == nil || len(res.Delivered) != 0 || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1 {
			t.Errorf("404 %s on the read: %v, %+v, %d left on the server", filepath.Base(f), err, res, e.srv.Count(b.Address()))
		}
	}
	// Nor has an answer out of its form: a bare 304, or a code under
	// another status.
	for _, o := range outOfForm {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				o.write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
		res, err := b.Receive(context.Background())
		if err == nil || len(res.Delivered) != 0 || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1 {
			t.Errorf("%s on the read: %v, %+v, %d left on the server", o.name, err, res, e.srv.Count(b.Address()))
		}
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("once the server answered: %+v", res)
	}
}

// A revocation handed over by a person is worth what one from a server is:
// it proves itself. That is the answer to a server that hides one.
func TestARevocationHandedOver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	rec, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The server knows of no revocation of B, and serves B as ever.
	ofC, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*protocol.Revocations{
		"another mailbox's signature": {Identity: rec.Identity, Revocation: ofC.Revocation},
		"no signature":                {Identity: rec.Identity},
	} {
		if _, _, err := a.KeepRevocation(t.Context(), bad); err == nil || keptRevocation(a, b.Address()) {
			t.Fatalf("%s was kept as a revocation: %v", name, err)
		}
	}
	if got, held, err := a.KeepRevocation(t.Context(), rec); err != nil || got != b.Address() || !held.Revoked || held.Certificates != nil {
		t.Fatalf("keeping a good record: %v", err)
	}
	var asked atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		asked.Add(1)
		next.ServeHTTP(w, r)
	})
	if _, err := a.Send(ctx, b.Address(), "to a mailbox revoked out of band"); !isRevoked(err, b.Address(), false) || asked.Load() != 0 {
		t.Fatalf("send: %v, after %d requests", err, asked.Load())
	}
	// And a message B's key still signs is refused, though the server delivers it.
	e.srv.SetMiddle(nil)
	send(t, b, a, "from a mailbox revoked out of band")
	if res := receive(t, a); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("a message from it: %+v", res)
	}
}

// A mailbox that is revoked learns it the same way, by the proof: it then knows
// it is finished, and says so. One whose server only says so knows better.
func TestAMailboxLearnsItIsRevoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)

	says(e, protocol.CodeRevoked, http.MethodGet, "/v1/"+a.Address().String()+"/messages")
	if _, err := a.Receive(ctx); err == nil || isRevoked(err, a.Address(), true) || !strings.Contains(err.Error(), "no revocation") {
		t.Fatalf("a mailbox told it is revoked, with nothing shown: %v", err)
	}
	if st, err := a.Status(t.Context()); err != nil || st.Revoked {
		t.Fatalf("status after a server's word: %+v, %v", st, err)
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, a); res == nil {
		t.Fatal("the mailbox does not work once the server stops saying so")
	}

	revoke(t, e, a)
	if _, err := a.Receive(ctx); !isRevoked(err, a.Address(), true) {
		t.Fatalf("a revoked mailbox's drain: %v", err)
	}
	st, err := a.Status(t.Context())
	if err != nil || !st.Revoked || len(st.Attention) == 0 || !strings.Contains(st.Attention[0], "revoked") {
		t.Fatalf("status of a revoked mailbox: %+v, %v", st, err)
	}
	if _, err := a.Send(ctx, b.Address(), "from a revoked mailbox"); !isRevoked(err, a.Address(), true) || failed(a, b.Address()) != 0 {
		t.Fatalf("a revoked mailbox's send: %v", err)
	}
}

// Every 410 revoked carries the record its server answered from (PROTOCOL.md
// §12.5; #353), at a send to a revoked mailbox, at a revoked mailbox's poll, and at
// the publish of a revocation it holds already. One that verifies is taken
// as the read's is, with no second call. Where an operator puts none in its
// place, or another mailbox's revocation, the mailbox reads the mailbox the call named,
// once, and takes it as revoked only because what that read carries
// verifies.
func TestA410CarriesTheRecord(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	ctx := context.Background()
	type call struct{ method, path string }
	for _, at := range []struct {
		name string
		// do revokes a mailbox in env e and makes the call a 410 answers,
		// through forged, the middleware that answers that call. It returns
		// the call, the mailbox the call named, and its error.
		do func(t *testing.T, e *env, forged func(w http.ResponseWriter, r *http.Request, next http.Handler)) (call, protocol.Address, error)
		// revoked is what a mailbox makes of a 410 whose record verifies.
		revoked func(t *testing.T, err error, named protocol.Address)
	}{
		{"a send's", func(t *testing.T, e *env, forged func(http.ResponseWriter, *http.Request, http.Handler)) (call, protocol.Address, error) {
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			revoke(t, e, b)
			post := call{http.MethodPost, "/v1/" + b.Address().String() + "/messages"}
			read := false
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				switch at, ok := forge.ReadOf(r); {
				case ok && at == b.Address() && !read: // the read before the post serves B as it was
					read = true
					e.serve(w, r, next, func(*protocol.MailboxResponse) {})
				case r.Method == post.method && r.URL.Path == post.path:
					forged(w, r, next)
				default:
					next.ServeHTTP(w, r)
				}
			})
			_, err := a.Send(ctx, b.Address(), "to a mailbox revoked since its read")
			if failed(a, b.Address()) != 1 || !keptRevocation(a, b.Address()) {
				t.Errorf("the message was not moved to outbox/failed/, or the revocation not kept: %v", err)
			}
			return post, b.Address(), err
		}, func(t *testing.T, err error, named protocol.Address) {
			if !isRevoked(err, named, false) {
				t.Errorf("send: %v", err)
			}
		}},
		{"a poll's", func(t *testing.T, e *env, forged func(http.ResponseWriter, *http.Request, http.Handler)) (call, protocol.Address, error) {
			a := e.mailbox(protocol.Classic)
			revoke(t, e, a)
			poll := call{http.MethodGet, "/v1/" + a.Address().String() + "/messages"}
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == poll.method && r.URL.Path == poll.path {
					forged(w, r, next)
					return
				}
				next.ServeHTTP(w, r)
			})
			_, err := a.Receive(ctx)
			if st, serr := a.Status(t.Context()); serr != nil || !st.Revoked {
				t.Errorf("status after the poll: %+v, %v", st, serr)
			}
			return poll, a.Address(), err
		}, func(t *testing.T, err error, named protocol.Address) {
			if !isRevoked(err, named, true) {
				t.Errorf("the poll: %v", err)
			}
		}},
		{"a publish's", func(t *testing.T, e *env, forged func(http.ResponseWriter, *http.Request, http.Handler)) (call, protocol.Address, error) {
			a := e.mailbox(protocol.Classic)
			rec := revoke(t, e, a)
			put := call{http.MethodPut, "/v1/" + a.Address().String() + "/revocations"}
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == put.method && r.URL.Path == put.path {
					forged(w, r, next)
					return
				}
				next.ServeHTTP(w, r)
			})
			_, err := client.Revoke(ctx, e.opts(), rec)
			return put, a.Address(), err
		}, func(t *testing.T, err error, _ protocol.Address) {
			if err != nil {
				t.Errorf("published again to a server that holds it: %v", err)
			}
		}},
	} {
		for _, c := range []struct {
			name  string
			carry func(t *testing.T, e *env) func(http.ResponseWriter, *http.Request, http.Handler)
			reads int // of the mailbox named, after the 410
		}{
			{"its own record", func(*testing.T, *env) func(http.ResponseWriter, *http.Request, http.Handler) {
				return func(w http.ResponseWriter, r *http.Request, next http.Handler) { next.ServeHTTP(w, r) }
			}, 0},
			{"no record", func(*testing.T, *env) func(http.ResponseWriter, *http.Request, http.Handler) {
				return func(w http.ResponseWriter, r *http.Request, next http.Handler) { forge.Carry(w, r, next, nil) }
			}, 1},
			{"another mailbox's revocation", func(t *testing.T, e *env) func(http.ResponseWriter, *http.Request, http.Handler) {
				ofC, err := e.mailbox(protocol.Classic).Revocation(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				return func(w http.ResponseWriter, r *http.Request, next http.Handler) { forge.Carry(w, r, next, ofC) }
			}, 1},
		} {
			t.Run(at.name+" 410 with "+c.name, func(t *testing.T) {
				e := newEnv(t)
				made, named, err := at.do(t, e, c.carry(t, e))
				at.revoked(t, err, named)
				log, after, reads := e.srv.Requests(), -1, 0
				for i, r := range log {
					switch {
					case r.Method == made.method && r.Path == made.path:
						after = i
					case after >= 0 && r.Method == http.MethodGet && r.Path == "/v1/"+named.String():
						reads++
					}
				}
				if after < 0 || reads != c.reads {
					t.Errorf("%d reads of the mailbox named after the 410, want %d: %+v", reads, c.reads, log)
				}
			})
		}
	}
}

// Revoking is checked before it is sent, takes no key but the record, and
// doing it twice changes nothing.
func TestRevokeTakesOnlyARecordThatVerifies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	rec, err := a.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byWorker, err := protocol.Sign(worker(t, a), protocol.RevocationStatement(a.Address()), protocol.RevokeNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		asked.Add(1)
		next.ServeHTTP(w, r)
	})
	for name, bad := range map[string]*protocol.Revocations{
		"a working key's signature":  {Identity: rec.Identity, Revocation: byWorker},
		"another mailbox's document": {Identity: b.Identity().Document(), Revocation: rec.Revocation},
		"a record with no signature": {Identity: rec.Identity},
	} {
		if _, err := client.Revoke(ctx, e.opts(), bad); err == nil || asked.Load() != 0 {
			t.Fatalf("%s was published: %v, %d requests", name, err, asked.Load())
		}
	}
	e.srv.SetMiddle(nil)
	// The server refuses what a client should never send.
	if _, err := protocolPut(e, a.Address(), &protocol.Revocations{Identity: rec.Identity, Revocation: byWorker}); client.Code(err) != protocol.CodeBadRevocation {
		t.Fatalf("a working key's signature, put to the server: %v", err)
	}
	send(t, b, a, "in A's mailbox when it is revoked")
	for range 2 {
		if _, err := client.Revoke(ctx, e.opts(), rec); err != nil {
			t.Fatalf("revoke: %v", err)
		}
	}
	if e.srv.Count(a.Address()) != 0 {
		t.Fatal("a revoked mailbox still holds messages")
	}
	if _, err := b.Send(ctx, a.Address(), "to the revoked mailbox"); !isRevoked(err, a.Address(), false) {
		t.Fatalf("send to it: %v", err)
	}
}

// protocolPut puts a record to the fake server as it is, with no check on
// this side: what a client that skipped its own check would do.
func protocolPut(e *env, a protocol.Address, rec *protocol.Revocations) (*http.Response, error) {
	return client.PutRevocations(context.Background(), e.opts(), a, rec)
}
