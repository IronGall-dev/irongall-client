package client_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box is revoked by its identity's own signature, and by nothing else. So
// a client takes "revoked" from a server only with the revocation in hand,
// keeps it once it has verified, and takes no server's word against it
// afterwards. These tests play the operator both ways: one that says revoked
// where nothing is, and one that hides a revocation that exists.

// revoke publishes b's own revocation, as its owner would.
func revoke(t *testing.T, e *env, b *client.Box) *protocol.Revocations {
	t.Helper()
	rec, err := b.Revocation()
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

func keptRevocation(a *client.Box, of protocol.Address) bool {
	_, ok := stateOf(a, "peers/"+of.String()+"/revoke.sig")
	return ok
}

func failed(a *client.Box, to protocol.Address) int {
	m, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", to.String()+".*.P"))
	return len(m)
}

func isRevoked(err error, a protocol.Address, own bool) bool {
	var gone *client.RevokedError
	return errors.As(err, &gone) && gone.Address == a && gone.Own == own
}

// A server that says a box is revoked, and has no revocation to show, has
// revoked nothing: the message stays in the outbox and goes when the server
// lets it.
func TestAServersWordRevokesNothing(t *testing.T) {
	ctx := context.Background()
	for _, where := range []struct{ name, method, suffix string }{
		{"at the read of the box", http.MethodGet, ""},
		{"at the send", http.MethodPost, "/messages"},
	} {
		t.Run(where.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			says(e, protocol.CodeRevoked, where.method, "/v1/"+b.Address().String()+where.suffix)
			_, err := a.Send(ctx, b.Address(), "to a box the server calls revoked")
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

// What a server may show in place of a revocation, each of it signed by
// someone: none of it is the identity's own signature over that address's
// statement, so none of it revokes.
func TestWhatIsNotARevocationRevokesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	ofC, err := c.Revocation()
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
		"another box's revocation":                          *ofC,
		"another box's signature with this box's document":  {Identity: doc, Revocation: ofC.Revocation},
		"this box's working key, under its own certificate": {Identity: doc, Revocation: byWorker},
		"a signature in another namespace":                  {Identity: doc, Revocation: asPrekey},
		"a document and no signature":                       {Identity: doc},
		"nothing":                                           {},
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
// the revocation is kept, and a server that later serves the box as if
// nothing had happened is not asked and not believed.
func TestARevocationIsCheckedAndSticks(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "pins B") // A holds B's identity and prekey from before
	revoke(t, e, b)

	_, err := a.Send(ctx, b.Address(), "after the revocation")
	if !isRevoked(err, b.Address(), false) || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("send to a revoked box: %v", err)
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

// Mail from a box that is then revoked is refused when it is read, whenever
// it was signed: nobody can vouch for when a signature was made. The server
// is asked once for each sender in a drain, and what it answered is kept, so
// a server that later hides the revocation and delivers that sender's mail is
// not believed.
func TestMailFromARevokedSenderIsRefused(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
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
		t.Fatalf("mail from a revoked sender: %+v", res)
	}
	if lookups.Load() != 1 || !keptRevocation(b, a.Address()) || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("%d lookups for one sender; kept: %v; left on the server: %d", lookups.Load(), keptRevocation(b, a.Address()), e.srv.Count(b.Address()))
	}

	// The operator hides the revocation and delivers mail A's working key
	// signed, which its certificate still covers.
	forge.Hides(e.t, e.srv)
	line := e.line(a.Identity().Document(), a.Address(), b.Address(), "signed with a key that still verifies")
	e.seal(b, a.Address(), line, forge.Sign(t, worker(t, a), line, b.Address()))
	res = receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("after the server hid the revocation: %+v", res)
	}
}

// problemBad returns the answer/problem-bad-* vectors: bodies that are no
// problem as PROTOCOL.md §0b reads one, and so no code at all.
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
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
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
	if q, _ := os.ReadDir(filepath.Join(b.Dir(), "quarantine")); len(q) != 0 {
		t.Fatal("a message nobody could judge was quarantined")
	}
	// Nor has a 2xx whose body is no box, as PROTOCOL.md §0b reads one.
	bad, _ := filepath.Glob("../testdata/vectors/answer/box-bad-*.json")
	if len(bad) == 0 {
		t.Fatal("no answer/box-bad-* vectors")
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
	// Nor has a 404 whose body is no problem as PROTOCOL.md §0b reads one,
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
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	rec, err := b.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	// The server knows of no revocation of B, and serves B as ever.
	ofC, err := c.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*protocol.Revocations{
		"another box's signature": {Identity: rec.Identity, Revocation: ofC.Revocation},
		"no signature":            {Identity: rec.Identity},
	} {
		if _, _, err := a.KeepRevocation(bad); err == nil || keptRevocation(a, b.Address()) {
			t.Fatalf("%s was kept as a revocation: %v", name, err)
		}
	}
	if got, held, err := a.KeepRevocation(rec); err != nil || got != b.Address() || !held.Revoked || held.Certificates != nil {
		t.Fatalf("keeping a good record: %v", err)
	}
	var asked atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		asked.Add(1)
		next.ServeHTTP(w, r)
	})
	if _, err := a.Send(ctx, b.Address(), "to a box revoked out of band"); !isRevoked(err, b.Address(), false) || asked.Load() != 0 {
		t.Fatalf("send: %v, after %d requests", err, asked.Load())
	}
	// And mail B's key still signs is refused, though the server delivers it.
	e.srv.SetMiddle(nil)
	send(t, b, a, "from a box revoked out of band")
	if res := receive(t, a); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("mail from it: %+v", res)
	}
}

// A box that is revoked learns it the same way, by the proof: it then knows
// it is finished, and says so. One whose server only says so knows better.
func TestABoxLearnsItIsRevoked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)

	says(e, protocol.CodeRevoked, http.MethodGet, "/v1/"+a.Address().String()+"/messages")
	if _, err := a.Receive(ctx); err == nil || isRevoked(err, a.Address(), true) || !strings.Contains(err.Error(), "no revocation") {
		t.Fatalf("a box told it is revoked, with nothing shown: %v", err)
	}
	if st, err := a.Status(); err != nil || st.Revoked {
		t.Fatalf("status after a server's word: %+v, %v", st, err)
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, a); res == nil {
		t.Fatal("the box does not work once the server stops saying so")
	}

	revoke(t, e, a)
	if _, err := a.Receive(ctx); !isRevoked(err, a.Address(), true) {
		t.Fatalf("a revoked box's drain: %v", err)
	}
	st, err := a.Status()
	if err != nil || !st.Revoked || len(st.Attention) == 0 || !strings.Contains(st.Attention[0], "revoked") {
		t.Fatalf("status of a revoked box: %+v, %v", st, err)
	}
	if _, err := a.Send(ctx, b.Address(), "from a revoked box"); !isRevoked(err, a.Address(), true) || failed(a, b.Address()) != 0 {
		t.Fatalf("a revoked box's send: %v", err)
	}
}

// Revoking is checked before it is sent, takes no key but the record, and
// doing it twice changes nothing.
func TestRevokeTakesOnlyARecordThatVerifies(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	rec, err := a.Revocation()
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
		"another box's document":     {Identity: b.Identity().Document(), Revocation: rec.Revocation},
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
	send(t, b, a, "in A's box when it is revoked")
	for range 2 {
		if _, err := client.Revoke(ctx, e.opts(), rec); err != nil {
			t.Fatalf("revoke: %v", err)
		}
	}
	if e.srv.Count(a.Address()) != 0 {
		t.Fatal("a revoked box still holds mail")
	}
	if _, err := b.Send(ctx, a.Address(), "to the revoked box"); !isRevoked(err, a.Address(), false) {
		t.Fatalf("send to it: %v", err)
	}
}

// protocolPut puts a record to the fake server as it is, with no check on
// this side: what a client that skipped its own check would do.
func protocolPut(e *env, a protocol.Address, rec *protocol.Revocations) (*http.Response, error) {
	return client.PutRevocations(context.Background(), e.opts(), a, rec)
}
