package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box asks what the server holds about an address before it posts to it,
// keeps what verifies, and checks the send against what it then holds. These
// tests play a box whose working key was taken, and an operator that serves
// its senders the statement the thief can read mail under.

// operator stands between the boxes and the server: it records every request
// as "METHOD path", and answers one itself when its rule does.
type operator struct {
	mu   sync.Mutex
	seen []string
	rule func(w http.ResponseWriter, r *http.Request) bool
}

// watch puts an operator in front of the server. rule may be nil.
func watch(e *env, rule func(w http.ResponseWriter, r *http.Request) bool) *operator {
	o := &operator{rule: rule}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		o.mu.Lock()
		o.seen = append(o.seen, r.Method+" "+r.URL.Path)
		o.mu.Unlock()
		if o.rule != nil && o.rule(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
	return o
}

// count returns how many requests were made with this method to a path with
// this suffix.
func (o *operator) count(method, suffix string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, s := range o.seen {
		if strings.HasPrefix(s, method+" ") && strings.HasSuffix(s, suffix) {
			n++
		}
	}
	return n
}

func answer(w http.ResponseWriter, code protocol.Code) bool {
	fakeserver.WriteJSON(w, code.Status(), protocol.Problem{Code: code, Status: int64(code.Status())})
	return true
}

func lookupOf(a *client.Box) string { return "/v1/" + a.Address().String() + "/revocations" }
func postTo(a *client.Box) string   { return "/v1/" + a.Address().String() }

// waiting returns how many entries a box's outbox holds for an address, and
// how many files it keeps for them beside their envelopes: none, since a
// seal is made for one post and never kept.
func waiting(b *client.Box, to protocol.Address) (entries, beside int) {
	p, _ := filepath.Glob(filepath.Join(b.Dir(), "outbox", to.String()+".*.P"))
	all, _ := filepath.Glob(filepath.Join(b.Dir(), "outbox", to.String()+".*"))
	return len(p), len(all) - len(p)
}

// theft plays a taken working key: it returns the statement A published
// under its first certificate, as the thief's, then has A renew and revoke
// that certificate. The address goes on.
func theft(t *testing.T, e *env, a *client.Box) (statement, signature []byte) {
	t.Helper()
	statement, signature = e.srv.Prekey(a.Address())
	taken := numberOf(t, a)
	if _, err := a.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if certs, err := a.RevokeEarlier(context.Background()); err != nil || certs == nil || !certs.Revokes(taken) || certs.Revokes(numberOf(t, a)) {
		t.Fatalf("revoke earlier: %+v, %v", certs, err)
	}
	return statement, signature
}

// helpsTheThief is an operator that serves A's senders the old statement,
// and takes whatever is then posted to A. With hide it also answers that it
// holds nothing about A.
func helpsTheThief(e *env, a *client.Box, statement, signature []byte, hide bool) *operator {
	return watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == postTo(a)+"/identity":
			fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: a.Identity().Document(), Prekey: statement, PrekeySignature: signature})
		case r.Method == http.MethodPost && r.URL.Path == postTo(a):
			fakeserver.Take(w, r)
		case hide && r.Method == http.MethodGet && r.URL.Path == lookupOf(a):
			return answer(w, protocol.CodeNotRevoked)
		default:
			return false
		}
		return true
	})
}

// A sender that has never read a box's mail holds nothing about it. Asked
// before the send, the server shows the box's list, and the sender then
// refuses the statement under the revoked certificate: nothing is posted.
// What the sender learned stands when the server later hides it.
func TestASenderAsksBeforeItSends(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	taken := numberOf(t, a)
	statement, signature := theft(t, e, a)

	// The control: a sender shown no list takes the old statement, and its
	// mail goes to the prekey the thief holds. This is what asking is for,
	// and what a server that hides the list can still do to a sender that
	// has never seen it.
	blind := e.box(protocol.Classic)
	op := helpsTheThief(e, a, statement, signature, true)
	if _, err := blind.Send(ctx, a.Address(), "to whoever holds the old prekey"); err != nil {
		t.Fatalf("a sender shown no list: %v", err)
	}
	if op.count(http.MethodGet, lookupOf(a)) != 1 || op.count(http.MethodPost, postTo(a)) != 1 {
		t.Fatalf("a sender shown no list asked once and posted once: %q", op.seen)
	}

	// The same operator, with the list not hidden: the sender asks first.
	b := e.box(protocol.Classic)
	op = helpsTheThief(e, a, statement, signature, false)
	_, err := b.Send(ctx, a.Address(), "never posted")
	if err == nil || !strings.Contains(err.Error(), "under a certificate its identity has revoked") || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("a send to a statement under a revoked certificate: %v", err)
	}
	if op.count(http.MethodPost, postTo(a)) != 0 || !keptList(b, a.Address()) || keptRevocation(b, a.Address()) {
		t.Fatalf("it was posted, or the list was not kept: %q", op.seen)
	}
	if n, beside := waiting(b, a.Address()); n != 1 || beside != 0 || failed(b, a.Address()) != 0 {
		t.Fatalf("the message is not waiting as its envelope alone in the outbox: %d, %d", n, beside)
	}

	// What a box learned while the server showed it holds after the server
	// hides it: C asked once, at no send, and has never seen a statement of
	// A's, so nothing but the list it keeps refuses the old one.
	c := e.box(protocol.Classic)
	e.srv.SetMiddle(nil)
	held, err := c.Ask(ctx, a.Address())
	if err != nil || held.Revoked || held.Certificates == nil || !held.Certificates.Revokes(taken) || held.Certificates.Revokes(numberOf(t, a)) {
		t.Fatalf("ask: %+v, %v", held, err)
	}
	op = helpsTheThief(e, a, statement, signature, true)
	if _, err := c.Send(ctx, a.Address(), "never posted either"); err == nil || !strings.Contains(err.Error(), "under a certificate its identity has revoked") {
		t.Fatalf("a send after the server turned: %v", err)
	}
	if op.count(http.MethodPost, postTo(a)) != 0 {
		t.Fatalf("it was posted: %q", op.seen)
	}

	// With an honest server the message that waited goes, to the statement
	// under the certificate in use.
	e.srv.SetMiddle(nil)
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "never posted" {
		t.Fatalf("the box that revoked its old certificate got: %+v", res)
	}
}

// No answer is not "none held": with no answer about the recipient nothing
// is posted and nothing is sealed, and the message waits. Whatever code the
// failed lookup carries is never read as an answer about the message.
func TestNoAnswerAboutARecipientPostsNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)

	op := watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == lookupOf(a) {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	_, err := b.Send(ctx, a.Address(), "waits for an answer")
	if err == nil || !strings.Contains(err.Error(), "could not be asked") || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("a send with no answer about its recipient: %v", err)
	}
	if op.count(http.MethodPost, postTo(a)) != 0 || op.count(http.MethodGet, "/identity") != 0 {
		t.Fatalf("something was asked or posted after no answer: %q", op.seen)
	}
	if n, beside := waiting(b, a.Address()); n != 1 || beside != 0 {
		t.Fatalf("the outbox: %d entries, %d files beside them", n, beside)
	}

	// A code that would end a message, had the post been answered with it.
	for _, code := range []protocol.Code{protocol.CodeBadAddress, protocol.CodeTooLarge, protocol.CodeConflict, protocol.CodeRevoked} {
		op = watch(e, func(w http.ResponseWriter, r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == lookupOf(a) && answer(w, code)
		})
		if _, err := b.Flush(ctx); err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
			t.Fatalf("a lookup answered %s: %v", code, err)
		}
		if n, _ := waiting(b, a.Address()); n != 1 || failed(b, a.Address()) != 0 || op.count(http.MethodPost, postTo(a)) != 0 || keptRevocation(b, a.Address()) {
			t.Fatalf("a lookup answered %s moved the message, posted it, or revoked the address: %q", code, op.seen)
		}
	}
	// A 404 whose body breaks §0b carries no code, though it says
	// not_revoked before the member that breaks it.
	for _, f := range problemBad(t) {
		body, _ := os.ReadFile(f) //nolint:gosec // a test vector
		op = watch(e, func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodGet || r.URL.Path != lookupOf(a) {
				return false
			}
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(body)
			return true
		})
		if _, err := b.Flush(ctx); err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
			t.Fatalf("a lookup answered 404 %s: %v", filepath.Base(f), err)
		}
		if n, _ := waiting(b, a.Address()); n != 1 || op.count(http.MethodPost, postTo(a)) != 0 {
			t.Fatalf("a lookup answered 404 %s moved the message or posted it: %q", filepath.Base(f), op.seen)
		}
	}

	e.srv.SetMiddle(nil)
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush with an answer: %v, %v", got, err)
	}
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("delivered: %+v", res)
	}
}

// postFails answers every post to a box with a 503, and lets the rest
// through.
func postFails(e *env, a *client.Box) {
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == postTo(a) {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
}

// A message can wait in the outbox for days. What waits is its envelope: a
// seal is made for one post, to what the box holds then, and never kept. So
// a message that waited goes under the recipient's statement in use at the
// flush: never to a prekey under a certificate since revoked, never to one
// ordered before a renewal the box has recorded since, and never to an
// address since revoked.
func TestAMessageThatWaitedIsSealedAtThePost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)

	postFails(e, a)
	if _, err := b.Send(ctx, a.Address(), "written under the first certificate"); err == nil {
		t.Fatal("the post was meant to fail")
	}
	if n, beside := waiting(b, a.Address()); n != 1 || beside != 0 {
		t.Fatalf("the outbox: %d entries, %d files beside them", n, beside)
	}
	statement, signature := theft(t, e, a)

	// The operator still serves the old statement, and would take a post to
	// its prekey. The box asks, learns of the revocation, and posts nothing:
	// the statement on offer is refused.
	op := helpsTheThief(e, a, statement, signature, false)
	if _, err := b.Flush(ctx); err == nil || !strings.Contains(err.Error(), "under a certificate its identity has revoked") {
		t.Fatalf("a flush with a statement under a revoked certificate on offer: %v", err)
	}
	if op.count(http.MethodPost, postTo(a)) != 0 {
		t.Fatalf("something was posted: %q", op.seen)
	}
	if n, _ := waiting(b, a.Address()); n != 1 || failed(b, a.Address()) != 0 {
		t.Fatal("the message did not stay in the outbox")
	}

	// With an honest server it is sealed to the statement in use: one post,
	// naming the certificate in use.
	var posted [][]byte
	watch(e, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == postTo(a) {
			body, _ := io.ReadAll(r.Body)
			posted = append(posted, body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		return false
	})
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	var req struct {
		CertificateSerial uint64 `json:"certificate_serial"`
	}
	if len(posted) != 1 || json.Unmarshal(posted[0], &req) != nil || req.CertificateSerial != numberOf(t, a) {
		t.Fatalf("%d posts, the first under certificate %d", len(posted), req.CertificateSerial)
	}
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "written under the first certificate" {
		t.Fatalf("delivered: %+v", res)
	}

	// An address revoked while a message waits: nothing is posted.
	c := e.box(protocol.Classic)
	postFails(e, c)
	if _, err := b.Send(ctx, c.Address(), "written before the address was revoked"); err == nil {
		t.Fatal("the post was meant to fail")
	}
	revoke(t, e, c)
	// This operator would take the post, where an honest server refuses it.
	op = watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == postTo(c) {
			fakeserver.Take(w, r)
			return true
		}
		return false
	})
	if _, err := b.Flush(ctx); !isRevoked(err, c.Address(), false) || !strings.Contains(err.Error(), "moved to outbox/failed/") {
		t.Fatalf("a flush to an address since revoked: %v", err)
	}
	if op.count(http.MethodPost, postTo(c)) != 0 || failed(b, c.Address()) != 1 || !keptRevocation(b, c.Address()) {
		t.Fatalf("it was posted, or not moved, or the revocation was not kept: %q", op.seen)
	}
}

// A message that waited while its recipient renewed, revoking nothing, goes
// under the renewal once the box has recorded it, whatever the server takes:
// here one that takes any post, as a server need not answer stale_prekey
// (#91: a seal kept from before the renewal was posted as it was).
func TestAMessageThatWaitedGoesUnderTheRenewalTheBoxRecorded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	postFails(e, a)
	if _, err := b.Send(ctx, a.Address(), "written under the first certificate"); err == nil {
		t.Fatal("the post was meant to fail")
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx, ""); err != nil { // a later certificate, nothing revoked
		t.Fatal(err)
	}
	if _, err := b.Send(ctx, a.Address(), "the box records the renewal"); err != nil {
		t.Fatal(err)
	}
	var posted []uint64
	watch(e, func(w http.ResponseWriter, r *http.Request) bool { // takes every post to a
		if r.Method != http.MethodPost || r.URL.Path != postTo(a) {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		var req protocol.SendRequest
		if protocol.Unmarshal(body, &req) == nil && req.CertificateSerial != nil {
			posted = append(posted, *req.CertificateSerial)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		fakeserver.Take(w, r)
		return true
	})
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	if len(posted) != 1 || posted[0] != numberOf(t, a) {
		t.Fatalf("posted under certificates %v after recording %d", posted, numberOf(t, a))
	}
}

// A message that waited while its own box ran the remedy for a taken working
// key is signed at the flush by the working key in use, under the new
// certificate, and delivered: a seal kept from before was posted under the
// certificate the remedy revoked, recorded as sent, and refused by its
// reader (#112).
func TestAMessageThatWaitedThroughTheRemedyIsSignedUnderTheNewCertificate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	first := numberOf(t, b)
	postFails(e, a)
	if _, err := b.Send(ctx, a.Address(), "written before the owner's remedy"); err == nil {
		t.Fatal("the post was meant to fail")
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(2 * time.Second)
	r, err := b.RenewAndRevoke(ctx, "") // irongall cert revoke-earlier
	if err != nil || r.Revoked == nil || !r.Revoked.Revokes(first) || r.Revoked.Revokes(numberOf(t, b)) {
		t.Fatalf("remedy: %+v, %v", r, err)
	}
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	res := receive(t, a)
	if len(res.Delivered) != 1 || len(res.Refused) != 0 || bodyOf(t, res.Delivered[0]) != "written before the owner's remedy" {
		t.Fatalf("its reader: %+v", res)
	}
}

// A message whose post was taken but whose answer was lost is posted again
// at the flush, sealed afresh: a new ciphertext, which the server stores and
// counts as new mail, and which its reader drops by its msg_id. Delivered
// once; the cost of the lost answer is one more send.
func TestALostAnswerCostsASendAndDeliversOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	lost := true
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && r.URL.Path == postTo(a) && lost {
			lost = false
			next.ServeHTTP(httptest.NewRecorder(), r) // stored, and the answer never comes
			http.Error(w, "the answer was lost", http.StatusBadGateway)
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Send(ctx, a.Address(), "posted once, answered never"); err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("the answer was meant to be lost: %v", err)
	}
	if e.srv.Count(a.Address()) != 1 {
		t.Fatal("the first post was not stored")
	}
	if got, err := b.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	if n, _ := waiting(b, a.Address()); n != 0 {
		t.Fatal("the message is still in the outbox")
	}
	if e.srv.Count(a.Address()) != 2 {
		t.Fatalf("the server holds %d: the flush was not a new ciphertext stored apart", e.srv.Count(a.Address()))
	}
	res := receive(t, a)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "posted once, answered never" {
		t.Fatalf("delivered: %+v", res)
	}
	if left := e.srv.Count(a.Address()); left != 0 {
		t.Fatalf("%d messages left on the server: the copy was not acked", left)
	}
}

// A send asks once, and a flush once for each recipient, however many
// messages wait for it.
func TestAFlushAsksOnceForEachRecipient(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)

	op := watch(e, nil)
	send(t, b, a, "one send")
	if n := op.count(http.MethodGet, lookupOf(a)); n != 1 {
		t.Fatalf("a send asked %d times: %q", n, op.seen)
	}

	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	for _, to := range []*client.Box{a, a, c, a} {
		if _, err := b.Send(ctx, to.Address(), "waits"); err == nil {
			t.Fatal("the post was meant to fail")
		}
	}
	op = watch(e, nil)
	if got, err := b.Flush(ctx); err != nil || len(got) != 4 {
		t.Fatalf("flush: %v, %v", got, err)
	}
	if na, nc := op.count(http.MethodGet, lookupOf(a)), op.count(http.MethodGet, lookupOf(c)); na != 1 || nc != 1 {
		t.Fatalf("a flush of three messages to one box and one to another asked %d and %d times", na, nc)
	}
}

// throughOf is the serial a record's revocation of certificates runs
// through, read from its statement.
func throughOf(t *testing.T, rec *protocol.Revocations) uint64 {
	t.Helper()
	certs, err := protocol.ParseRevokedCertificates(rec.RevokedCertificates)
	if err != nil {
		t.Fatalf("the record's revocation of certificates: %v", err)
	}
	return certs.Through
}

// record fetches what the server holds about a box, as anyone can.
func record(t *testing.T, e *env, a *client.Box) *protocol.Revocations {
	t.Helper()
	resp, err := http.Get(e.srv.URL + lookupOf(a))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read only
	var rec protocol.Revocations
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&rec) != nil {
		t.Fatalf("the record of %s: %d", a.Address(), resp.StatusCode)
	}
	return &rec
}

// A box may ask at any time, and a record may come from anywhere: a
// revocation of certificates handed over in a file is kept as one from a
// server is. The highest serial it runs through stands, and a record with a
// part that does not verify is refused whole.
func TestAskingAtAnyTimeAndARevocationHandedOver(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)

	if held, err := b.Ask(ctx, a.Address()); err != nil || held.Revoked || held.Certificates != nil {
		t.Fatalf("ask about a box with nothing revoked: %+v, %v", held, err)
	}
	stolen := worker(t, a)
	theft(t, e, a)
	first := record(t, e, a)
	firstThrough := throughOf(t, first)
	if held, err := b.Ask(ctx, a.Address()); err != nil || held.Revoked || held.Certificates == nil || held.Certificates.Through != firstThrough {
		t.Fatalf("ask after a revocation of certificates was published: %+v, %v", held, err)
	}

	// C never asks: the record reaches it as a file, and the server may say
	// what it likes.
	says(e, protocol.CodeNotRevoked, http.MethodGet, "/revocations")
	got, held, err := c.KeepRevocation(first)
	if err != nil || got != a.Address() || held.Revoked || held.Certificates == nil || held.Certificates.Through != firstThrough || !keptList(c, a.Address()) {
		t.Fatalf("a revocation of certificates handed over: %+v, %v", held, err)
	}
	mailAs(t, e, a, c, stolen, "signed by the key that was taken")
	if res := receive(t, c); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a thief's mail, the revocation handed over and the server hiding it: %+v", res)
	}
	e.srv.SetMiddle(nil)

	// One through a higher serial replaces it, and the lower one, handed
	// over again, changes nothing: what was revoked stays revoked.
	second := numberOf(t, a)
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	later := throughOf(t, record(t, e, a))
	if later <= firstThrough {
		t.Fatalf("the later revocation runs through %d, not above %d", later, firstThrough)
	}
	if _, held, err := c.KeepRevocation(record(t, e, a)); err != nil || held.Certificates.Through != later {
		t.Fatalf("a later revocation of certificates: %+v, %v", held, err)
	}
	if _, held, err := c.KeepRevocation(first); err != nil || held.Certificates.Through != later || !held.Certificates.Revokes(second) {
		t.Fatalf("a lower one handed over again: %+v, %v", held, err)
	}

	// A record with a part that does not verify is refused whole: a good
	// revocation beside a revocation of certificates the working key signed
	// keeps nothing.
	d := e.box(protocol.Classic)
	rev, err := d.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := protocol.NewRevokedCertificates(d.Address(), 1)
	if err != nil {
		t.Fatal(err)
	}
	byWorker, err := protocol.SignRevokedCertificates(worker(t, d), certs)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*protocol.Revocations{
		"certificates revoked by a working key":  {Identity: rev.Identity, Revocation: rev.Revocation, RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: byWorker},
		"certificates revoked with no signature": {Identity: rev.Identity, RevokedCertificates: certs.Statement()},
		"another box's revocation, and none":     {Identity: rev.Identity, Revocation: first.RevokedCertificatesSignature},
		"nothing but the identity":               {Identity: rev.Identity},
	} {
		if _, _, err := c.KeepRevocation(bad); err == nil || keptRevocation(c, d.Address()) || keptList(c, d.Address()) {
			t.Fatalf("%s was kept: %v", name, err)
		}
	}
	if _, held, err := c.KeepRevocation(rev); err != nil || !held.Revoked {
		t.Fatalf("the revocation alone: %+v, %v", held, err)
	}

	// Asking about an address the box holds a revocation of asks nobody.
	op := watch(e, nil)
	if held, err := c.Ask(ctx, d.Address()); err != nil || !held.Revoked || op.count(http.MethodGet, lookupOf(d)) != 0 {
		t.Fatalf("ask about a held revocation: %+v, %v, %q", held, err, op.seen)
	}
	// And no answer is an error, never "nothing held".
	watch(e, func(w http.ResponseWriter, _ *http.Request) bool {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return true
	})
	if held, err := b.Ask(ctx, c.Address()); err == nil || held != nil {
		t.Fatalf("ask with no answer: %+v, %v", held, err)
	}
}
