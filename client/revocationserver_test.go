package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/IronGall-dev/irongall-client/revocationserver"
)

// A box asks revocation servers beside its own server, and publishes its
// revocations to them (PROTOCOL.md §6.3). These tests run the real one,
// package revocationserver, beside the fake mailbox server, and play an
// operator of the mailbox server who hides a revocation from the first: the
// case that asking the mailbox server alone cannot catch.

// revServer is a revocation server a test can stand in front of.
type revServer struct {
	URL  string
	mu   sync.Mutex
	seen []string
	// passes counts the requests that carried an Authorization header: a
	// revocation server is shown no pass.
	passes int
	rule   func(w http.ResponseWriter, r *http.Request) bool
}

func newRevServer(t *testing.T) *revServer {
	t.Helper()
	x, err := revocationserver.Open(revocationserver.Options{Dir: t.TempDir(), WritesPerHour: -1})
	if err != nil {
		t.Fatal(err)
	}
	rs, h := &revServer{}, x.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.seen = append(rs.seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "" {
			rs.passes++
		}
		rule := rs.rule
		rs.mu.Unlock()
		if rule != nil && rule(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { srv.Close(); _ = x.Close() })
	rs.URL = srv.URL
	return rs
}

// set puts a rule in front of the revocation server, or removes it.
func (rs *revServer) set(rule func(w http.ResponseWriter, r *http.Request) bool) {
	rs.mu.Lock()
	rs.rule = rule
	rs.mu.Unlock()
}

func (rs *revServer) count(method string, a protocol.Address) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	n := 0
	for _, s := range rs.seen {
		if s == method+" /v1/"+a.String()+"/revocations" {
			n++
		}
	}
	return n
}

func (rs *revServer) total() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.seen)
}

// holds reports what the revocation server serves about a.
func (rs *revServer) holds(t *testing.T, a protocol.Address) *protocol.Revocations {
	t.Helper()
	resp, err := http.Get(rs.URL + "/v1/" + a.String() + "/revocations")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // a test
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	var rec protocol.Revocations
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the revocation server: %d, %v", resp.StatusCode, err)
	}
	return &rec
}

func down(w http.ResponseWriter, _ *http.Request) bool {
	http.Error(w, "down", http.StatusServiceUnavailable)
	return true
}

// silences records what a box's NoAnswer is told.
type silences struct {
	mu   sync.Mutex
	told []string
}

func (s *silences) note(server string, _ error) {
	s.mu.Lock()
	s.told = append(s.told, server)
	s.mu.Unlock()
}

func (s *silences) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.told)
}

// listing returns a box's options with these revocation servers listed.
func (e *env) listing(servers ...string) client.Options {
	o := e.opts()
	o.RevocationServers = append([]string{}, servers...)
	return o
}

func (e *env) boxWith(o client.Options) *client.Box {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), o, protocol.Classic)
	if err != nil {
		e.t.Fatalf("init: %v", err)
	}
	return b
}

// dropsRevocations is an operator of the mailbox server that takes every
// record sent to it, answers that it did, and keeps none: it hides a
// revocation from the first, and goes on serving the box as if nothing had
// happened.
func dropsRevocations(e *env) *operator {
	return watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/revocations") {
			fakeserver.WriteJSON(w, http.StatusCreated, struct{}{})
			return true
		}
		return false
	})
}

// A revoked address the mailbox server goes on serving. A sender that asks
// the mailbox server alone is told nothing and posts. A sender that also
// asks a revocation server holds the revocation before anything is sealed.
func TestARevocationServerShowsWhatTheMailboxServerHides(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	gone := e.boxWith(e.listing(rs.URL))

	op := dropsRevocations(e)
	rec, err := gone.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	if a, err := gone.Revoke(ctx, rec); err != nil || a != gone.Address() {
		t.Fatalf("revoke: %v", err)
	}
	if got := rs.holds(t, gone.Address()); got == nil || got.Revocation == nil {
		t.Fatal("the revocation did not reach the revocation server")
	}

	// The control: a sender that lists no revocation server is shown
	// nothing, and its mail is taken for a revoked address.
	blind := e.box(protocol.Classic)
	if _, err := blind.Send(ctx, gone.Address(), "to an address its owner ended"); err != nil {
		t.Fatalf("a sender that asks the mailbox server alone: %v", err)
	}
	if op.count(http.MethodPost, postTo(gone)) != 1 || keptRevocation(blind, gone.Address()) {
		t.Fatalf("the control did not post, or holds a revocation nobody showed it: %q", op.seen)
	}

	a := e.boxWith(e.listing(rs.URL))
	_, err = a.Send(ctx, gone.Address(), "never posted")
	if !isRevoked(err, gone.Address(), false) {
		t.Fatalf("a send to an address a revocation server holds a revocation of: %v", err)
	}
	if op.count(http.MethodPost, postTo(gone)) != 1 || op.count(http.MethodGet, postTo(gone)+"/identity") != 1 {
		t.Fatalf("something was fetched or posted after the revocation was in hand: %q", op.seen)
	}
	if !keptRevocation(a, gone.Address()) || failed(a, gone.Address()) != 1 {
		t.Fatal("the revocation was not kept, or the message was not moved to outbox/failed/")
	}
	// It is the box's from then on: the next send asks nobody.
	before := rs.total()
	if _, err := a.Send(ctx, gone.Address(), "nor this"); !isRevoked(err, gone.Address(), false) || rs.total() != before {
		t.Fatalf("a second send: %v, after %d more requests of the revocation server", err, rs.total()-before)
	}
	if rs.passes != 0 {
		t.Fatalf("a revocation server was shown a pass %d times", rs.passes)
	}
}

// A taken working key, and a mailbox server that serves senders the thief's
// statement and hides the list that revokes its certificate. The list is at
// the revocation server, where the box's owner published it.
func TestARevocationServerShowsAListTheMailboxServerHides(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a := e.boxWith(e.listing(rs.URL))
	statement, signature := theft(t, e, a)
	if got := rs.holds(t, a.Address()); got == nil || got.RevokedCertificates == nil || got.Revocation != nil {
		t.Fatal("rekey --revoke-earlier did not publish the list to the revocation server")
	}

	// The control: asking the mailbox server alone, a sender posts to the
	// prekey the thief holds.
	op := helpsTheThief(e, a, statement, signature, true)
	blind := e.box(protocol.Classic)
	if _, err := blind.Send(ctx, a.Address(), "to whoever holds the old prekey"); err != nil || op.count(http.MethodPost, postTo(a)) != 1 {
		t.Fatalf("a sender that asks the mailbox server alone: %v, %q", err, op.seen)
	}

	s := e.boxWith(e.listing(rs.URL))
	before := rs.count(http.MethodGet, a.Address())
	_, err := s.Send(ctx, a.Address(), "never posted")
	if err == nil || !strings.Contains(err.Error(), "under a certificate its identity has revoked") {
		t.Fatalf("a send to a statement under a certificate a revocation server lists: %v", err)
	}
	if op.count(http.MethodPost, postTo(a)) != 1 || !keptList(s, a.Address()) || keptRevocation(s, a.Address()) {
		t.Fatalf("it was posted, or the list was not kept: %q", op.seen)
	}
	// Asked of the mailbox server first, and of the revocation server once.
	if n := rs.count(http.MethodGet, a.Address()) - before; n != 1 {
		t.Fatalf("the revocation server was asked %d times about one recipient", n)
	}

	// A question at any time asks both, and keeps what either shows.
	c := e.boxWith(e.listing(rs.URL))
	held, err := c.Ask(ctx, a.Address())
	if err != nil || held.Revoked || held.Certificates == nil || !held.Certificates.Revokes(1) || held.Certificates.Revokes(2) {
		t.Fatalf("ask: %+v, %v", held, err)
	}
}

// Mail from a revoked sender, on a mailbox server that hides the revocation:
// a reader that asks a revocation server refuses it, and one that does not,
// delivers it.
func TestAReaderAsksARevocationServerAboutEachSender(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	from := e.boxWith(e.listing(rs.URL))
	blind, to := e.box(protocol.Classic), e.boxWith(e.listing(rs.URL))
	send(t, from, blind, "one")
	send(t, from, to, "two")
	send(t, from, to, "three")

	dropsRevocations(e)
	rec, err := from.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := from.Revoke(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// The control.
	if res := receive(t, blind); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("a reader that asks the mailbox server alone: %+v", res)
	}
	res := receive(t, to)
	if len(res.Delivered) != 0 || len(res.Refused) != 2 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("a reader that asks a revocation server: %+v", res)
	}
	// Once for the sender, whatever it sent.
	if rs.count(http.MethodGet, from.Address()) != 1 || !keptRevocation(to, from.Address()) {
		t.Fatalf("asked %d times, kept %t", rs.count(http.MethodGet, from.Address()), keptRevocation(to, from.Address()))
	}
}

// A revocation server that gives no answer changes nothing: the mail goes.
// The box's owner is told, once in a command, and the server is not asked
// again by that command.
func TestNoAnswerFromARevocationServerChangesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	var told silences
	o := e.listing(rs.URL)
	o.NoAnswer = told.note
	a := e.boxWith(o)
	x, y := e.box(protocol.Classic), e.box(protocol.Classic)

	rs.set(down)
	if _, err := a.Send(ctx, x.Address(), "goes anyway"); err != nil {
		t.Fatalf("a send while the revocation server is down: %v", err)
	}
	if told.n() != 1 || told.told[0] != rs.URL {
		t.Fatalf("the owner was told %q", told.told)
	}
	// A drain with two senders: the revocation server is asked about the
	// first and not again.
	send(t, x, a, "from x")
	send(t, y, a, "from y")
	before := rs.total()
	if res := receive(t, a); len(res.Delivered) != 2 {
		t.Fatalf("a drain while the revocation server is down: %+v", res)
	}
	if rs.total()-before != 1 || told.n() != 2 {
		t.Fatalf("a drain asked a silent revocation server %d times, and its owner was told %d times in all", rs.total()-before, told.n())
	}
	// The next command asks it again: it may be back.
	rs.set(nil)
	before = rs.total()
	if _, err := a.Send(ctx, y.Address(), "asked again"); err != nil || rs.total()-before != 1 || told.n() != 2 {
		t.Fatalf("the next command: %v, %d requests, told %d times", err, rs.total()-before, told.n())
	}

	// One that is not there at all.
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	o = e.listing(gone.URL)
	o.NoAnswer = told.note
	b := e.boxWith(o)
	if _, err := b.Send(ctx, x.Address(), "to nobody's revocation server"); err != nil || told.n() != 3 {
		t.Fatalf("a send with a revocation server that is not there: %v, told %d times", err, told.n())
	}

	// One that never answers costs a command one bounded wait.
	client.SetRevocationServerWait(t, 50*time.Millisecond)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	rs.set(func(http.ResponseWriter, *http.Request) bool { <-release; return true })
	start := time.Now()
	if _, err := a.Send(ctx, x.Address(), "does not wait"); err != nil || told.n() != 4 {
		t.Fatalf("a send with a revocation server that hangs: %v, told %d times", err, told.n())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("a send waited %s on a revocation server", d)
	}
}

// The box's own server is asked first, and with no answer from it nothing
// is posted and no revocation server is asked: what a revocation server says
// is never in place of the server the mail goes through.
func TestARevocationServerIsNoSubstituteForTheBoxsOwn(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a, b := e.boxWith(e.listing(rs.URL)), e.box(protocol.Classic)

	op := watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == lookupOf(b) {
			return down(w, r)
		}
		return false
	})
	_, err := a.Send(ctx, b.Address(), "waits for an answer")
	if err == nil || !strings.Contains(err.Error(), "could not be asked") {
		t.Fatalf("a send with no answer from the box's own server: %v", err)
	}
	if rs.total() != 0 || op.count(http.MethodPost, postTo(b)) != 0 {
		t.Fatalf("a revocation server was asked, or the message posted: %d, %q", rs.total(), op.seen)
	}
}

// What a revocation server shows is checked as anything is: a record that
// does not verify counts as nothing shown, and revokes nobody.
func TestWhatARevocationServerShowsIsChecked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a, b, other := e.boxWith(e.listing(rs.URL)), e.box(protocol.Classic), e.box(protocol.Classic)

	foreign, err := other.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	for name, rec := range map[string]protocol.Revocations{
		"another box's revocation":                *foreign,
		"another box's signature under this name": {Identity: b.Identity().Document(), Revocation: foreign.Revocation},
		"a list nobody signed":                    {Identity: b.Identity().Document(), RevokedCertificates: []byte("irongall-revoked-certs-v1\n" + b.Address().String() + "\n1\n1\n"), RevokedCertificatesSignature: foreign.Revocation},
	} {
		rs.set(func(w http.ResponseWriter, _ *http.Request) bool {
			fakeserver.WriteJSON(w, http.StatusOK, rec)
			return true
		})
		if _, err := a.Send(ctx, b.Address(), name); err != nil {
			t.Errorf("%s stopped a send: %v", name, err)
		}
		if keptRevocation(a, b.Address()) || keptList(a, b.Address()) {
			t.Fatalf("%s was kept", name)
		}
	}
	if res := receive(t, b); len(res.Delivered) != 3 {
		t.Fatalf("delivered %d of 3", len(res.Delivered))
	}
}

// A record is published at every server, whatever the others answer: a
// mailbox server that refuses a revocation, or is down, does not keep it
// from a revocation server, and the owner is told which did not take it.
func TestARecordIsPublishedAtEveryServer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)

	// The revocation server down: the box's own took it, and the error says
	// who did not.
	gone := e.boxWith(e.listing(rs.URL))
	rec, err := gone.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	rs.set(down)
	_, err = gone.Revoke(ctx, rec)
	var part *client.NotPublishedError
	if !errors.As(err, &part) || !slices.Equal(part.Took, []string{e.srv.URL}) || len(part.Failed) != 1 || part.Failed[0].Server != rs.URL {
		t.Fatalf("revoke with the revocation server down: %v", err)
	}
	// The same again, once it is back, is the cure.
	rs.set(nil)
	if _, err := gone.Revoke(ctx, rec); err != nil || rs.holds(t, gone.Address()) == nil {
		t.Fatalf("revoke again: %v", err)
	}

	// The mailbox server refusing: the revocation server took it all the
	// same.
	gone = e.boxWith(e.listing(rs.URL))
	if rec, err = gone.Revocation(); err != nil {
		t.Fatal(err)
	}
	says(e, protocol.CodeUnavailable, http.MethodPut, "/revocations")
	_, err = gone.Revoke(ctx, rec)
	if !errors.As(err, &part) || !slices.Equal(part.Took, []string{rs.URL}) || len(part.Failed) != 1 || part.Failed[0].Server != e.srv.URL || client.Code(err) != protocol.CodeUnavailable {
		t.Fatalf("revoke with the mailbox server refusing: %v", err)
	}
	if rs.holds(t, gone.Address()) == nil {
		t.Fatal("a mailbox server that refused a revocation kept it from the revocation server")
	}

	// A box that lists none gets its own server's error as it is.
	alone := e.box(protocol.Classic)
	if rec, err = alone.Revocation(); err != nil {
		t.Fatal(err)
	}
	if _, err = alone.Revoke(ctx, rec); errors.As(err, &part) || client.Code(err) != protocol.CodeUnavailable {
		t.Fatalf("revoke at the only server there is: %v", err)
	}
	e.srv.SetMiddle(nil)

	// A record that does not verify goes nowhere.
	before := rs.total()
	bad := *rec
	bad.Revocation = []byte("no signature")
	if _, err := gone.Publish(ctx, &bad); err == nil || rs.total() != before {
		t.Fatalf("a record that does not verify: %v, %d requests", err, rs.total()-before)
	}
	if _, err := gone.Publish(ctx, &protocol.Revocations{Identity: rec.Identity}); err == nil || rs.total() != before {
		t.Fatalf("a record with nothing signed: %v", err)
	}
}

// A list of revoked certificates that not every server took is out all the
// same: the box keeps it, and the record it keeps publishes it again.
func TestAListNotEverywhereIsKeptAndPublishedAgain(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a := e.boxWith(e.listing(rs.URL))
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	rs.set(down)
	list, err := a.RevokeEarlier(ctx)
	var part *client.NotPublishedError
	if list == nil || !list.Revokes(1) || !errors.As(err, &part) || part.Failed[0].Server != rs.URL {
		t.Fatalf("revoke earlier with the revocation server down: %+v, %v", list, err)
	}
	kept := filepath.Join(a.Dir(), "revoked-certs.json")
	raw, err := os.ReadFile(kept)
	if err != nil {
		t.Fatalf("a list a server took was not kept: %v", err)
	}
	var rec protocol.Revocations
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rs.set(nil)
	if rs.holds(t, a.Address()) != nil {
		t.Fatal("the revocation server holds a list it never took")
	}
	if got, err := a.Publish(ctx, &rec); err != nil || got != a.Address() {
		t.Fatalf("publishing the kept record again: %v", err)
	}
	if got := rs.holds(t, a.Address()); got == nil || string(got.RevokedCertificates) != string(rec.RevokedCertificates) {
		t.Fatal("the list did not reach the revocation server")
	}

	// A list no server took is not kept: its version is not spent.
	b := e.boxWith(e.listing(rs.URL))
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	rs.set(down)
	says(e, protocol.CodeUnavailable, http.MethodPut, "/revocations")
	if list, err := b.RevokeEarlier(ctx); list != nil || !errors.As(err, &part) || len(part.Took) != 0 {
		t.Fatalf("revoke earlier with every server down: %+v, %v", list, err)
	}
	if exists(filepath.Join(b.Dir(), "revoked-certs.json")) {
		t.Fatal("a list no server took was kept")
	}
}

// Which revocation servers a box asks: what its options name, or else what
// its file names, or else the default for its server.
func TestTheRevocationServersABoxLists(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	list := func(o client.Options) ([]string, error) {
		t.Helper()
		x, err := client.Open(b.Dir(), o)
		if err != nil {
			t.Fatal(err)
		}
		return x.RevocationServers()
	}
	file := filepath.Join(b.Dir(), "revocation-servers")

	// A box on another server than the default asks none unless told.
	if got, err := list(e.opts()); err != nil || len(got) != 0 {
		t.Fatalf("a box on its own server: %q, %v", got, err)
	}
	// A box on the default server asks the default revocation server.
	if got, err := list(client.Options{}); err != nil || !slices.Equal(got, []string{client.DefaultRevocationServer}) {
		t.Fatalf("a box on the default server: %q, %v", got, err)
	}
	// Its file says otherwise, one to a line.
	if err := os.WriteFile(file, []byte("https://one.example\nhttps://two.example:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, o := range []client.Options{{}, e.opts()} {
		if got, err := list(o); err != nil || !slices.Equal(got, []string{"https://one.example", "https://two.example:8443"}) {
			t.Fatalf("the box's file: %q, %v", got, err)
		}
	}
	// What the options name comes before the file, and the box's own server
	// is never among them: it is asked anyway.
	if got, err := list(e.listing("https://three.example", e.srv.URL, "https://three.example")); err != nil || !slices.Equal(got, []string{"https://three.example"}) {
		t.Fatalf("the options: %q, %v", got, err)
	}
	// A file that names nothing is as if it were not there.
	if err := os.WriteFile(file, []byte(" \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := list(client.Options{}); err != nil || !slices.Equal(got, []string{client.DefaultRevocationServer}) {
		t.Fatalf("a file with nothing in it, on the default server: %q, %v", got, err)
	}
	if got, err := list(e.opts()); err != nil || len(got) != 0 {
		t.Fatalf("a file with nothing in it, on another server: %q, %v", got, err)
	}
	// None: an empty list that is not nil, or the one word in the file.
	if got, err := list(client.Options{RevocationServers: []string{}}); err != nil || len(got) != 0 {
		t.Fatalf("an empty list: %q, %v", got, err)
	}
	if err := os.WriteFile(file, []byte("none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := list(client.Options{}); err != nil || len(got) != 0 {
		t.Fatalf("a file that says none: %q, %v", got, err)
	}
	// A file that names something else is an error, and so is a list.
	if err := os.WriteFile(file, []byte("https://one.example/path\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := list(client.Options{}); err == nil {
		t.Fatalf("a file with a path in it: %q", got)
	}
	if got, err := list(client.Options{RevocationServers: []string{"one.example"}}); err == nil {
		t.Fatalf("a server with no scheme: %q", got)
	}
	// With such a file the box asks about nobody, so it posts nothing.
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Send(context.Background(), e.box(protocol.Classic).Address(), "never posted"); err == nil || !strings.Contains(err.Error(), "revocation-servers file") {
		t.Fatalf("a send from a box whose file cannot be read: %v", err)
	}
	st, err := x.Status()
	if err != nil || len(st.Attention) == 0 || !strings.Contains(strings.Join(st.Attention, " "), "revocation servers") {
		t.Fatalf("status with a file that cannot be read: %+v, %v", st, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if st, err = x.Status(); err != nil || st.RevocationServers == nil || len(st.RevocationServers) != 0 || strings.Contains(strings.Join(st.Attention, " "), "revocation servers") {
		t.Fatalf("status of a box that asks none: %+v, %v", st, err)
	}
}

func TestParseRevocationServers(t *testing.T) {
	for in, want := range map[string][]string{
		"https://a.example":                            {"https://a.example"},
		"https://a.example,https://b.example:8443":     {"https://a.example", "https://b.example:8443"},
		" https://a.example \n\thttps://a.example\r\n": {"https://a.example"},
		"http://127.0.0.1:8080 http://[::1]:8080":      {"http://127.0.0.1:8080", "http://[::1]:8080"},
		"none": {},
	} {
		got, err := client.ParseRevocationServers(in)
		if err != nil || got == nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	// Text that names nothing is as if it were not there.
	for _, in := range []string{"", " ", "\n", " ,\t\r\n"} {
		if got, err := client.ParseRevocationServers(in); got != nil || err != nil {
			t.Errorf("%q: %q, %v, want nothing named", in, got, err)
		}
	}
	for _, in := range []string{
		"a.example", "ftp://a.example", "https://", "https://a.example/", "https://a.example/v1", "https://a.example?x=1",
		"https://user@a.example", "HTTPS://a.example", "https://A.example", "https://a.example:port", "none https://a.example", "https://a.example none",
		"https://-a.example", "https://a.example:123456",
	} {
		if got, err := client.ParseRevocationServers(in); err == nil {
			t.Errorf("%q was taken as %q", in, got)
		}
	}
}
