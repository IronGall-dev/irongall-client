package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A command that learns part way that its mailbox is finished, an answer on the
// way showing the mailbox its own revocation, which it keeps once it verifies,
// says that alone and asks and signs nothing more after it (PROTOCOL.md
// §12.5): at whatever call it learns it, by whatever answer.

// putRecord sends rec to the server behind a middleware, as another holder
// of the record would mid-command, and fails the test unless it was taken.
func putRecord(t *testing.T, next http.Handler, a protocol.Address, rec *protocol.Revocations) {
	t.Helper()
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/"+a.String()+"/revocations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, req)
	if rr.Code >= 300 {
		t.Errorf("the record put mid-command was answered %d", rr.Code)
	}
}

// finishedOwn reports whether err is the mailbox's own RevokedError.
func finishedOwn(err error) bool {
	var gone *client.RevokedError
	return errors.As(err, &gone) && gone.Own
}

// A read answered 410 revoked with a record that does not verify is that
// read's answer: nothing more is asked of it, so a proof's own reads are never
// proved again (proved), and a server that answers so at every read gets one
// (#353).
func TestARevokedReadWhoseRecordDoesNotVerifyIsNotReadAgain(t *testing.T) {
	t.Parallel()
	for _, of := range []string{"a peer", "itself"} {
		t.Run(of, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t)
			a, b := e.mailbox(), e.mailbox()
			read := b
			if of == "itself" {
				read = a
			}
			bad := notItsRecord(t, read)
			var reads atomic.Int32
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				// Bounded, so that a mailbox that reads again still ends.
				if r.Method == http.MethodGet && r.URL.Path == mailboxPath(read) && reads.Add(1) <= 10 {
					forge.Refuse(w, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = bad })
					return
				}
				next.ServeHTTP(w, r)
			})
			var err error
			if of == "itself" {
				_, err = a.Rekey(ctx)
			} else {
				_, err = a.Resolve(ctx, b.Address())
			}
			if client.Code(err) != protocol.CodeRevoked || finishedOwn(err) || reads.Load() != 1 {
				t.Errorf("a read of %s answered 410 with a record that does not verify: %v, after %d reads of it", of, err, reads.Load())
			}
		})
	}
}

// Every command a mailbox runs under its lock, in the states that reach each of
// its paths, against a server made hostile at its 1st call, then its 2nd, and
// on through every call an honest run makes: the crash tests' kill at each
// step is the model (crash_test.go). At that call the mailbox's address is
// revoked at its server, by another holder of the record, and the call is
// answered one way (partwayVariants). An answer to a call that names the mailbox,
// showing its own revocation, that verifies, is the event: the mailbox then holds
// the revocation, and no pass and no read of its server's ACL owed, the
// command's error is it, and nothing more is asked or signed; between a call whose answer must be proved and the event, only the
// proof's own reads of the mailbox go out. A mailbox shown none that verifies holds
// none, and its command is not REVOKED: a server's word revokes nothing.
func TestEveryCommandShownItsOwnRevocationAtEachCall(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, c := range partwayCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			honest := partwayHonest(t, c)
			for n, call := range honest {
				for _, v := range partwayVariants {
					if v == partwayRead && !(call.method == http.MethodGet && strings.HasSuffix(call.path, "/revocations")) {
						continue
					}
					t.Run(fmt.Sprintf("call %d %s %s/%s", n+1, call.method, call.short, v), func(t *testing.T) {
						t.Parallel()
						partwayAt(t, c, n+1, v)
					})
				}
			}
		})
	}
}

// What the call made hostile answers.
const (
	partwayRecord   = "410 with its record"
	partwayServed   = "410 with a record that does not verify, the revocation served"
	partwayUnserved = "410 with a record that does not verify, none published"
	partwayCert     = "401 certificate_revoked"
	partwayRead     = "a 2xx read of its revocations carrying it"
)

var partwayVariants = []string{partwayRecord, partwayServed, partwayUnserved, partwayCert, partwayRead}

// A partwayCase is a command in a state that reaches one of its paths.
type partwayCase struct {
	name string
	set  func(t *testing.T, e *env) partwaySet
}

// partwaySet is a mailbox put in its state: its directory, the mailbox whose
// revocation is published, the state's own operator at call i (it answers r
// and reports true, or leaves it to the server), the command, and what the
// command must say once it learned the revocation, beyond what every one must.
type partwaySet struct {
	dir   string
	a     *client.Mailbox
	inner func(i int, w http.ResponseWriter, r *http.Request, next http.Handler) bool
	run   func(ctx context.Context) (any, error)
	check func(t *testing.T, w *partwayRun)
	// joined is a command whose error joins its entries', a flush's: it holds
	// the revocation, and is not it alone.
	joined bool
}

// partwayCall is one call the command made, and what it was answered.
type partwayCall struct {
	method, path, short string
	pass                bool
	status              int
	// shows is an answer to a call naming the mailbox that carries its own
	// revocation, verifying: a 410's record, or a read of its revocations.
	shows bool
}

func (c partwayCall) String() string {
	s := fmt.Sprintf("%s %s %d", c.method, c.short, c.status)
	if c.pass {
		s += " +pass"
	}
	if c.shows {
		s += " (shows it)"
	}
	return s
}

// partwayRun is what one run did.
type partwayRun struct {
	mailbox *client.Mailbox // opened again once the command ended
	got     any
	err     error
	calls   []partwayCall
	event   int // the index in calls of the event, or -1
}

// partwayLog is the operator in front of the server for one run: hostile at
// call n alone, as v says, and the state's own operator at every other.
type partwayLog struct {
	mu    sync.Mutex
	calls []partwayCall
	event int
	keys  []string // the mailbox's working keys and prekeys when the event was answered
}

func (l *partwayLog) middle(t *testing.T, s partwaySet, rec, bad *protocol.Revocations, n int, v string) func(http.ResponseWriter, *http.Request, http.Handler) {
	own := s.a.Address()
	return func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		l.mu.Lock()
		i := len(l.calls) + 1
		l.calls = append(l.calls, partwayCall{method: r.Method, path: r.URL.Path, short: partwayShort(r.URL.Path, own), pass: r.Header.Get("Authorization") != ""})
		l.mu.Unlock()
		got := httptest.NewRecorder()
		switch {
		case i == n:
			if v != partwayUnserved {
				putRecord(t, next, own, rec)
			}
			switch v {
			case partwayRecord:
				forge.Refuse(got, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = rec })
			case partwayServed, partwayUnserved:
				forge.Refuse(got, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = bad })
			case partwayCert:
				forge.Refuse(got, protocol.CodeCertificateRevoked)
			case partwayRead:
				fakeserver.WriteJSON(got, http.StatusOK, rec)
			}
		case s.inner != nil && s.inner(i, got, r, next):
		default:
			next.ServeHTTP(got, r)
		}
		shows := partwayNames(r.URL.Path, own) && partwayShows(r, got, own)
		l.mu.Lock()
		l.calls[i-1].status, l.calls[i-1].shows = got.Code, shows
		if shows && l.event < 0 {
			// The command waits for this answer: nothing of the mailbox moves.
			l.event, l.keys = i-1, keysOf(s.dir)
		}
		l.mu.Unlock()
		for k, vs := range got.Header() {
			w.Header()[k] = vs
		}
		w.WriteHeader(got.Code)
		_, _ = w.Write(got.Body.Bytes())
	}
}

// partwayShows reports whether an answer carries a's revocation, verifying.
func partwayShows(r *http.Request, got *httptest.ResponseRecorder, a protocol.Address) bool {
	var rec *protocol.Revocations
	switch {
	case got.Code == http.StatusGone:
		var p protocol.Problem
		if protocol.Unmarshal(got.Body.Bytes(), &p) != nil {
			return false
		}
		rec = p.Record
	case got.Code == http.StatusOK && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/revocations"):
		rec = &protocol.Revocations{}
		if protocol.Unmarshal(got.Body.Bytes(), rec) != nil {
			return false
		}
	}
	if rec == nil || len(rec.Revocation) == 0 {
		return false
	}
	_, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	return err == nil
}

// partwayNames reports whether a call's path names mailbox a.
func partwayNames(path string, a protocol.Address) bool {
	own := "/v1/" + a.String()
	return path == own || strings.HasPrefix(path, own+"/")
}

// partwayIsRead reports whether a call is a read of a mailbox or of its
// revocations, which carries no pass.
func partwayIsRead(c partwayCall) bool {
	rest, _ := strings.CutPrefix(c.path, "/v1/")
	return c.method == http.MethodGet && (!strings.Contains(rest, "/") || strings.HasSuffix(rest, "/revocations"))
}

// partwayMustLearn reports whether the mailbox must hold its revocation after
// call c was answered as v: an answer about the mailbox itself that its proof
// reads the mailbox for (the revocation is served by then), or one that carries
// the record itself. A 401 is about the mailbox's own pass, whatever mailbox the
// call names; a read carries no pass and is not read again.
func partwayMustLearn(c partwayCall, v string, a protocol.Address) bool {
	switch v {
	case partwayRecord:
		return partwayNames(c.path, a)
	case partwayServed:
		return partwayNames(c.path, a) && !partwayIsRead(c)
	case partwayCert:
		return !partwayIsRead(c)
	case partwayRead:
		return true
	}
	return false
}

// partwayProved reports whether call c, answered as v, is one whose answer
// the mailbox proves by reading itself: what goes out between it and the event
// is that read alone.
func partwayProved(c partwayCall, v string, a protocol.Address) bool {
	return v == partwayServed && partwayNames(c.path, a) && !partwayIsRead(c) || v == partwayCert && !partwayIsRead(c)
}

var partwayHex = regexp.MustCompile(`[0-9a-z]{64,}`) // an id, 64 hex, or an address, 77 of base32

// partwayShort is a path with the mailbox's address written own and any other
// address or id written as #.
func partwayShort(path string, a protocol.Address) string {
	return partwayHex.ReplaceAllString(strings.ReplaceAll(path, a.String(), "own"), "#")
}

// keysOf is what a mailbox's work/ and prekeys/ hold, by name.
func keysOf(dir string) []string {
	var names []string
	for _, d := range []string{"work", "prekeys"} {
		es, _ := os.ReadDir(filepath.Join(dir, d))
		for _, e := range es {
			names = append(names, d+"/"+e.Name())
		}
	}
	return names
}

// partwayHonest runs c against the honest server and returns its calls.
func partwayHonest(t *testing.T, c partwayCase) []partwayCall {
	t.Helper()
	e := newEnv(t)
	s := c.set(t, e)
	l := &partwayLog{event: -1}
	e.srv.SetMiddle(l.middle(t, s, nil, nil, 0, ""))
	if _, err := s.run(context.Background()); err != nil {
		t.Fatalf("the honest run: %v; calls %v", err, l.calls)
	}
	e.srv.SetMiddle(nil)
	if len(l.calls) == 0 {
		t.Fatal("the honest run made no call")
	}
	return l.calls
}

// partwayAt runs c with its server hostile at call n, as v says, and holds
// the run to what every command must do.
func partwayAt(t *testing.T, c partwayCase, n int, v string) {
	ctx := context.Background()
	e := newEnv(t)
	s := c.set(t, e)
	rec, err := s.a.Revocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	l := &partwayLog{event: -1}
	e.srv.SetMiddle(l.middle(t, s, rec, notItsRecord(t, s.a), n, v))
	got, err := s.run(ctx)
	e.srv.SetMiddle(nil)
	if len(l.calls) < n {
		t.Fatalf("the run made %d calls, the honest one at least %d: %v", len(l.calls), n, l.calls)
	}
	mailbox, oerr := client.Open(s.dir, e.opts())
	if oerr != nil {
		t.Fatal(oerr)
	}
	st, serr := mailbox.Status(ctx)
	if serr != nil {
		t.Fatal(serr)
	}
	w := &partwayRun{mailbox: mailbox, got: got, err: err, calls: l.calls, event: l.event}
	at := l.calls[n-1]
	if peerRevoked(err) {
		t.Errorf("its error names a peer revoked, where none is: %v; calls %v", err, l.calls)
	}
	if l.event < 0 {
		if partwayMustLearn(at, v, s.a.Address()) {
			t.Errorf("answered %s at %s, and nothing it asked showed it its revocation: %v; calls %v", v, at, err, l.calls)
		}
		// A 403 sender_revoked is proved by reading the mailbox, which its server
		// holds revoked by then.
		for _, c := range l.calls[n-1:] {
			if c.status == http.StatusForbidden && !partwayIsRead(c) && strings.HasSuffix(c.path, "/messages") {
				t.Errorf("answered 403 at %s, and it did not read itself: %v; calls %v", c, err, l.calls)
			}
		}
		if st.Revoked {
			t.Errorf("it holds its own revocation, which no answer showed: calls %v", l.calls)
		}
		if finishedOwn(err) {
			t.Errorf("REVOKED on a server's word: %v; calls %v", err, l.calls)
		}
		return
	}
	if !st.Revoked {
		t.Errorf("an answer showed it its revocation, which it does not hold: calls %v", l.calls)
	}
	if !finishedOwn(err) {
		t.Errorf("the command's error is not its revocation: %v; calls %v", err, l.calls)
	} else if _, alone := err.(*client.RevokedError); !alone && !s.joined {
		t.Errorf("the command's error is not its revocation alone: %v; calls %v", err, l.calls)
	}
	for _, c := range l.calls[l.event+1:] {
		t.Errorf("asked after the event: %s; calls %v", c, l.calls)
	}
	if partwayProved(at, v, s.a.Address()) {
		for _, c := range l.calls[n:l.event] {
			if c.method != http.MethodGet || c.short != "/v1/own" && c.short != "/v1/own/revocations" {
				t.Errorf("asked between the answer to prove and the proof: %s; calls %v", c, l.calls)
			}
		}
	}
	for _, k := range keysOf(s.dir) {
		if !slices.Contains(l.keys, k) {
			t.Errorf("made %s after the event: calls %v", k, l.calls)
		}
	}
	if has(mailbox, "pass") {
		t.Errorf("it keeps a pass after the event: calls %v", l.calls)
	}
	if has(mailbox, "acl-read") {
		t.Errorf("it keeps a read of its server's ACL owed after the event: calls %v", l.calls)
	}
	if s.check != nil {
		s.check(t, w)
	}
}

// peerRevoked reports whether err holds, anywhere in its tree, a
// RevokedError of another address than the mailbox's own.
func peerRevoked(err error) bool {
	var gone *client.RevokedError
	if errors.As(err, &gone) && !gone.Own {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		return slices.ContainsFunc(u.Unwrap(), peerRevoked)
	case interface{ Unwrap() error }:
		return peerRevoked(u.Unwrap())
	}
	return false
}

// notItsRecord is a record of a's identity whose revocation another key
// signed: one that does not verify.
func notItsRecord(t *testing.T, a *client.Mailbox) *protocol.Revocations {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevocation(signer, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: a.Identity().Document(), Revocation: sig}
}

// recvSaysItAlone holds a drain that learned it to that alone: no renewal and
// no ACL failed, and no renewal is kept as one that failed (#335, #378).
func recvSaysItAlone(t *testing.T, w *partwayRun) {
	if res, _ := w.got.(*client.Result); res != nil && (res.RenewErr != nil || res.ACLErr != nil) {
		t.Errorf("recv's result: a renewal that failed %v, an ACL not sent %v; calls %v", res.RenewErr, res.ACLErr, w.calls)
	}
	if has(w.mailbox, "renew-failed") {
		t.Errorf("it keeps a renewal that failed: calls %v", w.calls)
	}
}

// remedySaysItAlone holds a remedy that learned it before its server took
// its revocation, or answered that it holds a higher one, to no Remedy: no
// server took anything from it (#326, #379).
func remedySaysItAlone(t *testing.T, w *partwayRun) {
	for _, c := range w.calls[:w.event] {
		if c.method == http.MethodPut && c.short == "/v1/own/revocations" && (c.status < 300 || c.status == http.StatusConflict) {
			return
		}
	}
	if r, _ := w.got.(*client.Remedy); r != nil {
		t.Errorf("a Remedy where no server took anything: %+v; calls %v", r, w.calls)
	}
}

// outboxSaysItAlone holds a send or a flush that learned it to leaving
// nothing waiting it had not tried before: the entry it was posting then,
// and each it had not reached, are in outbox/failed/, with nothing asked of
// a later one (#340). One tried before, and kept for a call that failed, may
// wait.
func outboxSaysItAlone(t *testing.T, w *partwayRun) {
	own := "/v1/" + w.mailbox.Address().String()
	at := ""
	for _, c := range w.calls[:w.event+1] {
		if !partwayNames(c.path, w.mailbox.Address()) {
			at, _, _ = strings.Cut(strings.TrimPrefix(c.path, "/v1/"), "/")
		}
	}
	left, _ := filepath.Glob(filepath.Join(w.mailbox.Dir(), "outbox", "*.P"))
	for _, name := range left {
		to, _, _ := strings.Cut(filepath.Base(name), ".")
		reached := slices.ContainsFunc(w.calls[:w.event+1], func(c partwayCall) bool { return c.path != own && strings.HasPrefix(c.path, "/v1/"+to) })
		if !reached || to == at {
			t.Errorf("waits in the outbox, not in outbox/failed/: the entry to %s, which it was posting when it learned it or had not reached; calls %v", partwayShort("/v1/"+to, w.mailbox.Address()), w.calls)
		}
	}
}

// partwayHides is the state's operator that serves the mailbox's first read of
// itself without the revocation of its certificates its server holds, so
// that its publish of one is answered conflict.
func partwayHides(e *env, a *client.Mailbox) func(int, http.ResponseWriter, *http.Request, http.Handler) bool {
	return func(i int, w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if i != 1 || r.Method != http.MethodGet || r.URL.Path != mailboxPath(a) {
			return false
		}
		e.serve(w, r, next, func(b *protocol.MailboxResponse) { b.RevokedCertificates, b.RevokedCertificatesSignature = nil, nil })
		return true
	}
}

// forgetsAtUpload is the state's operator that forgets mailbox a as its first
// prekey upload arrives, which the server then answers 404 no_such_mailbox
// (#386).
func forgetsAtUpload(e *env, a *client.Mailbox) func(int, http.ResponseWriter, *http.Request, http.Handler) bool {
	var forgot atomic.Bool
	return func(_ int, _ http.ResponseWriter, r *http.Request, _ http.Handler) bool {
		if r.Method == http.MethodPut && r.URL.Path == mailboxPath(a)+"/prekey" && forgot.CompareAndSwap(false, true) {
			e.srv.Forget(a.Address())
		}
		return false
	}
}

func partwayCases() []partwayCase {
	recv := func(e *env, a *client.Mailbox) partwaySet {
		return partwaySet{dir: a.Dir(), a: a, check: recvSaysItAlone, run: func(ctx context.Context) (any, error) { return a.Receive(ctx) }}
	}
	remedy := func(a *client.Mailbox) partwaySet {
		return partwaySet{dir: a.Dir(), a: a, check: remedySaysItAlone, run: func(ctx context.Context) (any, error) { return a.RenewAndRevoke(ctx) }}
	}
	earlier := func(a *client.Mailbox) partwaySet {
		return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.RevokeEarlier(ctx) }}
	}
	restored := func(t *testing.T, e *env, a *client.Mailbox) partwaySet {
		dir := restore(t, e, a).Dir()
		e.clock.Add(2 * time.Second)
		return partwaySet{dir: dir, a: a, run: func(ctx context.Context) (any, error) { return client.Init(ctx, dir, e.opts()) }}
	}
	serverAllowed := func(t *testing.T, a *client.Mailbox) {
		t.Helper()
		if err := a.SetPolicy(t.Context(), client.Policy{Unknown: client.LandInbox, Server: client.AdmitAllowed}); err != nil {
			t.Fatal(err)
		}
	}
	return []partwayCase{
		{"recv", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			send(t, b, a, "waits")
			return recv(e, a)
		}},
		{"recv, a renewal due", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			send(t, b, a, "waits")
			e.clock.Add(25 * time.Hour)
			return recv(e, a)
		}},
		{"recv, mended after a 404", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.srv.Forget(a.Address())
			e.clock.Add(time.Minute)
			return recv(e, a)
		}},
		{"recv, mended after certificate_revoked", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			send(t, b, a, "waits")
			publish(t, e, certsRecord(t, a.Dir(), numberOf(t, a)))
			e.clock.Add(time.Minute)
			return recv(e, a)
		}},
		{"recv, a renewal due on a mailbox its server forgot", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.srv.Forget(a.Address())
			e.clock.Add(25 * time.Hour)
			return recv(e, a)
		}},
		{"prekey renew", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.clock.Add(2 * time.Second)
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Rekey(ctx) }}
		}},
		{"prekey renew, a mailbox its server forgot", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.srv.Forget(a.Address())
			e.clock.Add(2 * time.Second)
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Rekey(ctx) }}
		}},
		{"prekey renew, its server forgets it between its read and its upload", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.clock.Add(2 * time.Second)
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Rekey(ctx) }, inner: forgetsAtUpload(e, a)}
		}},
		{"cert revoke-earlier, its server forgets it between its read and its upload", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.clock.Add(2 * time.Second)
			s := remedy(a)
			s.inner = forgetsAtUpload(e, a)
			return s
		}},
		{"cert revoke-earlier", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.clock.Add(2 * time.Second)
			return remedy(a)
		}},
		{"cert revoke-earlier after a conflict", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			publishAt(t, e.srv.URL, ownRevocation(t, a, numberOf(t, a)+7200))
			e.clock.Add(2 * time.Second)
			s := remedy(a)
			s.inner = partwayHides(e, a)
			return s
		}},
		{"RevokeEarlier", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.clock.Add(2 * time.Second)
			return earlier(a)
		}},
		{"RevokeEarlier after a conflict", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			publishAt(t, e.srv.URL, ownRevocation(t, a, numberOf(t, a)+7200))
			e.clock.Add(2 * time.Second)
			s := earlier(a)
			s.inner = partwayHides(e, a)
			return s
		}},
		{"send", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, check: outboxSaysItAlone, run: func(ctx context.Context) (any, error) { return a.Send(ctx, b.Address(), "sent") }}
		}},
		{"send, its ACL changed, the one its server took admitting no reply", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			serverAllowed(t, a)
			if err := a.SyncACL(t.Context()); err != nil {
				t.Fatal(err)
			}
			return partwaySet{dir: a.Dir(), a: a, check: outboxSaysItAlone, run: func(ctx context.Context) (any, error) { return a.Send(ctx, b.Address(), "sent") }}
		}},
		{"send JSON", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, check: outboxSaysItAlone, run: func(ctx context.Context) (any, error) {
				return a.SendJSON(ctx, b.Address(), []byte(`{"sent":true}`), client.Fields{})
			}}
		}},
		{"outbox flush, two waiting", func(t *testing.T, e *env) partwaySet {
			a, b, c := e.mailbox(), e.mailbox(), e.mailbox()
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodPost {
					forge.Refuse(w, protocol.CodeUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			})
			for _, p := range []*client.Mailbox{b, c} {
				if _, err := a.Send(t.Context(), p.Address(), "waits"); err == nil {
					t.Fatal("a send went out while the server was down")
				}
			}
			e.srv.SetMiddle(nil)
			return partwaySet{dir: a.Dir(), a: a, check: outboxSaysItAlone, joined: true, run: func(ctx context.Context) (any, error) { return a.Flush(ctx) }}
		}},
		{"outbox flush, its ACL changed, the one its server took admitting no reply", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			serverAllowed(t, a)
			if err := a.SyncACL(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/acl") {
					forge.Refuse(w, protocol.CodeUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			})
			if _, err := a.Send(t.Context(), b.Address(), "waits for the ACL"); err == nil {
				t.Fatal("a send went out before the ACL that admits its reply")
			}
			e.srv.SetMiddle(nil)
			return partwaySet{dir: a.Dir(), a: a, check: outboxSaysItAlone, joined: true, run: func(ctx context.Context) (any, error) { return a.Flush(ctx) }}
		}},
		{"init, restored from its identity alone", func(t *testing.T, e *env) partwaySet {
			return restored(t, e, e.mailbox())
		}},
		{"init, restored from its identity alone, its server forgot it", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			e.srv.Forget(a.Address())
			return restored(t, e, a)
		}},
		{"peer allow", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			serverAllowed(t, a)
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Allow(ctx, b.Address()) }}
		}},
		{"peer block", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Block(ctx, b.Address()) }}
		}},
		{"SyncACL", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			serverAllowed(t, a)
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return nil, a.SyncACL(ctx) }}
		}},
		{"account adopt", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			key := e.srv.AdoptKey("acct")
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Adopt(ctx, key) }}
		}},
		{"account leave", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return nil, a.Leave(ctx) }}
		}},
		{"Resolve a peer", func(t *testing.T, e *env) partwaySet {
			a, b := e.mailbox(), e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Resolve(ctx, b.Address()) }}
		}},
		{"Resolve itself", func(t *testing.T, e *env) partwaySet {
			a := e.mailbox()
			return partwaySet{dir: a.Dir(), a: a, run: func(ctx context.Context) (any, error) { return a.Resolve(ctx, a.Address()) }}
		}},
	}
}

// A flush that learns its mailbox's own revocation at an entry's post moves each
// later entry to outbox/failed/ with nothing asked (#340), by the mailbox's own
// ended state, the one fact, which the keep sets: here the record the mailbox is
// shown also revokes the certificate it signs under, so a later entry's seal
// would refuse before any call and leave it waiting (#414 item 1).
func TestAFlushThatLearnsItsOwnRevocationMovesEveryLaterEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.mailbox(), e.mailbox(), e.mailbox()
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost {
			forge.Refuse(w, protocol.CodeUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	for _, p := range []*client.Mailbox{b, c} {
		if _, err := a.Send(ctx, p.Address(), "waits"); err == nil {
			t.Fatal("a send went out while the server was down")
		}
	}
	e.srv.SetMiddle(nil)
	// Another holder of the mailbox's identity revokes the certificate it signs
	// under, then the address: what the server carries of it holds both.
	publish(t, e, certsRecord(t, a.Dir(), numberOf(t, a)))
	revoke(t, e, a)
	var calls []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		next.ServeHTTP(w, r)
	})
	_, err := a.Flush(ctx)
	e.srv.SetMiddle(nil)
	if !finishedOwn(err) {
		t.Errorf("the flush's error does not hold its mailbox's revocation: %v", err)
	}
	if st, serr := a.Status(ctx); serr != nil || !st.Revoked {
		t.Errorf("the mailbox does not hold its revocation: %+v, %v", st, serr)
	}
	left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P"))
	if len(left) != 0 || failed(a, b.Address())+failed(a, c.Address()) != 2 {
		t.Errorf("%d of 2 entries wait in the outbox, not in outbox/failed/, after the flush learned its mailbox's revocation (calls %v): %v", len(left), calls, err)
	}
}
