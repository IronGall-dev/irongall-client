package client_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

// The remedy with its own server down for the read of the box, or for
// everything: the revocation still goes to the revocation server it lists
// (PROTOCOL.md §6.3).
func TestTheRemedyReachesTheRevocationServersWithItsOwnServerDown(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	o := e.listing(rs.URL)
	a := e.boxWith(o)
	o.Base = "http://127.0.0.1:1" // nothing listens
	down, err := client.Open(a.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	r, err := down.RenewAndRevoke(ctx, "")
	if r == nil || r.Revoked == nil || r.Unread == nil || r.OwnTook || r.NotRenewed == nil || err != nil {
		t.Fatalf("the remedy with its own server down: %+v, %v", r, err)
	}
	if rs.holds(t, a.Address()) == nil {
		t.Error("the revocation server holds nothing")
	}
}

// With no revocation server listed, and its own server failing only the read
// of the box: the remedy revokes and renews there all the same.
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
	if err != nil || r == nil || r.Unread == nil || r.Prekey == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) || !r.OwnTook {
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
	stem := filepath.Join(a.Dir(), "prekeys", strconv.FormatUint(first, 10))
	old, err := os.ReadFile(stem + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	oldSig, err := os.ReadFile(stem + ".txt.sig")
	if err != nil {
		t.Fatal(err)
	}
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

// A revocation server the box lists holds a revocation through T, two hours
// past the box's clock, and gives no answer within the wait to the remedy's
// ask. Its server took the lower one, and the revocation server answers the
// remedy's record conflict: the remedy asks again, signs through T, and
// numbers its certificate above it.
func TestTheRemedyNumbersAboveARevocationShownLate(t *testing.T) {
	ctx := context.Background()
	client.SetRevocationServerWait(t, 300*time.Millisecond)
	e := newEnv(t)
	rs := newRevServer(t)
	a := e.boxWith(e.listing(rs.URL))
	T := numberOf(t, a) + 7200
	publishAt(t, rs.URL, ownRevocation(t, a, T))
	var gets atomic.Int32
	rs.set(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && gets.Add(1) == 1 {
			<-r.Context().Done() // no answer within the wait
			return true
		}
		return false
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Revoked == nil || r.Revoked.Through != T || r.Below != T+1 || r.Prekey == nil || r.NotRevoked != nil {
		t.Fatalf("the remedy shown T %d late: %+v, %v", T, r, err)
	}
	s := e.boxWith(e.listing(rs.URL))
	if _, err := s.Send(ctx, a.Address(), "to the remedied box"); err != nil {
		t.Errorf("a sender that lists the revocation server: %v", err)
	}
}

// The box's own server holds a revocation through T and leaves it out of its
// first read of the box, then answers the remedy's record conflict: the
// remedy asks again, and numbers above T.
func TestTheRemedyAsksAgainAfterItsServerAnswersConflict(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	T := numberOf(t, a) + 7200
	publishAt(t, e.srv.URL, ownRevocation(t, a, T))
	reads := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(a) && reads == 0 {
			reads++
			e.serve(w, r, next, func(b *protocol.BoxResponse) { b.RevokedCertificates, b.RevokedCertificatesSignature = nil, nil })
			return
		}
		next.ServeHTTP(w, r)
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Revoked == nil || r.Revoked.Through != T || r.Below != T+1 || r.Prekey == nil {
		t.Fatalf("the remedy, T %d hidden from the first read: %+v, %v", T, r, err)
	}
}

// One remedy asks a revocation server that gives no answer once, and its own
// server's box once: the read of the box carries both the statement it
// serves and what it holds of the box's revocations.
func TestTheRemedyAsksEachServerOnce(t *testing.T) {
	ctx := context.Background()
	client.SetRevocationServerWait(t, 300*time.Millisecond)
	e := newEnv(t)
	rs := newRevServer(t)
	o := e.listing(rs.URL)
	var told silences
	o.NoAnswer = told.note
	a := e.boxWith(o)
	rs.set(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet {
			<-r.Context().Done()
			return true
		}
		return false
	})
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
	if n := rs.count(http.MethodGet, a.Address()); n != 1 || told.n() != 1 || reads.Load() != 1 {
		t.Errorf("the silent revocation server asked %d times and told %d times; the box's own read %d times", n, told.n(), reads.Load())
	}
}

// A box that keeps its own revocation of its address is finished, whatever
// its own server still serves (PROTOCOL.md §6.3): here its server was down
// when it was published, and a revocation server took it.
func TestABoxThatKeepsItsOwnRevocationSignsNothingMore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a := e.boxWith(e.listing(rs.URL))
	b := e.box(protocol.Classic)
	send(t, b, a, "to a box about to be finished")
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
	// Refused before anything is asked: no call reaches the server.
	var calls atomic.Int32
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		return false
	})
	var gone *client.RevokedError
	if _, err := a.Send(ctx, b.Address(), "from a finished box"); !errors.As(err, &gone) || !gone.Own || calls.Load() != 0 {
		t.Errorf("a send: %v, with %d calls to the server", err, calls.Load())
	}
	if failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", "*.P")); len(failed) != 1 {
		t.Errorf("%d entries in outbox/failed/, want the one it can never deliver", len(failed))
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Errorf("its reader delivered %d", len(res.Delivered))
	}
	calls.Store(0)
	if _, err := a.Receive(ctx); !errors.As(err, &gone) || calls.Load() != 0 {
		t.Errorf("a drain: %v, with %d calls to the server", err, calls.Load())
	}
	before, begun := numberOf(t, a), begunAt(t, a)
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx, ""); !errors.As(err, &gone) || numberOf(t, a) != before || begunAt(t, a) != begun {
		t.Errorf("a renewal: %v, serial %d -> %d, a prekey begun at %d -> %d", err, before, numberOf(t, a), begun, begunAt(t, a))
	}
	if err := a.Leave(ctx); !errors.As(err, &gone) {
		t.Errorf("an owner call: %v", err)
	}
	// What carries no pass still goes: published again, its server takes it.
	if _, err := a.Revoke(ctx, rec); err != nil {
		t.Errorf("published again: %v", err)
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
// once the renewal is taken. Here the box's own server was down for both of
// the remedy's PUTs, and a revocation server took the revocation.
func TestASendInTheRemedysWindowWaitsForTheRenewal(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	a, reader := e.boxWith(e.listing(rs.URL)), e.boxWith(e.listing(rs.URL))
	inUse := numberOf(t, a)
	watch(e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && (r.URL.Path == boxPath(a)+"/revocations" || r.URL.Path == boxPath(a)+"/prekey") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if r == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) || r.NotRenewed == nil || r.OwnTook {
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
