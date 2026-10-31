package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// RenewAndRevoke is the remedy for a mailbox whose working key may have been
// taken: a new certificate, and a revocation of every one before it, which
// goes out first. These tests play a taker who holds the old working key and
// a server that refuses the renewal, a renewal that waited when the mailbox was
// copied, and a mailbox that does not hold its own revocation.

// The server refuses the owner's renewal, here for the identity's
// certificates of the day. The revocation went out first, the certificate in
// use among those it revokes: what the taker signs with it is refused, the
// mailbox takes no messages meanwhile, and its next drain sends the renewal that
// waited, after which the mailbox receives again.
func TestTheRemedyWhenTheRenewalIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, reader := e.mailbox(), e.mailbox()
	inUse := numberOf(t, a)
	taken := worker(t, a)

	says(e, protocol.CodeRateLimited, http.MethodPut, "/prekey")
	r, err := a.RenewAndRevoke(ctx)
	if err != nil || r == nil || r.Prekey != nil || r.NotRevoked != nil || client.Code(r.NotRenewed) != protocol.CodeRateLimited {
		t.Fatalf("the remedy with the renewal refused: %+v, %v", r, err)
	}
	if r.Below <= inUse || r.Revoked == nil || r.Revoked.Through != r.Below-1 || !r.Revoked.Revokes(inUse) {
		t.Fatalf("its revocation: below %d, %+v, with %d in use", r.Below, r.Revoked, inUse)
	}
	if !heldCertsOf(t, e, a).Revokes(inUse) {
		t.Fatal("the server does not hold the revocation")
	}
	if numberOf(t, a) != inUse || begunAt(t, a) != r.Below {
		t.Fatalf("the mailbox records %d and holds %d waiting", numberOf(t, a), begunAt(t, a))
	}
	// Asked again while the renewal waits, it revokes what it holds already
	// and no less: one through the serial below the certificate in use would
	// be refused everywhere.
	if again, err := a.RevokeEarlier(ctx); err != nil || again == nil || again.Through != r.Revoked.Through {
		t.Fatalf("revoke earlier while the renewal waits: %+v, %v", again, err)
	}

	// What the taker signs is refused by a reader that asks, and so is the
	// owner's own unread messages under that certificate: nobody can tell them
	// apart.
	messageAs(t, e, a, reader, taken, "signed with the taken working key")
	if res := receive(t, reader); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("the taker's message, after the revocation: %+v", res)
	}

	// The mailbox is dark: its pass is under a revoked certificate, and its drain
	// tries the renewal first, which the server still refuses.
	if res, err := a.Receive(ctx); err == nil || res == nil || client.Code(res.RenewErr) != protocol.CodeRateLimited {
		t.Fatalf("a drain while the renewal is refused: %+v, %v", res, err)
	}

	// A message to it waits meanwhile: a sender refuses its prekey, which is
	// under a revoked certificate, and keeps the message in its outbox.
	if _, err := reader.Send(ctx, a.Address(), "while the mailbox is dark"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a send to the mailbox while it is dark: %v", err)
	}

	// The next day the server takes it: the drain sends the renewal that
	// waited, as it was signed, and the message that waited goes.
	e.srv.SetMiddle(nil)
	e.clock.Add(time.Hour)
	res := receive(t, a)
	if res.Renewed == nil || res.Renewed.Serial != r.Below || numberOf(t, a) != r.Below {
		t.Fatalf("the drain that sends the waiting renewal: %+v", res)
	}
	if got, err := reader.Flush(ctx); err != nil || len(got) != 1 {
		t.Fatalf("the waiting message: %v, %v", got, err)
	}
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "while the mailbox is dark" {
		t.Fatalf("the mailbox after its renewal: %+v", res)
	}
}

// The revocation goes out whatever the renewal after it meets: it is
// numbered from the new certificate, and waits on nothing the server says of
// the renewal, which a taker spending the mailbox's calls could hold back.
func TestTheRemedyRevokesWhateverTheRenewalMeets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a := e.mailbox()
	inUse := numberOf(t, a)
	for _, code := range []protocol.Code{protocol.CodeUnavailable, protocol.CodePassExpired, protocol.CodeBadKey, protocol.CodeRateLimited} {
		says(e, code, http.MethodPut, "/prekey")
		r, err := a.RenewAndRevoke(ctx)
		if err != nil || r == nil || r.Prekey != nil || r.NotRevoked != nil || client.Code(r.NotRenewed) != code || r.Revoked == nil || r.Revoked.Through != r.Below-1 {
			t.Fatalf("the remedy when the renewal is refused %s: %+v, %v", code, r, err)
		}
		if !heldCertsOf(t, e, a).Revokes(inUse) {
			t.Fatalf("after a renewal refused %s, the server holds no revocation of the certificate in use", code)
		}
	}
	e.srv.SetMiddle(nil)
	if numberOf(t, a) != inUse {
		t.Fatal("the mailbox moved to another certificate")
	}
}

// The remedy sends its renewal once, and waits out no Retry-After
// (dromas-dev/dromas-server#84): once the server holds the revocation,
// the renewal that replaces the revoked certificate spends none of the mailbox's
// counts, so the calls a taker spent before it cannot hold the renewal back.
// A renewal refused all the same is sent again at the mailbox's next renewal,
// as the one it waited for.
func TestTheRemedySendsItsRenewalOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a := e.mailbox()
	var order []string
	refused := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		if req.Method == http.MethodPut {
			order = append(order, req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:])
		}
		if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/prekey") && refused < 1 {
			refused++
			w.Header().Set("Retry-After", "1")
			fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Code: protocol.CodeRateLimited, Status: http.StatusTooManyRequests})
			return
		}
		next.ServeHTTP(w, req)
	})
	r, err := a.RenewAndRevoke(ctx)
	if err != nil || r.Prekey != nil || client.Code(r.NotRenewed) != protocol.CodeRateLimited || r.Revoked == nil {
		t.Fatalf("the remedy after a refusal with a Retry-After of a second: %+v, %v", r, err)
	}
	if strings.Join(order, " ") != "revocations prekey" {
		t.Fatalf("the remedy's uploads, in order: %v", order)
	}
	order = nil
	if _, err := a.Rekey(ctx); err != nil || numberOf(t, a) != r.Below {
		t.Fatalf("the next renewal: %v; the mailbox stands at certificate %d, not the remedy's %d", err, numberOf(t, a), r.Below)
	}
	if strings.Join(order, " ") != "prekey" {
		t.Fatalf("the next renewal's uploads, in order: %v", order)
	}
}

// A renewal that waited when the mailbox was copied is the taker's too: they hold
// its working key. The remedy never sends it: it makes a new working key and
// certificate above it, and revokes the waiting one with the rest.
func TestTheRemedySendsNoRenewalThatWaited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, reader := e.mailbox(), e.mailbox()
	first := numberOf(t, a)
	kept := uploads(e, a)
	if _, err := a.Rekey(ctx); err == nil {
		t.Fatal("the renewal was meant to wait")
	}
	e.srv.SetMiddle(nil)
	waiting := begunAt(t, a)
	if waiting <= first || len(*kept) != 1 {
		t.Fatalf("no renewal waits: %d after %d", waiting, first)
	}
	copied := workerAt(t, a, waiting) // the copy of the mailbox holds it

	r, err := a.RenewAndRevoke(ctx)
	if err != nil || r.Prekey == nil || r.Below != r.Prekey.Serial || r.Below <= waiting {
		t.Fatalf("the remedy after a renewal waited: %+v, %v", r, err)
	}
	if st, _ := e.srv.Prekey(a.Address()); bytes.Equal(st, (*kept)[0].Prekey) {
		t.Fatal("the remedy published the statement that waited")
	}
	if !r.Revoked.Revokes(first) || !r.Revoked.Revokes(waiting) || r.Revoked.Revokes(r.Below) {
		t.Fatalf("its revocation: %+v", r.Revoked)
	}
	messageAs(t, e, a, reader, copied, "signed with the waiting renewal's working key")
	send(t, a, reader, "from the owner")
	res := receive(t, reader)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "from the owner" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of the copy's message and the owner's: %+v", res)
	}
}

// A mailbox that does not hold its own revocation asks what is held before it
// renews, and its new certificate is numbered above it: a mailbox restored from
// its identity on a machine whose clock reads behind, where the server holds
// a revocation through a serial above the mailbox's certificate in use, and a
// mailbox whose revocation the server took with the answer lost.
func TestTheRemedyAsksForItsOwnRevocationFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a := e.mailbox()
	first := numberOf(t, a)

	// An hour on, the renewal is refused, so the server holds a revocation
	// through one below the renewal that waits: above the certificate in use.
	e.clock.Add(time.Hour)
	says(e, protocol.CodeRateLimited, http.MethodPut, "/prekey")
	r, err := a.RenewAndRevoke(ctx)
	if err != nil || r.Revoked == nil || r.Revoked.Through != r.Below-1 || servedCertificate(t, e, a) != first {
		t.Fatalf("the first remedy: %+v, %v", r, err)
	}
	e.srv.SetMiddle(nil)

	// The identity alone, on a machine whose clock reads five minutes behind
	// the one that revoked: by its clock alone it would number a certificate
	// the identity has revoked, which the server refuses.
	behind := func() time.Time { return e.clock.Now().Add(-5 * time.Minute) }
	if protocol.SerialAt(behind(), first) > r.Revoked.Through {
		t.Fatal("the restored mailbox's clock gives a serial above the revocation, so this tests nothing")
	}
	restored := restoreWith(t, e, a, behind)
	held := r.Revoked.Through
	r, err = restored.RenewAndRevoke(ctx)
	if err != nil || r.Prekey == nil || r.Below <= held || r.Revoked == nil || r.Revoked.Through != r.Below-1 {
		t.Fatalf("the restored mailbox's remedy, the server holding a revocation through %d: %+v, %v", held, r, err)
	}

	// The server takes the next revocation and its answer is lost.
	lost := false
	e.srv.SetMiddle(func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/revocations") && !lost {
			lost = true
			next.ServeHTTP(httptest.NewRecorder(), req)
			http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
			return
		}
		next.ServeHTTP(w, req)
	})
	e.clock.Add(time.Hour)
	r, err = restored.RenewAndRevoke(ctx)
	if err != nil || r == nil || r.Revoked != nil || r.NotRevoked == nil || !lost {
		t.Fatalf("a remedy whose revocation's answer was lost: %+v, %v", r, err)
	}
	if held := heldCertsOf(t, e, a); held.Through != r.Below-1 {
		t.Fatalf("the server holds a revocation through %d, not the one whose answer was lost", held.Through)
	}
	e.srv.SetMiddle(nil)
	lostBelow := r.Below
	r, err = restored.RenewAndRevoke(ctx)
	if err != nil || r.Revoked == nil || r.Below <= lostBelow || r.Revoked.Through != r.Below-1 {
		t.Fatalf("the remedy after the lost answer: %+v, %v", r, err)
	}
}

// heldCertsOf is the revocation of a mailbox's certificates the server holds,
// checked under its identity.
func heldCertsOf(t *testing.T, e *env, a *client.Mailbox) *protocol.RevokedCertificates {
	t.Helper()
	rec := record(t, e, a)
	certs, err := protocol.VerifyRevokedCertificates(a.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
	if err != nil {
		t.Fatalf("the revocation of certificates the server holds: %v", err)
	}
	return certs
}

// A mailbox its server forgot reads its revocations at GET …/revocations, and
// the remedy's ask after a conflict does too (#258): the server holds a
// revocation of the mailbox's certificates through T, two hours above the
// certificate in use, made on another machine, and gives no answer to the
// remedy's first read of it, so the remedy's record conflicts. The mailbox reads
// itself again, keeps the higher one, and numbers its new certificate above
// it (PROTOCOL.md §12.6).
func TestTheRemedyOfAForgottenMailboxAsksItsRevocationsAgainAfterItsConflict(t *testing.T) {
	t.Parallel()
	e := newWorkEnv(t)
	a := e.mailbox()
	T := numberOf(t, a) + 7200
	publish(t, e, certsRecord(t, a.Dir(), T))
	e.srv.Forget(a.Address())
	revocations := "/v1/" + a.Address().String() + "/revocations"
	first := true
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == revocations && first {
			first = false
			forge.Refuse(w, protocol.CodeUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	r, err := a.RenewAndRevoke(context.Background())
	if err != nil || r == nil {
		t.Fatalf("the remedy: %v", err)
	}
	if r.Revoked == nil || r.Revoked.Through < T || r.Below <= T || r.Prekey == nil {
		t.Errorf("the remedy of a forgotten mailbox after its server's conflict: below %d, revoked %v, not revoked %v, not renewed %v; the server holds through %d", r.Below, r.Revoked, r.NotRevoked, r.NotRenewed, T)
	}
}

// A revocation the mailbox's server took, and a fault of the mailbox at its keep
// after that, is a revocation taken, as a renewal is (#110): the remedy and
// RevokeEarlier return it with the fault as the call's error, never as a
// revocation not taken, and the mailbox's next read of itself keeps what its
// server holds (#383). The fault is a full disk's from the publish on: at
// the keep alone, after which the remedy's renewal is taken, or at every
// write after it, where the renewal is not.
func TestAFaultAfterTheRevocationWasTakenLeavesItTaken(t *testing.T) {
	ctx := context.Background()
	full := &os.PathError{Op: "write", Path: "state", Err: syscall.ENOSPC}
	for _, c := range []struct {
		name string
		// once is a fault at the keep alone.
		once bool
		run  func(t *testing.T, b *client.Mailbox) (*protocol.RevokedCertificates, error)
	}{
		{"RevokeEarlier", true, func(t *testing.T, b *client.Mailbox) (*protocol.RevokedCertificates, error) {
			return b.RevokeEarlier(ctx)
		}},
		{"the remedy, its renewal taken", true, func(t *testing.T, b *client.Mailbox) (*protocol.RevokedCertificates, error) {
			r, err := b.RenewAndRevoke(ctx)
			if r == nil {
				t.Fatalf("no remedy: %v", err)
			}
			if r.NotRevoked != nil || r.Prekey == nil || r.NotRenewed != nil {
				t.Errorf("the remedy: %+v, %v", r, err)
			}
			return r.Revoked, err
		}},
		{"the remedy, its renewal not taken", false, func(t *testing.T, b *client.Mailbox) (*protocol.RevokedCertificates, error) {
			r, err := b.RenewAndRevoke(ctx)
			if r == nil {
				t.Fatalf("no remedy: %v", err)
			}
			if r.NotRevoked != nil || r.Prekey != nil || !errors.Is(r.NotRenewed, syscall.ENOSPC) {
				t.Errorf("the remedy: %+v, %v", r, err)
			}
			return r.Revoked, err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newWorkEnv(t)
			b := e.mailbox()
			e.clock.Add(2 * time.Second)
			var armed atomic.Bool
			client.SetStep(func(name string) {
				if name == "revocation published" {
					armed.Store(true)
				}
			})
			t.Cleanup(func() { client.SetStep(nil) })
			client.SetWriteFault(t, func() error {
				if c.once && armed.CompareAndSwap(true, false) || !c.once && armed.Load() {
					return full
				}
				return nil
			})
			certs, err := c.run(t, b)
			armed.Store(false)
			if certs == nil || !errors.Is(err, syscall.ENOSPC) || heldCertsOf(t, e, b).Through != certs.Through || has(b, "revoked-certs.json") {
				t.Fatalf("a revocation taken and not kept: %+v, %v; kept %v", certs, err, has(b, "revoked-certs.json"))
			}
			if held, err := b.Ask(ctx, b.Address()); err != nil || held.Certificates == nil || held.Certificates.Through != certs.Through {
				t.Errorf("the mailbox's next read of itself: %+v, %v", held, err)
			}
		})
	}
}

// A conflict whose read again shows a higher revocation of the mailbox's
// certificates, which verifies, and a fault of the mailbox at its keep: the
// revocation is the server's and shown, so RevokeEarlier and the remedy
// return it with the fault as the call's error, never as nothing revoked,
// and the remedy numbers its renewal above it, which the server then takes
// (#406 item 1; #383 on the conflict path). The fault fires once, at the
// keep the read after the conflict makes.
func TestAFaultKeepingTheRevocationShownAfterAConflictLeavesItTaken(t *testing.T) {
	ctx := context.Background()
	full := &os.PathError{Op: "write", Path: "state", Err: syscall.ENOSPC}
	for _, name := range []string{"RevokeEarlier", "RenewAndRevoke"} {
		t.Run(name, func(t *testing.T) {
			e := newWorkEnv(t)
			a := e.mailbox()
			T := numberOf(t, a) + 7200
			publish(t, e, certsRecord(t, a.Dir(), T)) // a higher revocation, the identity's own
			var reads atomic.Int32
			var armed, fired atomic.Bool
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodGet && r.URL.Path == mailboxPath(a) {
					if reads.Add(1) == 1 { // hidden at the first read: the publish conflicts
						e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.RevokedCertificates, br.RevokedCertificatesSignature = nil, nil })
						return
					}
					if reads.Load() == 2 { // shown at the read after the conflict; its keep fails
						armed.Store(true)
					}
				}
				next.ServeHTTP(w, r)
			})
			client.SetWriteFault(t, func() error {
				if armed.CompareAndSwap(true, false) {
					fired.Store(true)
					return full
				}
				return nil
			})
			var certs *protocol.RevokedCertificates
			var err error
			if name == "RevokeEarlier" {
				certs, err = a.RevokeEarlier(ctx)
			} else {
				r, rerr := a.RenewAndRevoke(ctx)
				if r == nil {
					t.Fatalf("no remedy: %v", rerr)
				}
				certs, err = r.Revoked, rerr
				if r.NotRevoked != nil || r.NotRenewed != nil || r.Prekey == nil || r.Below <= T || servedSerial(t, e, a) != r.Below {
					t.Errorf("the remedy: below %d, not revoked %v, not renewed %v, prekey %+v; the server holds through %d and serves %d", r.Below, r.NotRevoked, r.NotRenewed, r.Prekey, T, servedSerial(t, e, a))
				}
			}
			e.srv.SetMiddle(nil)
			if !fired.Load() {
				t.Fatal("the fault never fired")
			}
			if certs == nil || certs.Through != T || !errors.Is(err, syscall.ENOSPC) {
				t.Errorf("the server holds and showed a verified revocation through %d: %+v, %v", T, certs, err)
			}
		})
	}
}
