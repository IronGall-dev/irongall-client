package client_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// RenewAndRevoke is the remedy for a box whose working key may have been
// taken: a new certificate, and a revocation of every one before it, which
// goes out first. These tests play a taker who holds the old working key and
// a server that refuses the renewal, a renewal that waited when the box was
// copied, and a box that does not hold its own revocation.

// The server refuses the owner's renewal, here for the identity's
// certificates of the day. The revocation went out first, the certificate in
// use among those it revokes: what the taker signs with it is refused, the
// box takes no mail meanwhile, and its next drain sends the renewal that
// waited, after which the box receives again.
func TestTheRemedyWhenTheRenewalIsRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, reader := e.box(protocol.Classic), e.box(protocol.Classic)
	inUse := numberOf(t, a)
	taken := worker(t, a)

	says(e, protocol.CodeRateLimited, http.MethodPut, "/prekey")
	r, err := a.RenewAndRevoke(ctx, "")
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
		t.Fatalf("the box records %d and holds %d waiting", numberOf(t, a), begunAt(t, a))
	}
	// Asked again while the renewal waits, it revokes what it holds already
	// and no less: one through the serial below the certificate in use would
	// be refused everywhere.
	if again, err := a.RevokeEarlier(ctx); err != nil || again == nil || again.Through != r.Revoked.Through {
		t.Fatalf("revoke earlier while the renewal waits: %+v, %v", again, err)
	}

	// What the taker signs is refused by a reader that asks, and so is the
	// owner's own unread mail under that certificate: nobody can tell them
	// apart.
	mailAs(t, e, a, reader, taken, "signed with the taken working key")
	if res := receive(t, reader); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("the taker's mail, after the revocation: %+v", res)
	}

	// The box is dark: its pass is under a revoked certificate, and its drain
	// tries the renewal first, which the server still refuses.
	if res, err := a.Receive(ctx); err == nil || res == nil || client.Code(res.RenewErr) != protocol.CodeRateLimited {
		t.Fatalf("a drain while the renewal is refused: %+v, %v", res, err)
	}

	// Mail to it waits meanwhile: a sender refuses its prekey, which is
	// under a revoked certificate, and keeps the message in its outbox.
	if _, err := reader.Send(ctx, a.Address(), "while the box is dark"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a send to the box while it is dark: %v", err)
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
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "while the box is dark" {
		t.Fatalf("the box after its renewal: %+v", res)
	}
}

// The revocation goes out whatever the renewal after it meets: it is
// numbered from the new certificate, and waits on nothing the server says of
// the renewal, which a taker spending the box's calls could hold back.
func TestTheRemedyRevokesWhateverTheRenewalMeets(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	inUse := numberOf(t, a)
	for _, code := range []protocol.Code{protocol.CodeUnavailable, protocol.CodePassExpired, protocol.CodeBadKey, protocol.CodeRateLimited} {
		says(e, code, http.MethodPut, "/prekey")
		r, err := a.RenewAndRevoke(ctx, "")
		if err != nil || r == nil || r.Prekey != nil || r.NotRevoked != nil || client.Code(r.NotRenewed) != code || r.Revoked == nil || r.Revoked.Through != r.Below-1 {
			t.Fatalf("the remedy when the renewal is refused %s: %+v, %v", code, r, err)
		}
		if !heldCertsOf(t, e, a).Revokes(inUse) {
			t.Fatalf("after a renewal refused %s, the server holds no revocation of the certificate in use", code)
		}
	}
	e.srv.SetMiddle(nil)
	if numberOf(t, a) != inUse {
		t.Fatal("the box moved to another certificate")
	}
}

// A taker who holds the working key can spend the box's calls, so the server
// may refuse the renewal for them. Once the server holds the revocation it
// takes nothing under the taken certificate, and the calls come back: a
// refusal with a short Retry-After is waited out and the renewal sent once
// more. A longer one is not waited for.
func TestTheRemedyWaitsOutAShortRetryAfter(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	var order []string
	refused := 0
	retryAfter := "1"
	e.srv.SetMiddle(func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		if req.Method == http.MethodPut {
			order = append(order, req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:])
		}
		if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/prekey") && refused < 1 {
			refused++
			w.Header().Set("Retry-After", retryAfter)
			fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Code: protocol.CodeRateLimited, Status: http.StatusTooManyRequests})
			return
		}
		next.ServeHTTP(w, req)
	})
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r.Prekey == nil || r.NotRenewed != nil || r.Revoked == nil || numberOf(t, a) != r.Below {
		t.Fatalf("the remedy after a short Retry-After: %+v, %v", r, err)
	}
	if strings.Join(order, " ") != "revocations prekey prekey" {
		t.Fatalf("the remedy's uploads, in order: %v", order)
	}

	refused, retryAfter, order = 0, "120", nil
	r, err = a.RenewAndRevoke(ctx, "")
	if err != nil || r.Prekey != nil || client.Code(r.NotRenewed) != protocol.CodeRateLimited || r.Revoked == nil {
		t.Fatalf("the remedy after a long Retry-After: %+v, %v", r, err)
	}
	if strings.Join(order, " ") != "revocations prekey" {
		t.Fatalf("the remedy's uploads after a long Retry-After, in order: %v", order)
	}
}

// A renewal that waited when the box was copied is the taker's too: they hold
// its working key. The remedy never sends it: it makes a new working key and
// certificate above it, and revokes the waiting one with the rest.
func TestTheRemedySendsNoRenewalThatWaited(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, reader := e.box(protocol.Classic), e.box(protocol.Classic)
	first := numberOf(t, a)
	kept := uploads(e, a)
	if _, err := a.Rekey(ctx, ""); err == nil {
		t.Fatal("the renewal was meant to wait")
	}
	e.srv.SetMiddle(nil)
	waiting := begunAt(t, a)
	if waiting <= first || len(*kept) != 1 {
		t.Fatalf("no renewal waits: %d after %d", waiting, first)
	}
	copied := workerAt(t, a, waiting) // the copy of the box holds it

	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r.Prekey == nil || r.Below != r.Prekey.Serial || r.Below <= waiting {
		t.Fatalf("the remedy after a renewal waited: %+v, %v", r, err)
	}
	if st, _ := e.srv.Prekey(a.Address()); bytes.Equal(st, (*kept)[0].Prekey) {
		t.Fatal("the remedy published the statement that waited")
	}
	if !r.Revoked.Revokes(first) || !r.Revoked.Revokes(waiting) || r.Revoked.Revokes(r.Below) {
		t.Fatalf("its revocation: %+v", r.Revoked)
	}
	mailAs(t, e, a, reader, copied, "signed with the waiting renewal's working key")
	send(t, a, reader, "from the owner")
	res := receive(t, reader)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "from the owner" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of the copy's mail and the owner's: %+v", res)
	}
}

// A box that does not hold its own revocation asks what is held before it
// renews, and its new certificate is numbered above it: a box restored from
// its identity on a machine whose clock reads behind, where the server holds
// a revocation through a serial above the box's certificate in use, and a
// box whose revocation the server took with the answer lost.
func TestTheRemedyAsksForItsOwnRevocationFirst(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	first := numberOf(t, a)

	// An hour on, the renewal is refused, so the server holds a revocation
	// through one below the renewal that waits: above the certificate in use.
	e.clock.Add(time.Hour)
	says(e, protocol.CodeRateLimited, http.MethodPut, "/prekey")
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r.Revoked == nil || r.Revoked.Through != r.Below-1 || servedCertificate(t, e, a) != first {
		t.Fatalf("the first remedy: %+v, %v", r, err)
	}
	e.srv.SetMiddle(nil)

	// The identity alone, on a machine whose clock reads five minutes behind
	// the one that revoked: by its clock alone it would number a certificate
	// the identity has revoked, which the server refuses.
	behind := func() time.Time { return e.clock.Now().Add(-5 * time.Minute) }
	if protocol.SerialAt(behind(), first) > r.Revoked.Through {
		t.Fatal("the restored box's clock gives a serial above the revocation, so this tests nothing")
	}
	restored := restoreWith(t, e, a, behind)
	held := r.Revoked.Through
	r, err = restored.RenewAndRevoke(ctx, "")
	if err != nil || r.Prekey == nil || r.Below <= held || r.Revoked == nil || r.Revoked.Through != r.Below-1 {
		t.Fatalf("the restored box's remedy, the server holding a revocation through %d: %+v, %v", held, r, err)
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
	r, err = restored.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Revoked != nil || r.NotRevoked == nil || !lost {
		t.Fatalf("a remedy whose revocation's answer was lost: %+v, %v", r, err)
	}
	if held := heldCertsOf(t, e, a); held.Through != r.Below-1 {
		t.Fatalf("the server holds a revocation through %d, not the one whose answer was lost", held.Through)
	}
	e.srv.SetMiddle(nil)
	lostBelow := r.Below
	r, err = restored.RenewAndRevoke(ctx, "")
	if err != nil || r.Revoked == nil || r.Below <= lostBelow || r.Revoked.Through != r.Below-1 {
		t.Fatalf("the remedy after the lost answer: %+v, %v", r, err)
	}
}

// heldCertsOf is the revocation of a box's certificates the server holds,
// checked under its identity.
func heldCertsOf(t *testing.T, e *env, a *client.Box) *protocol.RevokedCertificates {
	t.Helper()
	rec := record(t, e, a)
	certs, err := protocol.VerifyRevokedCertificates(a.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
	if err != nil {
		t.Fatalf("the revocation of certificates the server holds: %v", err)
	}
	return certs
}
