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
	"github.com/IronGall-dev/irongall-client/protocol"
)

// RenewAndRevoke is the remedy for a box whose working key may have been
// taken: a new certificate, and a list of every one before it. These tests
// play a taker who holds the old working key and a server that refuses the
// renewal, a renewal that waited when the box was copied, and a box that
// does not hold its own list.

// A holder of the working key can spend a box's renewals for the day, so the
// server refuses the owner's renewal as rate_limited. The list goes out all
// the same, naming the certificate in use: what the taker signs with it is
// refused, the box takes no mail meanwhile, and its next drain sends the
// renewal that waited, after which the box receives again.
func TestTheRemedyWhenTheDaysRenewalsAreSpent(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, reader := e.box(protocol.Classic), e.box(protocol.Classic)
	inUse := numberOf(t, a)
	taken := worker(t, a)

	says(e, protocol.CodeRateLimited, http.MethodPut, "/prekey")
	r, err := a.RenewAndRevoke(ctx, "")
	if err != nil || r == nil || r.Prekey != nil || client.Code(r.NotRenewed) != protocol.CodeRateLimited {
		t.Fatalf("the remedy with the day's renewals spent: %+v, %v", r, err)
	}
	if r.Below <= inUse || r.List == nil || !r.List.Revokes(inUse) || r.List.Revokes(r.Below) {
		t.Fatalf("its list: below %d, %+v, with %d in use", r.Below, r.List, inUse)
	}
	if !keptListOf(t, e, a).Revokes(inUse) {
		t.Fatal("the server does not hold the list")
	}
	if numberOf(t, a) != inUse || begunAt(t, a) != r.Below {
		t.Fatalf("the box records %d and holds %d waiting", numberOf(t, a), begunAt(t, a))
	}

	// What the taker signs is refused by a reader that asks, and so is the
	// owner's own unread mail under that certificate: nobody can tell them
	// apart.
	mailAs(t, e, a, reader, taken, "signed with the taken working key")
	if res := receive(t, reader); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("the taker's mail, after the list: %+v", res)
	}

	// The box is dark: its pass is under a listed certificate, and its drain
	// tries the renewal first, which the server still refuses.
	if res, err := a.Receive(ctx); err == nil || res == nil || client.Code(res.RenewErr) != protocol.CodeRateLimited {
		t.Fatalf("a drain while the renewal is refused: %+v, %v", res, err)
	}

	// Mail to it waits meanwhile: a sender refuses its prekey, which is
	// under a listed certificate, and keeps the message in its outbox.
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

// For any other failure of the renewal nothing is revoked: the server counts
// renewals only after it has taken the box's new certificate and its pass as
// timely, and no other refusal shows the box's clock right. A list numbered
// by a clock that reads ahead would name certificates not yet made.
func TestTheRemedyRevokesNothingWhenTheRenewalFailsOtherwise(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	inUse := numberOf(t, a)
	for _, code := range []protocol.Code{protocol.CodeUnavailable, protocol.CodePassExpired, protocol.CodeBadKey} {
		says(e, code, http.MethodPut, "/prekey")
		r, err := a.RenewAndRevoke(ctx, "")
		if r == nil || r.List != nil || r.Prekey != nil || client.Code(r.NotRenewed) != code || client.Code(err) != code {
			t.Fatalf("the remedy when the renewal is refused %s: %+v, %v", code, r, err)
		}
		if resp, err := http.Get(e.srv.URL + lookupOf(a)); err != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("after a renewal refused %s, the server holds a record of the box: %v %v", code, resp, err)
		} else {
			_ = resp.Body.Close()
		}
	}
	e.srv.SetMiddle(nil)
	if numberOf(t, a) != inUse {
		t.Fatal("the box moved to another certificate")
	}
}

// A renewal that waited when the box was copied is the taker's too: they hold
// its working key. The remedy never sends it: it makes a new working key and
// certificate above it, and the list names the waiting one with the rest.
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
	if !r.List.Revokes(first) || !r.List.Revokes(waiting) || r.List.Revokes(r.Below) {
		t.Fatalf("its list: %+v", r.List)
	}
	mailAs(t, e, a, reader, copied, "signed with the waiting renewal's working key")
	send(t, a, reader, "from the owner")
	res := receive(t, reader)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "from the owner" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of the copy's mail and the owner's: %+v", res)
	}
}

// A box that does not hold its own list asks what is held before it signs
// one, so its version is above it: a box restored from its identity, and one
// whose list the server took with the answer lost.
func TestTheRemedyAsksForItsOwnListFirst(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	first := numberOf(t, a)
	if r, err := a.RenewAndRevoke(ctx, ""); err != nil || r.List.Version != 1 {
		t.Fatalf("the first remedy: %+v, %v", r, err)
	}

	// The identity alone, on another machine.
	e.clock.Add(time.Hour)
	restored := restore(t, e, a)
	r, err := restored.RenewAndRevoke(ctx, "")
	if err != nil || r.List == nil || r.List.Version != 2 || !r.List.Revokes(first) || r.List.Revokes(r.Below) {
		t.Fatalf("the restored box's remedy: %+v, %v", r, err)
	}

	// The server takes the next list and its answer is lost.
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
	if r, err := restored.RenewAndRevoke(ctx, ""); err == nil || r == nil || r.List != nil || !lost {
		t.Fatalf("a remedy whose list's answer was lost: %+v, %v", r, err)
	}
	if held := keptListOf(t, e, a); held.Version != 3 {
		t.Fatalf("the server holds version %d, not the one whose answer was lost", held.Version)
	}
	e.srv.SetMiddle(nil)
	r, err = restored.RenewAndRevoke(ctx, "")
	if err != nil || r.List == nil || r.List.Version != 4 || r.List.Revokes(r.Below) {
		t.Fatalf("the remedy after the lost answer: %+v, %v", r, err)
	}
}

// keptListOf is the list the server holds for a box, checked under its
// identity.
func keptListOf(t *testing.T, e *env, a *client.Box) *protocol.RevokedCertificates {
	t.Helper()
	rec := record(t, e, a)
	list, err := protocol.VerifyRevokedCertificates(a.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
	if err != nil {
		t.Fatalf("the list the server holds: %v", err)
	}
	return list
}
