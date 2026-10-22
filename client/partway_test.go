package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A command that learns part way that its box is finished, a read on the way
// showing the box its own revocation, which it keeps once it verifies, says
// that alone and asks and signs nothing more after it (PROTOCOL.md §6.3):
// whatever door it learns it by.

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

// finishedOwn reports whether err is the box's own RevokedError.
func finishedOwn(err error) bool {
	var gone *client.RevokedError
	return errors.As(err, &gone) && gone.Own
}

// callsFrom is the calls the server logged from index from on.
func callsFrom(e *env, from int) []string {
	var out []string
	for _, c := range e.srv.Requests()[from:] {
		p := c.Method + " " + c.Path
		if c.Pass {
			p += " +pass"
		}
		out = append(out, p)
	}
	return out
}

// The remedy shown its own revocation at its publish, or at the read after a
// conflict, says REVOKED alone, with no Remedy: no server took anything from
// it there, and it signs and sends nothing with a pass after (#326).
func TestARemedyShownItsOwnRevocationOnTheWaySaysThatAlone(t *testing.T) {
	for _, at := range []string{"its publish", "the read after a conflict"} {
		t.Run(at, func(t *testing.T) {
			e := newEnv(t)
			a := e.box(protocol.Classic)
			first, files := numberOf(t, a), prekeyFiles(t, a)
			rec, err := a.Revocation()
			if err != nil {
				t.Fatal(err)
			}
			own := boxPath(a)
			var reads atomic.Int32
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				switch {
				case at == "its publish" && r.Method == http.MethodGet && r.URL.Path == own && reads.Add(1) == 1:
					next.ServeHTTP(w, r)
					putRecord(t, next, a.Address(), rec)
					return
				case at == "the read after a conflict" && r.Method == http.MethodPut && r.URL.Path == own+"/revocations" && reads.Add(1) == 1:
					putRecord(t, next, a.Address(), certsRecord(t, a.Dir(), first+7200))
					next.ServeHTTP(w, r) // 409 conflict
					putRecord(t, next, a.Address(), rec)
					return
				}
				next.ServeHTTP(w, r)
			})
			before := len(e.srv.Requests())
			r, err := a.RenewAndRevoke(context.Background(), "")
			calls := callsFrom(e, before)
			if r != nil || !finishedOwn(err) {
				t.Fatalf("the remedy: %+v, %v; calls %q", r, err, calls)
			}
			for _, c := range calls {
				if strings.HasSuffix(c, "+pass") {
					t.Errorf("a pass went out: %q", calls)
				}
			}
			if numberOf(t, a) != first || prekeyFiles(t, a) != files {
				t.Errorf("the box renewed or made a key: number %d, was %d; %d prekey files, was %d", numberOf(t, a), first, prekeyFiles(t, a), files)
			}
		})
	}
}

// prekeyFiles is how many files a box's prekeys/ and work/ hold.
func prekeyFiles(t *testing.T, b *client.Box) int {
	t.Helper()
	p, err := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := filepath.Glob(filepath.Join(b.Dir(), "work", "*"))
	if err != nil {
		t.Fatal(err)
	}
	return len(p) + len(w)
}

// A drain whose pass is refused certificate_revoked, and whose read of the
// box shows its own address revoked, at the box or at its revocations, is
// refused REVOKED; with its certificate revoked as well it renews nothing,
// and keeps no renewal that failed. So is a drain whose due renewal reads the
// address revoked, with nothing of that read's 410 as a renewal that failed
// (#335).
func TestADrainShownItsOwnRevocationOnTheWaySaysRevoked(t *testing.T) {
	ctx := context.Background()
	for _, c := range []string{"the read is 410", "the box is 404 and its revocations hold it", "its certificate revoked too", "its due renewal reads it"} {
		t.Run(c, func(t *testing.T) {
			e := newEnv(t)
			a := e.box(protocol.Classic)
			rec, err := a.Revocation()
			if err != nil {
				t.Fatal(err)
			}
			if c == "its certificate revoked too" {
				both := certsRecord(t, a.Dir(), numberOf(t, a))
				rec.RevokedCertificates, rec.RevokedCertificatesSignature = both.RevokedCertificates, both.RevokedCertificatesSignature
			}
			publish(t, e, rec)
			own := boxPath(a)
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				switch {
				case c == "its due renewal reads it":
				case r.Method == http.MethodGet && r.URL.Path == own+"/messages":
					forge.Refuse(w, protocol.CodeCertificateRevoked)
					return
				case c == "the box is 404 and its revocations hold it" && r.Method == http.MethodGet && r.URL.Path == own:
					forge.Refuse(w, protocol.CodeNoSuchMailbox)
					return
				}
				next.ServeHTTP(w, r)
			})
			if c == "its due renewal reads it" {
				e.clock.Add(25 * time.Hour)
			}
			before := len(e.srv.Requests())
			res, err := a.Receive(ctx)
			calls := callsFrom(e, before)
			if !finishedOwn(err) {
				t.Fatalf("the drain: %v; calls %q", err, calls)
			}
			if res != nil && res.RenewErr != nil {
				t.Errorf("a renewal that failed: %v", res.RenewErr)
			}
			if has(a, "renew-failed") {
				t.Error("the box keeps a renewal that failed")
			}
			for _, call := range calls {
				if strings.HasPrefix(call, "PUT") {
					t.Errorf("the drain sent %q", call)
				}
			}
		})
	}
}

// A flush that learns at one entry that its box is finished posts nothing
// more, and reads no later entry's recipient: each goes to outbox/failed/
// with nothing asked. So does a send whose read of itself, on a pass refused
// on the way, showed the box its own revocation (#340).
func TestAFlushShownItsOwnRevocationAtOneEntryAsksNothingMore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	peers := []*client.Box{e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)}
	down := true
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if down && r.Method == http.MethodPost {
			forge.Refuse(w, protocol.CodeUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	for _, p := range peers {
		if _, err := a.Send(ctx, p.Address(), "waits in the outbox"); err == nil {
			t.Fatal("a send went out while the server was down")
		}
	}
	down = false
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	publish(t, e, rec)
	before := len(e.srv.Requests())
	_, err = a.Flush(ctx)
	read := 0
	for _, call := range e.srv.Requests()[before:] {
		for _, p := range peers {
			if call.Method == http.MethodGet && call.Path == boxPath(p) {
				read++
			}
		}
	}
	failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", "*.P"))
	left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P"))
	if !finishedOwn(err) || read != 1 || len(failed) != 3 || len(left) != 0 {
		t.Fatalf("the flush: %v; %d recipients read, want the first alone; %d in outbox/failed/, %d left", err, read, len(failed), len(left))
	}
}

// Init on an identity alone, of an address its server holds revoked, says
// REVOKED and keeps the revocation: where its read shows it, and where the
// read was clean and the address was revoked before the registration's
// upload, whose 410 has the box read itself (#342).
func TestInitOfARestoredBoxRevokedAtItsServerSaysRevoked(t *testing.T) {
	ctx := context.Background()
	for _, c := range []string{"at its read", "at its upload"} {
		t.Run(c, func(t *testing.T) {
			e := newEnv(t)
			a := e.box(protocol.Classic)
			rec, err := a.Revocation()
			if err != nil {
				t.Fatal(err)
			}
			if c == "at its read" {
				publish(t, e, rec)
			} else {
				var once atomic.Bool
				e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					next.ServeHTTP(w, r)
					if r.Method == http.MethodGet && r.URL.Path == boxPath(a) && once.CompareAndSwap(false, true) {
						putRecord(t, next, a.Address(), rec)
					}
				})
			}
			dir := restore(t, e, a).Dir()
			if _, err := client.Init(ctx, dir, e.opts(), protocol.Classic); !finishedOwn(err) {
				t.Fatalf("init: %v", err)
			}
			b, err := client.Open(dir, e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if st, err := b.Status(); err != nil || !st.Revoked {
				t.Errorf("the restored box after init: %+v, %v", st, err)
			}
		})
	}
}
