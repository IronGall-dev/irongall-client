package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// largest lists box b's first message as a ciphertext of the protocol's
// largest size, all zeros, and answers its fetch as the server answers one,
// a Range included, each fetch's bytes counted in served, in chunks of 64
// KiB after each pause: none for a link at full speed. It returns the id.
func largest(t *testing.T, e *env, b *client.Box, pause func() time.Duration, served *[]*atomic.Int64, mu *sync.Mutex) string {
	t.Helper()
	ct := make([]byte, protocol.MaxCiphertext)
	sum := sha256.Sum256(ct)
	id := hex.EncodeToString(sum[:])
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages":
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			var list protocol.MessageList
			if err := protocol.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Messages) == 0 {
				t.Errorf("the list: %v", err)
				return
			}
			list.Messages[0].ID, list.Messages[0].Size = id, protocol.MaxCiphertext
			fakeserver.WriteList(w, list)
		case r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages/"+id:
			n := &atomic.Int64{}
			mu.Lock()
			*served = append(*served, n)
			mu.Unlock()
			from, ok := protocol.RangeAsked(r.Header.Values("Range"), r.Header.Values("If-Range"))
			w.Header().Set("Content-Type", protocol.CiphertextContentType)
			if ok && from < int64(len(ct)) {
				w.Header().Set("Content-Length", strconv.Itoa(len(ct)-int(from)))
				w.Header().Set("Content-Range", protocol.ContentRange(from, int64(len(ct))))
				w.WriteHeader(http.StatusPartialContent)
			} else {
				from = 0
				w.Header().Set("Content-Length", strconv.Itoa(len(ct)))
				w.WriteHeader(http.StatusOK)
			}
			for i := int(from); i < len(ct); i += 64 << 10 {
				k, err := w.Write(ct[i:min(i+64<<10, len(ct))])
				n.Add(int64(k))
				if err != nil {
					return
				}
				w.(http.Flusher).Flush()
				if d := pause(); d > 0 {
					time.Sleep(d)
				}
			}
		default:
			next.ServeHTTP(w, r)
		}
	})
	return id
}

// A drain holds the box's lock for as long as it runs, and runs no longer
// than its time while bytes move (#2): a fetch of the largest ciphertext,
// trickled at about 1.25 MiB/s, holds the lock past a second command's
// patience, which then fails as locked having asked the server nothing; a
// reading started during it reads once the drain lets go; and the drain,
// cut at its time, stops as at its other limits, with More and no error,
// keeping what it read. The next recv finishes the fetch from there, asking
// only for the bytes the box did not keep. The bounds are the test's own,
// seconds, through the package's seams (SetLockPatience, Options.DrainTime).
func TestADrainHoldsTheLockForItsTimeAndTheNextGoesOnFromIt(t *testing.T) {
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	const patience, drainTime = 2 * time.Second, 6 * time.Second
	client.SetLockPatience(t, patience)
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "listed as the largest a ciphertext may be")
	var mu sync.Mutex
	var served []*atomic.Int64
	var slow atomic.Bool
	slow.Store(true)
	id := largest(t, e, b, func() time.Duration {
		if slow.Load() {
			return 50 * time.Millisecond
		}
		return 0
	}, &served, &mu)
	fetched := func() []int64 {
		mu.Lock()
		defer mu.Unlock()
		var ns []int64
		for _, n := range served {
			ns = append(ns, n.Load())
		}
		return ns
	}
	opt := e.opts()
	opt.DrainTime = drainTime
	x, err := client.Open(b.Dir(), opt)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		res *client.Result
		err error
		at  time.Time
	}
	done := make(chan outcome, 1)
	start := time.Now()
	go func() {
		res, err := x.Receive(context.Background())
		done <- outcome{res, err, time.Now()}
	}()
	for ns := fetched(); len(ns) == 0 || ns[0] == 0; ns = fetched() {
		if time.Since(start) > drainTime {
			t.Fatal("the fetch moved no byte")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A second command waits its patience, and fails as locked, having asked
	// the server nothing.
	y, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	calls := len(e.srv.Requests())
	began := time.Now()
	if _, err := y.Receive(context.Background()); err == nil || !strings.Contains(err.Error(), "held its lock") || time.Since(began) < patience {
		t.Fatalf("a second command during the drain: %v after %s", err, time.Since(began))
	}
	if got := len(e.srv.Requests()); got != calls {
		t.Fatalf("the second command asked the server %d calls while it waited", got-calls)
	}

	// A reading started during the drain reads, once the drain lets go.
	time.Sleep(time.Until(start.Add(drainTime - patience/2)))
	read := time.Now()
	st, err := y.Status(context.Background())
	if err != nil || st == nil {
		t.Fatalf("a reading during the drain: %v", err)
	}
	first := <-done
	if !read.Before(first.at) {
		t.Fatalf("the reading began at %s, after the drain ended at %s", read.Sub(start), first.at.Sub(start))
	}

	// Cut at its time: More, no error, nothing judged, the partial kept.
	if first.err != nil || !first.res.More || len(first.res.Refused)+len(first.res.Delivered) != 0 || first.at.Sub(start) > drainTime+5*time.Second {
		t.Fatalf("the drain at its time: %+v, %v, after %s", first.res, first.err, first.at.Sub(start))
	}
	got, kept, err := x.Partial()
	if err != nil || got != id || kept <= 0 || kept >= protocol.MaxCiphertext || kept > fetched()[0] {
		t.Fatalf("the drain kept %d bytes of %q, %v; the server served %d", kept, got, err, fetched()[0])
	}

	// The next recv finishes the fetch from what was kept: the server serves
	// the rest, and no byte the box kept.
	slow.Store(false)
	z, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	res := receive(t, z)
	if len(res.Refused) != 1 || res.Refused[0].ID != id || res.Refused[0].Code != client.RefusedDecrypt || res.More {
		t.Fatalf("the next recv: %+v", res)
	}
	if ns := fetched(); len(ns) != 2 || ns[1] != protocol.MaxCiphertext-kept {
		t.Fatalf("the fetches were served %v bytes, want the %d after the %d kept", ns, protocol.MaxCiphertext-kept, kept)
	}
	noPartial(t, z)
}

// At the drain's bound in time, a fault of the box itself at keeping what
// the cut fetch read (here its state's write of the record, as a full disk
// fails it) is the drain's error, never More with no error: the drain takes
// a cut at its time as the bound reached, and the fault comes back ahead of
// the cut's error, out of its reach (#403 item 2).
func TestAFaultKeepingThePartialAtTheDrainsTimeIsAnError(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, strings.Repeat("trickled until the drain's time cuts it. ", 3000))
	var armed, failed atomic.Bool
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, boxPath(b)+"/messages/") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		ct := rec.Body.Bytes()
		armed.Store(true) // the next write of the box's state fails, once
		for i := 0; i < len(ct); i += 4 << 10 {
			if _, err := w.Write(ct[i:min(i+4<<10, len(ct))]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})
	full := &os.PathError{Op: "write", Path: "state", Err: syscall.ENOSPC}
	client.SetWriteFault(t, func() error {
		if armed.Load() && failed.CompareAndSwap(false, true) {
			return full
		}
		return nil
	})
	opt := e.opts()
	opt.DrainTime = 500 * time.Millisecond
	x, err := client.Open(b.Dir(), opt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := x.Receive(context.Background())
	if !failed.Load() {
		t.Fatal("the fault never fired")
	}
	if !errors.Is(err, syscall.ENOSPC) || res != nil && res.More {
		t.Errorf("the box's own fault keeping the partial at the drain's time: More %v, error %v", res != nil && res.More, err)
	}
}
