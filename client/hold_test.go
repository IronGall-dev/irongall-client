package client_test

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// held runs b.Hold for up to wait in a goroutine and returns what it came
// to on the channel.
func held(b *client.Box, wait time.Duration) <-chan *client.HoldResult {
	c := make(chan *client.HoldResult, 1)
	go func() {
		h, err := b.Hold(context.Background(), wait)
		if err != nil {
			h = nil
		}
		c <- h
	}()
	return c
}

func TestAHeldListIsAnsweredWhenMailArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newMemEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		receive(t, b) // an empty box: its tag kept
		c := held(b, time.Hour)
		time.Sleep(time.Minute)
		synctest.Wait()
		select {
		case <-c:
			t.Fatal("the hold ended with nothing sent")
		default:
		}
		send(t, a, b, "while the list was held")
		h := <-c
		if h == nil || !h.Changed || h.After != time.Minute {
			t.Fatalf("the hold came to %+v, want changed after a minute", h)
		}
		if res := receive(t, b); len(res.Delivered) != 1 {
			t.Fatalf("the receive after it delivered %d, want 1", len(res.Delivered))
		}
	})
}

func TestAHeldListWithNothingNewEndsAtTheBoxsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newMemEnv(t)
		b := e.box(protocol.Classic)
		receive(t, b)
		h := <-held(b, time.Hour)
		if h == nil || h.Changed || h.Dropped || h.After != client.DefaultHold {
			t.Fatalf("the hold came to %+v, want unchanged at %v", h, client.DefaultHold)
		}
		// A shorter wait asked is the one held.
		if h := <-held(b, 2*time.Minute); h == nil || h.Changed || h.After != 2*time.Minute {
			t.Fatalf("a 2-minute hold came to %+v", h)
		}
	})
}

func TestAHoldLetsTheBoxsOtherCommandsGoOn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newMemEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		receive(t, b)
		c := held(b, time.Hour)
		time.Sleep(time.Second)
		start := time.Now()
		send(t, b, a, "sent while the box's own list is held")
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("the send waited %v for the hold", waited)
		}
		h := <-c
		if h == nil || h.Changed {
			t.Fatalf("the hold came to %+v, want unchanged: a send changes the recipient's list, not the sender's", h)
		}
	})
}

// A held list answered 410 with the box's own revocation is proved as any
// call's answer is: the box keeps the revocation, and Hold returns it.
func TestAHeldListShownTheBoxsOwnRevocationKeepsIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		e := newMemEnv(t)
		b := e.box(protocol.Classic)
		receive(t, b)
		rec, err := b.Revocation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Query().Has("wait") {
				putRecord(t, next, b.Address(), rec)
				forge.Refuse(w, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = rec })
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := b.Hold(ctx, time.Hour); !finishedOwn(err) {
			t.Fatalf("the hold: %v, want the box's own revocation", err)
		}
		if s, err := b.Status(ctx); err != nil || !s.Revoked {
			t.Fatalf("the box after the hold: %+v, %v; want its revocation kept", s, err)
		}
	})
}

func TestADroppedHoldKeepsAliveThenShortensItsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newMemEnv(t)
		b := e.box(protocol.Classic)
		receive(t, b)
		drop := 2 * time.Minute
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Query().Has("wait") {
				time.Sleep(drop)
				panic(http.ErrAbortHandler) // the connection drops, unanswered
			}
			next.ServeHTTP(w, r)
		})
		below := drop - 15*time.Second
		// The first drop keeps the wait and turns keep-alive on below it.
		h := <-held(b, time.Hour)
		if h == nil || !h.Dropped || h.After != drop || h.Wait != client.DefaultHold || h.KeepAlive != below {
			t.Fatalf("the first drop came to %+v, want the wait kept and keep-alive at %v", h, below)
		}
		// One that drops with keep-alive on shortens the wait below it.
		h = <-held(b, time.Hour)
		if h == nil || !h.Dropped || h.Wait != below || h.KeepAlive != below {
			t.Fatalf("the second drop came to %+v, want the wait at %v", h, below)
		}
		// A drop sooner than its keep-alive lowers the keep-alive first, never
		// under half a minute, and only then the wait, never under a minute.
		drop = 40 * time.Second
		h = <-held(b, time.Hour)
		if h == nil || !h.Dropped || h.Wait != below || h.KeepAlive != client.MinHold/2 {
			t.Fatalf("a drop at 40 s came to %+v, want keep-alive at %v and the wait kept", h, client.MinHold/2)
		}
		h = <-held(b, time.Hour)
		if h == nil || !h.Dropped || h.Wait != client.MinHold {
			t.Fatalf("a second drop at 40 s came to %+v, want the wait at %v", h, client.MinHold)
		}
	})
}

func TestHoldsStartAtMostOnceAMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newMemEnv(t)
		b := e.box(protocol.Classic) // never received: no tag kept, so each hold ends at once
		start := time.Now()
		var at []time.Duration
		for range 4 {
			h := <-held(b, time.Hour)
			if h == nil || !h.Changed {
				t.Fatalf("a hold with no tag kept came to %+v, want changed", h)
			}
			at = append(at, time.Since(start))
		}
		want := []time.Duration{0, 0, time.Minute, 2 * time.Minute}
		for i := range want {
			if at[i] != want[i] {
				t.Fatalf("holds started at %v, want %v", at, want)
			}
		}
	})
}
