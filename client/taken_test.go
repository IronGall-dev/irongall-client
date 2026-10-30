package client_test

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// jumpAtRenewal moves a mailbox's clock by `by` once its server has answered
// the renewal's PUT …/prekey: the server took the renewal at the reading
// before the jump.
type jumpAtRenewal struct {
	off *time.Duration
	by  time.Duration
}

func (j jumpAtRenewal) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey") {
		*j.off = j.by
	}
	return resp, err
}

// The renewal's twin of TestAClockThatJumpsDuringADrainDeletesNoKey (#209):
// a clock that jumps 70 days ahead after the server took the renewal deletes
// no prekey, since keys are deleted by the reading the server took
// (AGENTS.md, decided on #200; PROTOCOL.md §12.4). The message waiting for the
// retired key is delivered once the clock is right.
func TestAClockThatJumpsDuringARenewalDeletesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "first, sealed to the prekey about to retire")
	send(t, a, b, "second, sealed to it too")
	e.clock.Add(2 * time.Second)
	keys, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	var off time.Duration
	o := e.skewed(&off)
	o.HTTPClient = &http.Client{Transport: jumpAtRenewal{&off, 70 * 24 * time.Hour}}
	jumpy, err := client.Open(b.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := jumpy.Rekey(ctx)
	after, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	t.Logf("renewal: %v; prekey keys %d before, %d after (the new one among them)", rerr, len(keys), len(after))
	right, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	res, err := right.Receive(ctx)
	if res == nil {
		res = &client.Result{}
	}
	t.Logf("once the clock is right: delivered %d, refused %d, %v", len(res.Delivered), len(res.Refused), err)
	for _, r := range res.Refused {
		t.Logf("  refused: %s %s", r.Code, r.Reason)
	}
	if len(after) < len(keys)+1 || len(res.Delivered) != 2 {
		t.Errorf("a clock that jumped after the server took the renewal deleted the key the waiting message needs")
	}
}

// The same through the remedy (cert revoke-earlier), whose renewal is taken
// before the jump. The two messages were sealed to the prekey it retires and
// signed under the sender's certificate, which the remedy does not revoke.
func TestAClockThatJumpsDuringTheRemedyDeletesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "first, sealed to the prekey about to retire")
	send(t, a, b, "second, sealed to it too")
	e.clock.Add(2 * time.Second)
	keys, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	var off time.Duration
	o := e.skewed(&off)
	o.HTTPClient = &http.Client{Transport: jumpAtRenewal{&off, 70 * 24 * time.Hour}}
	jumpy, err := client.Open(b.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	r, rerr := jumpy.RenewAndRevoke(ctx)
	after, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	t.Logf("remedy: %+v, %v; prekey keys %d before, %d after (the new one among them)", r, rerr, len(keys), len(after))
	right, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	res, err := right.Receive(ctx)
	if res == nil {
		res = &client.Result{}
	}
	t.Logf("once the clock is right: delivered %d, refused %d, %v", len(res.Delivered), len(res.Refused), err)
	if len(after) < len(keys)+1 || len(res.Delivered) != 2 {
		t.Errorf("a clock that jumped after the server took the remedy's renewal deleted the key the waiting message needs")
	}
}

// rightAtFirstCall sets a mailbox's clock right (off = 0) as its first request
// goes out: a clock that read ahead when the command began and was stepped
// back before anything was signed or sent.
type rightAtFirstCall struct{ off *time.Duration }

func (j rightAtFirstCall) RoundTrip(r *http.Request) (*http.Response, error) {
	*j.off = 0
	return http.DefaultTransport.RoundTrip(r)
}

// A renewal whose mailbox's clock reads 70 days ahead when the command begins and
// is right before its first request: every pass the server takes is dated by
// the right clock, so no key a message waits for is deleted, and the message sealed to
// the retired prekey is delivered.
func TestAClockSteppedBackBeforeARenewalDeletesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "first, sealed to the prekey about to retire")
	send(t, a, b, "second, sealed to it too")
	e.clock.Add(2 * time.Second)
	keys, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	off := 70 * 24 * time.Hour
	o := e.skewed(&off)
	o.HTTPClient = &http.Client{Transport: rightAtFirstCall{&off}}
	stepped, err := client.Open(b.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := stepped.Rekey(ctx)
	after, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	t.Logf("renewal: %v; prekey keys %d before, %d after (the new one among them)", rerr, len(keys), len(after))
	right, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	res, err := right.Receive(ctx)
	if res == nil {
		res = &client.Result{}
	}
	t.Logf("then: delivered %d, refused %d, %v", len(res.Delivered), len(res.Refused), err)
	for _, r := range res.Refused {
		t.Logf("  refused: %s %s", r.Code, r.Reason)
	}
	if rerr != nil || len(after) < len(keys)+1 || len(res.Delivered) != 2 {
		t.Errorf("a clock stepped back before the renewal's first request deleted the key the waiting message needs")
	}
}

// A drain that empties the mailbox deletes the older retired prekeys by its
// clock only as it read when the server answered the drain's list, never by
// a later reading (PROTOCOL.md §12.4). Here Receive's
// first reading is 2 hours ahead and the clock is right again before the
// list: the key that the list's reading keeps must be kept.
func TestDropRetiredDeletesByNoReadingLaterThanTheLists(t *testing.T) {
	t.Parallel()
	for _, ahead := range []time.Duration{0, 2 * time.Hour} {
		ctx := context.Background()
		e := newEnv(t)
		var first atomic.Bool
		o := e.opts()
		o.Now = func() time.Time {
			if first.CompareAndSwap(true, false) {
				return e.clock.Now().Add(ahead)
			}
			return e.clock.Now()
		}
		b, err := client.Init(ctx, t.TempDir(), o)
		if err != nil {
			t.Fatal(err)
		}
		k1 := numberOf(t, b)
		for range 2 {
			e.clock.Add(2 * time.Second)
			if _, err := b.Rekey(ctx); err != nil {
				t.Fatal(err)
			}
		}
		e.clock.Add(5 * time.Minute)
		first.Store(true) // the next reading is Receive's first
		if _, err := b.Receive(ctx); err != nil {
			t.Fatal(err)
		}
		kept := exists(prekeyFile(b, k1, ".agekey"))
		t.Logf("Receive's first reading %v ahead, then right: the oldest retired key, retired 5 minutes before, kept: %v", ahead, kept)
		if !kept {
			t.Errorf("Receive's first reading %v ahead deleted a key retired 5 minutes before, which the list's reading keeps", ahead)
		}
	}
}

// RecvWithin's cadence leaves the prekey exactly MaxSkew by the mailbox's clock
// when recv begins, and recv's renewal reads the mailbox's own mailbox before it
// publishes. A mailbox 9m59s slow and a sender 50m fast, the two clocks furthest
// apart a server takes: recv runs exactly a day after the prekey was made
// (renewDue renews once it is more than a day old), then exactly RecvWithin
// later. The sender sends every second from 3 seconds before the second recv
// to 3 seconds after it, and once while the renewal's read is answered.
func TestARenewalAtRecvWithinWhoseReadTakesSeconds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := time.Hour
	slow, fast := -(10*time.Minute - time.Second), 50*time.Minute
	for _, c := range []struct {
		name          string
		mailbox, from time.Duration
		delay         time.Duration // how long the renewal's read of the mailbox's own mailbox takes
	}{
		{"the shortest lifetime, the read takes 5s", slow, fast, 5 * time.Second},
		{"control: the shortest lifetime, the read takes no time", slow, fast, 0},
		{"control: the shortest lifetime, the read takes 5s, the mailbox right and the sender 30m fast", 0, 30 * time.Minute, 5 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			mailboxOff, fromOff := c.mailbox, c.from
			b, err := client.Init(ctx, t.TempDir(), e.skewed(&mailboxOff))
			if err != nil {
				t.Fatal(err)
			}
			landAll(t, b)
			a, err := client.Init(ctx, t.TempDir(), e.skewed(&fromOff))
			if err != nil {
				t.Fatal(err)
			}
			lifetimeOf(t, b, client.MinPrekeyLifetime)
			p, err := b.Rekey(ctx)
			if err != nil {
				t.Fatal(err)
			}
			made, _ := protocol.ParseTime(strings.TrimSpace(madeOf(t, b, p.Serial)))
			e.clock.Add(made.Add(24 * h).Sub(e.clock.Now().Add(mailboxOff))) // the mailbox's clock reads made + 24h
			if res := receive(t, b); res.Renewed != nil {
				t.Fatal("renewed at exactly a day old")
			}
			var refused, sends atomic.Int32
			sendOne := func() {
				sends.Add(1)
				if _, err := a.Send(ctx, b.Address(), "a message"); err != nil {
					refused.Add(1)
				}
			}
			own := "/v1/" + b.Address().String()
			var armed atomic.Bool
			e.srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				if c.delay > 0 && q.Method == http.MethodGet && q.URL.Path == own && armed.CompareAndSwap(true, false) {
					e.clock.Add(c.delay)
					sendOne() // a send while the renewal is under way
				}
				next.ServeHTTP(w, q)
			})
			e.clock.Add(client.RecvWithin(client.MinPrekeyLifetime) - 3*time.Second)
			if _, err := a.Receive(ctx); err != nil { // the sender renews, so its certificate signs messages
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				sendOne()
				e.clock.Add(time.Second)
			}
			armed.Store(true)
			res := receive(t, b) // at exactly made + 24h + RecvWithin by the mailbox's clock
			for i := 0; i < 3; i++ {
				e.clock.Add(time.Second)
				sendOne()
			}
			t.Logf("mailbox %v, sender %v, the read %v: renewed %v, %d of %d sends refused", c.mailbox, c.from, c.delay, res.Renewed != nil, refused.Load(), sends.Load())
			if refused.Load() > 0 {
				t.Error("a sender whose clock a server takes was refused at RecvWithin's cadence")
			}
		})
	}
}

// jumpAtList moves a mailbox's clock by `by` once its server has answered a
// drain's list: the server took the list at the reading before the jump.
type jumpAtList struct {
	off *time.Duration
	by  time.Duration
}

func (j jumpAtList) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
		*j.off = j.by
	}
	return resp, err
}

// The replay set is pruned by the date of the pass the drain's list carried,
// which the server took (PROTOCOL.md §12.4): a clock that jumps 70 days
// once the list is answered drops no line and raises no floor, so the messages
// it would have let go stay known.
func TestAClockThatJumpsDuringADrainPrunesNoLine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	send(t, a, b, "delivered once")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	before, _ := stateOf(b, "seen")
	var off time.Duration
	o := e.skewed(&off)
	o.HTTPClient = &http.Client{Transport: jumpAtList{&off, 70 * 24 * time.Hour}}
	jumpy, err := client.Open(b.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := jumpy.Receive(ctx)
	after, _ := stateOf(b, "seen")
	t.Logf("the drain whose clock jumped once its list was answered: %v", rerr)
	if !bytes.Equal(before, after) || has(b, "seen-floor") {
		t.Errorf("a clock that jumped after the server took the list pruned the replay set by where it went: %q, then %q", before, after)
	}
}
