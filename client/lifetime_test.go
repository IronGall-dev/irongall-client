package client_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box's prekeys are valid for 33 days, or for the shorter lifetime its
// owner sets, down to a day and an hour (PROTOCOL.md §6.4). Each client
// records when it signed a prekey, and the box times its renewals and its
// deletions by that record, never by the statement's not_after.

// lifetimeOf sets b's prekey lifetime.
func lifetimeOf(t *testing.T, b *client.Box, d time.Duration) {
	t.Helper()
	if err := b.SetPrekeyLifetime(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

// madeOf is what b's record says of when prekey n was signed.
func madeOf(t *testing.T, b *client.Box, n uint64) string {
	t.Helper()
	return string(statement(t, b, n, ".made"))
}

// A prekey is made for the box's lifetime, and its record says when: the
// default, the shortest and one between.
func TestAPrekeyIsMadeForTheBoxsLifetime(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	st, err := b.Status(t.Context())
	if err != nil || st.PrekeyLifetime != int64(protocol.PrekeyLifetime/time.Second) || st.PrekeyMade != e.clock.Now().Format(protocol.TimeLayout) {
		t.Fatalf("a new box's status: %+v, %v", st, err)
	}
	for _, d := range []time.Duration{client.MinPrekeyLifetime, 3 * 24 * time.Hour, protocol.PrekeyLifetime} {
		lifetimeOf(t, b, d)
		e.clock.Add(time.Second)
		p, err := b.Rekey(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		now := e.clock.Now()
		if !p.NotAfter.Equal(now.Add(d)) {
			t.Errorf("a lifetime of %v: the prekey ends at %v, %v after it was made", d, p.NotAfter, p.NotAfter.Sub(now))
		}
		if got := madeOf(t, b, p.Serial); got != now.Format(protocol.TimeLayout) {
			t.Errorf("a lifetime of %v: the record says %q", d, got)
		}
		st, err := b.Status(t.Context())
		if err != nil || st.PrekeyLifetime != int64(d/time.Second) || st.PrekeyMade != now.Format(protocol.TimeLayout) || strings.Contains(strings.Join(st.Attention, " "), "lifetime") {
			t.Errorf("a lifetime of %v: status %+v, %v", d, st, err)
		}
	}
}

// Receive renews a short-lived prekey once it is a day old, and not before:
// its age is its record's, where not_after less 33 days would make it a
// month old at once, and renew it at every receive. Senders reach the box
// throughout.
func TestAShortLivedPrekeyIsRenewedOnceADayOld(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	lifetimeOf(t, b, client.MinPrekeyLifetime)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	for age := 8 * time.Hour; age <= 24*time.Hour; age += 8 * time.Hour {
		e.clock.Add(8 * time.Hour)
		if res := receive(t, b); res.Renewed != nil {
			t.Fatalf("renewed a prekey %v old", age)
		}
	}
	e.clock.Add(time.Second)
	send(t, a, b, "an hour before the prekey runs out")
	res := receive(t, b)
	if res.Renewed == nil || len(res.Delivered) != 1 {
		t.Fatalf("no renewal of a day-old prekey with an hour left: %+v", res)
	}
	if !res.Renewed.NotAfter.Equal(e.clock.Now().Add(client.MinPrekeyLifetime)) {
		t.Fatalf("the renewal ends at %v", res.Renewed.NotAfter)
	}
	send(t, a, b, "to the renewed prekey")
	if res := receive(t, b); res.Renewed != nil || len(res.Delivered) != 1 {
		t.Fatalf("after the renewal: %+v", res)
	}
}

// A lifetime set lower holds from the next receive, which renews a prekey
// made for longer; one set higher waits for the day-old renewal.
func TestALowerLifetimeHoldsFromTheNextReceive(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	lifetimeOf(t, b, 2*24*time.Hour)
	res := receive(t, b)
	if res.Renewed == nil || !res.Renewed.NotAfter.Equal(e.clock.Now().Add(2*24*time.Hour)) {
		t.Fatalf("a lower lifetime, at the next receive: %+v", res.Renewed)
	}
	if res := receive(t, b); res.Renewed != nil {
		t.Fatal("renewed again at the receive after")
	}
	lifetimeOf(t, b, 10*24*time.Hour)
	if res := receive(t, b); res.Renewed != nil {
		t.Fatal("a higher lifetime renewed at once")
	}
}

// A prekey with no record of when it was made is renewed at the next
// receive, and while the newest retired prekey has none, every retired key
// is kept until its deletion time.
func TestAPrekeyWithNoRecordIsRenewedAndItsKeysKept(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	k1 := numberOf(t, b)
	e.clock.Add(25 * time.Hour)
	receive(t, b)
	k2 := numberOf(t, b)
	b.SetRecord(t, "prekeys/"+strconv.FormatUint(k2, 10)+".made", nil)
	st, err := b.Status(t.Context())
	if err != nil || st.PrekeyMade != "" {
		t.Fatalf("status with no record: %+v, %v", st, err)
	}
	e.clock.Add(time.Second)
	res := receive(t, b)
	if res.Renewed == nil {
		t.Fatal("a prekey with no record was not renewed")
	}
	e.clock.Add(2 * time.Hour)
	receive(t, b)
	if !exists(prekeyFile(b, k1, ".agekey")) || !exists(prekeyFile(b, k2, ".agekey")) {
		t.Fatal("a retired key was deleted while the newest retired one has no record")
	}
}

// A prekey-lifetime file that names no lifetime is never read as the
// default: no prekey is signed, a receive that is due to renew fails, and
// status says why. One that names one, with or without its line feed, is
// read.
func TestALifetimeOutOfFormIsNeverTheDefault(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{"", "\n", "abc\n", "0\n", "89999\n", "90000\n", "93599\n", "93600\n", "97199\n", "2851201\n", "090000\n", " 90000\n", "90000 \n", "90000\n\n", "90000\r\n", "9e4\n", "+90000\n", "1d1h\n", "99999999999\n"} {
		e := newEnv(t)
		b := e.box(protocol.Classic)
		n := numberOf(t, b)
		if err := os.WriteFile(filepath.Join(b.Dir(), "prekey-lifetime"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := b.PrekeyLifetime(); err == nil {
			t.Errorf("%q was read as a lifetime", raw)
		}
		if _, err := b.Rekey(ctx, ""); err == nil || numberOf(t, b) != n {
			t.Errorf("%q: a prekey was published: %v", raw, err)
		}
		e.clock.Add(25 * time.Hour)
		if res, err := b.Receive(ctx); err != nil || res.RenewErr == nil || !strings.Contains(res.RenewErr.Error(), "prekey-lifetime") || numberOf(t, b) != n {
			t.Errorf("%q: a receive due to renew: %+v, %v", raw, res, err)
		}
		if st, err := b.Status(t.Context()); err != nil || st.PrekeyLifetime != 0 || !strings.Contains(strings.Join(st.Attention, " "), "prekey lifetime cannot be read") {
			t.Errorf("%q: status %+v, %v", raw, st, err)
		}
	}
	for raw, want := range map[string]time.Duration{"97200": client.MinPrekeyLifetime, "97200\n": client.MinPrekeyLifetime, "2851200\n": protocol.PrekeyLifetime, "172800\n": 48 * time.Hour} {
		b := newEnv(t).box(protocol.Classic)
		if err := os.WriteFile(filepath.Join(b.Dir(), "prekey-lifetime"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := b.PrekeyLifetime(); err != nil || got != want {
			t.Errorf("%q: %v, %v", raw, got, err)
		}
	}
	b := newEnv(t).box(protocol.Classic)
	for _, d := range []time.Duration{0, client.MinPrekeyLifetime - time.Second, protocol.PrekeyLifetime + time.Second, client.MinPrekeyLifetime + time.Millisecond} {
		if err := b.SetPrekeyLifetime(ctx, d); err == nil {
			t.Errorf("a lifetime of %v was set", d)
		}
	}
	if exists(filepath.Join(b.Dir(), "prekey-lifetime")) {
		t.Fatal("a refused lifetime was written")
	}
}

// At the shortest lifetime, the two clocks furthest apart that a server
// takes, a box 9 minutes slow and a sender 49 fast (PROTOCOL.md §0), still
// meet: the box renews once its prekey is a day old, which leaves that
// sender an hour of it and two minutes.
func TestTheShortestLifetimeAtTheClocksFurthestApart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	slow, fast := -9*time.Minute, 49*time.Minute
	b, err := client.Init(ctx, t.TempDir(), e.skewed(&slow), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, b)
	a, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	lifetimeOf(t, b, client.MinPrekeyLifetime)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(24*time.Hour + time.Second)
	send(t, a, b, "with an hour and two minutes of the prekey left, by the sender's clock")
	if res := receive(t, b); res.Renewed == nil || len(res.Delivered) != 1 {
		t.Fatalf("the slow box's receive: %+v", res)
	}
	e.clock.Add(2 * time.Hour)
	send(t, a, b, "to the renewed prekey, after the first ran out")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("after the first prekey ran out: %+v", res)
	}
}

// PROTOCOL.md §6.4: "With a lifetime L, recv must run at least every L less
// a day and an hour". At that cadence the renewal comes with an hour of the
// prekey left by the box's clock, so a sender up to that hour fast, which a
// server takes (§0), is never refused: at the shortest lifetime and at one a
// little longer, with recv a minute short of the day the first time.
func TestTheDocumentedCadenceLeavesRoomForAClock(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		life      time.Duration
		box, from time.Duration // the box's clock and the sender's, from the server's
	}{
		{client.MinPrekeyLifetime, 0, 30 * time.Minute},
		{client.MinPrekeyLifetime, -9 * time.Minute, 49 * time.Minute},
		{3*24*time.Hour + time.Hour, 0, 30 * time.Minute},
	} {
		e := newEnv(t)
		boxOff, fromOff := c.box, c.from
		b, err := client.Init(ctx, t.TempDir(), e.skewed(&boxOff), protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		landAll(t, b)
		a, err := client.Init(ctx, t.TempDir(), e.skewed(&fromOff), protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		lifetimeOf(t, b, c.life)
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatal(err)
		}
		every := client.RecvWithin(c.life)
		e.clock.Add(24*time.Hour - time.Minute) // a recv a minute short of the day
		if res := receive(t, b); res.Renewed != nil {
			t.Fatal("renewed early")
		}
		e.clock.Add(every - time.Hour)
		refused := 0
		for m := 2; m <= 120; m += 2 {
			e.clock.Add(2 * time.Minute)
			if m == 60 {
				receive(t, b) // the next recv, every after the last
			}
			if _, err := a.Send(ctx, b.Address(), "a message every two minutes"); err != nil {
				refused++
			}
		}
		if refused > 0 {
			t.Errorf("lifetime %v, recv every %v, box %v and sender %v off: refused %d of 60 sends, two minutes apart", c.life, every, c.box, c.from, refused)
		}
	}
}

// A renewal the server never took waits, signed for 33 days, and the owner
// then sets the shortest lifetime. PROTOCOL.md §6.4: "A lifetime set lower
// holds from the next recv, which renews a prekey made for longer." The one
// that waited is spent, and a new key is made for the lifetime now set.
func TestALowerLifetimeHoldsOverAWaitingRenewal(t *testing.T) {
	for _, via := range []string{"recv", "prekey renew"} {
		t.Run(via, func(t *testing.T) {
			e := newEnv(t)
			b := e.box(protocol.Classic)
			e.clock.Add(25 * time.Hour)
			forge.FailOnce(e.srv, http.MethodPut, "/prekey") // the server is down: it never sees the upload
			if res := receive(t, b); res.RenewErr == nil {
				t.Fatal("the renewal did not fail")
			}
			lifetimeOf(t, b, client.MinPrekeyLifetime)
			e.clock.Add(time.Hour)
			var p *protocol.Prekey
			if via == "recv" {
				p = receive(t, b).Renewed
			} else {
				var err error
				if p, err = b.Rekey(context.Background(), ""); err != nil {
					t.Fatal(err)
				}
			}
			if p == nil {
				t.Fatal("no renewal")
			}
			made, err := protocol.ParseTime(strings.TrimSuffix(madeOf(t, b, p.Serial), "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if life := p.NotAfter.Sub(made); life > client.MinPrekeyLifetime {
				t.Errorf("%s published a prekey made for %v after the lifetime was set to %v", via, life, client.MinPrekeyLifetime)
			}
		})
	}
}
