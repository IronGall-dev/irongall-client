package client_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/protocol"
)

// servedSerial is the serial of the prekey the server serves for b.
func servedSerial(t *testing.T, e *env, b *client.Box) uint64 {
	t.Helper()
	st, _ := e.srv.Prekey(b.Address())
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		t.Fatal(err)
	}
	return p.Serial
}

// Receive renews the prekey once it is more than a day old, keeping its
// type, and not again until the new one is a day old: a box received at
// least monthly never lapses, and a busy one renews at most daily.
func TestReceiveRenewsADayOldPrekey(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	e.clock.Add(24 * time.Hour)
	if res := receive(t, b); res.Renewed != nil || servedSerial(t, e, b) != 1 {
		t.Fatal("renewed a prekey only a day old")
	}
	e.clock.Add(time.Second)
	res := receive(t, b)
	if res.Renewed == nil || res.Renewed.Serial != 2 || servedSerial(t, e, b) != 2 {
		t.Fatalf("no renewal of a prekey more than a day old: %+v", res)
	}
	if res.Renewed.Type() != protocol.Classic {
		t.Fatalf("the renewal changed the box's key type to %s", res.Renewed.Type())
	}
	if res := receive(t, b); res.Renewed != nil || servedSerial(t, e, b) != 2 {
		t.Fatal("renewed again at the next receive")
	}
}

// A renewal that fails does not stop the drain, says why, and is tried
// again an hour later, not at every poll.
func TestReceiveRetriesAFailedRenewalHourly(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	var puts atomic.Int32
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey") {
			puts.Add(1)
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(25 * time.Hour)
	send(t, a, b, "while the renewal fails")
	res := receive(t, b)
	if res.RenewErr == nil || len(res.Delivered) != 1 || puts.Load() != 1 {
		t.Fatalf("a failed renewal: %v, delivered %d, %d tries", res.RenewErr, len(res.Delivered), puts.Load())
	}
	e.clock.Add(time.Hour - time.Second)
	if res := receive(t, b); res.RenewErr != nil || puts.Load() != 1 {
		t.Fatalf("tried again within the hour: %d tries", puts.Load())
	}
	e.clock.Add(time.Second)
	if res := receive(t, b); res.RenewErr == nil || puts.Load() != 2 {
		t.Fatalf("not tried again after an hour: %d tries", puts.Load())
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); res.Renewed != nil {
		t.Fatal("tried again inside the hour after a failure")
	}
	e.clock.Add(time.Hour)
	if res := receive(t, b); res.Renewed == nil || servedSerial(t, e, b) != 2 {
		t.Fatal("not renewed once the server took it")
	}
}

// After a drain that emptied the box and began more than an hour after the
// last renewal, every retired prekey but the newest is deleted, key and
// statement. Mail encrypted to the newest retired one still decrypts.
func TestReceiveKeepsOnePriorPrekey(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	key := func(n int) string { return filepath.Join(b.Dir(), "prekeys", strconv.Itoa(n)) }
	send(t, a, b, "to key 1")
	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || len(res.Delivered) != 1 {
		t.Fatalf("day 1: renewed %v, delivered %d", res.Renewed, len(res.Delivered))
	}
	send(t, a, b, "to key 2")
	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || res.Renewed.Serial != 3 || len(res.Delivered) != 1 {
		t.Fatalf("day 2: renewed %v, delivered %d", res.Renewed, len(res.Delivered))
	}
	if !exists(key(1)+".agekey") || !exists(key(2)+".agekey") {
		t.Fatal("a drain that began before the renewal deleted a prekey")
	}
	e.clock.Add(time.Hour)
	receive(t, b)
	if !exists(key(1) + ".agekey") {
		t.Fatal("deleted an hour after the renewal, not more")
	}
	e.clock.Add(time.Second)
	failOnce(e, http.MethodGet, "/messages")
	if _, err := b.Receive(context.Background()); err == nil {
		t.Fatal("the failed drain succeeded")
	}
	if !exists(key(1) + ".agekey") {
		t.Fatal("a drain that did not empty the box deleted a prekey")
	}
	receive(t, b)
	for _, f := range []string{".agekey", ".txt", ".txt.sig"} {
		if exists(key(1) + f) {
			t.Fatalf("prekey 1's %s was kept", f)
		}
	}
	if !exists(key(2)+".agekey") || !exists(key(3)+".agekey") {
		t.Fatal("deleted the newest retired prekey or the current one")
	}
}
