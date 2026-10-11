package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
// newest retired prekey was made (so every older one had been retired for an
// hour), every retired prekey but the newest is deleted, key and statement.
// Mail encrypted to the newest retired one still decrypts.
func TestReceiveKeepsOnePriorPrekey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	key := func(n int) string { return filepath.Join(b.Dir(), "prekeys", strconv.Itoa(n)) }
	send(t, a, b, "to key 1")
	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || len(res.Delivered) != 1 {
		t.Fatalf("renewed %v, delivered %d", res.Renewed, len(res.Delivered))
	}
	send(t, a, b, "to key 2")
	if _, err := b.Rekey(ctx, ""); err != nil { // retires key 2 at once
		t.Fatal(err)
	}
	e.clock.Add(time.Hour)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("mail to the newest retired prekey was not delivered")
	}
	if !exists(key(1) + ".agekey") {
		t.Fatal("deleted an hour after the newest retired prekey was made, not more")
	}
	e.clock.Add(time.Second)
	failOnce(e, http.MethodGet, "/messages")
	if _, err := b.Receive(ctx); err == nil {
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

// A box received monthly deletes its older prekeys at the check-in that
// renews: a key is gone by the second renewal after it was retired.
func TestMonthlyBoxDeletesAtTheRenewingCheckIn(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	key1 := filepath.Join(b.Dir(), "prekeys", "1.agekey")
	for range 2 {
		e.clock.Add(30 * 24 * time.Hour)
		if res := receive(t, b); res.Renewed == nil {
			t.Fatal("a monthly check-in did not renew")
		}
	}
	if exists(key1) {
		t.Fatal("key 1 outlived the second renewal after it was retired")
	}
	if !exists(filepath.Join(b.Dir(), "prekeys", "2.agekey")) {
		t.Fatal("the newest retired prekey was deleted")
	}
}

// uploads fails every prekey upload for a box from now on, as a server that
// is down would, and returns what it was sent: a server may keep that.
func uploads(e *env, b *client.Box) *[]protocol.PrekeyRequest {
	var kept []protocol.PrekeyRequest
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, b.Address().String()+"/prekey") {
			body, _ := io.ReadAll(r.Body)
			var req protocol.PrekeyRequest
			if err := json.Unmarshal(body, &req); err != nil {
				e.t.Errorf("a prekey upload: %v", err)
			}
			kept = append(kept, req)
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	return &kept
}

// A renewal the server did not take is sent again exactly as it was signed,
// never signed again: the same key with a later not_after would be a second
// lease on it. When the server takes it, those bytes are what it publishes.
func TestAFailedRenewalIsSentAgainUnchanged(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	kept := uploads(e, b)
	e.clock.Add(25 * time.Hour)
	for range 5 {
		if res := receive(t, b); res.RenewErr == nil {
			t.Fatal("the renewal did not fail")
		}
		e.clock.Add(time.Hour)
	}
	if len(*kept) != 5 {
		t.Fatalf("%d uploads, not one for each hour", len(*kept))
	}
	for i, k := range *kept {
		if !bytes.Equal(k.Prekey, (*kept)[0].Prekey) || !bytes.Equal(k.PrekeySignature, (*kept)[0].PrekeySignature) {
			t.Fatalf("upload %d differs from the first:\n%s\n%s", i, k.Prekey, (*kept)[0].Prekey)
		}
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); res.Renewed == nil || res.Renewed.Serial != 2 {
		t.Fatalf("not renewed once the server took it: %+v", res.Renewed)
	}
	if st, sig := e.srv.Prekey(b.Address()); !bytes.Equal(st, (*kept)[0].Prekey) || !bytes.Equal(sig, (*kept)[0].PrekeySignature) {
		t.Fatal("what the server published is not what the first attempt signed")
	}
}

// A server that fails every renewal, and keeps what it is sent, gets each key
// in ONE statement: so no key can be encrypted to for more than 33 days after
// it was signed, whatever the server does. When a statement it holds expires,
// the box signs a new key at the next serial, and deletes a passed-over key
// 33 days after its not_after, as it does any retired one.
func TestAServerThatFailsEveryRenewalGetsEachKeyOnce(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	kept := uploads(e, b)
	type lease struct {
		signed time.Time
		p      *protocol.Prekey
		st     protocol.PrekeyRequest
	}
	byKey := map[string]lease{}
	var order []string
	seen := 0
	for day := 1; day <= 75; day++ {
		e.clock.Add(24 * time.Hour)
		receive(t, b)
		for ; seen < len(*kept); seen++ {
			k := (*kept)[seen]
			p, err := protocol.VerifyPrekey(b.Identity(), k.Prekey, k.PrekeySignature)
			if err != nil {
				t.Fatalf("day %d: an upload does not verify: %v", day, err)
			}
			have, ok := byKey[p.Key]
			switch {
			case !ok:
				byKey[p.Key] = lease{e.clock.Now(), p, k}
				order = append(order, p.Key)
			case !bytes.Equal(have.st.Prekey, k.Prekey):
				t.Fatalf("day %d: the key signed on %s was signed again, now to %s", day, have.signed.Format(time.DateOnly), p.NotAfter.Format(time.DateOnly))
			}
		}
	}
	if seen < 70 || len(order) != 3 {
		t.Fatalf("%d uploads in 75 days, for %d keys: want one a day, for a new key every 33 days", seen, len(order))
	}
	serials := map[uint64]bool{}
	for _, key := range order {
		l := byKey[key]
		if life := l.p.NotAfter.Sub(l.signed); life > protocol.MaxPrekeyLifetime {
			t.Errorf("serial %d could be encrypted to for %s after it was signed", l.p.Serial, life)
		}
		serials[l.p.Serial] = true
	}
	if len(serials) != 3 {
		t.Errorf("three keys at %d serials: a serial is signed once", len(serials))
	}
	// The first key's only statement has expired: a server that serves it
	// is refused by a sender.
	first := byKey[order[0]]
	doc, _ := os.ReadFile(filepath.Join(b.Dir(), "identity.doc"))
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, b.Address().String()+"/identity") {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: doc, Prekey: first.st.Prekey, PrekeySignature: first.st.PrekeySignature})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := a.Resolve(context.Background(), b.Address()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("a sender given the first key's statement on day 75: %v", err)
	}
	// Signed on day 2, expired on day 35, deleted on day 68: with its
	// statement. The key in service and the one before it are held.
	stem := func(l lease) string { return filepath.Join(b.Dir(), "prekeys", strconv.FormatUint(l.p.Serial, 10)) }
	if exists(stem(first)+".agekey") || exists(stem(first)+".txt.sig") {
		t.Error("a passed-over key outlived its not_after + 33 days")
	}
	for _, key := range order[1:] {
		if !exists(stem(byKey[key]) + ".agekey") {
			t.Errorf("serial %d's key is gone while mail to it may still wait", byKey[key].p.Serial)
		}
	}
}

// A key an attempt made and never signed went nowhere: the next attempt uses
// it, at the same serial.
func TestAKeyNeverSignedIsUsed(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	failOnce(e, http.MethodPut, "/prekey")
	if _, err := b.Rekey(context.Background(), ""); err == nil {
		t.Fatal("the rekey should have failed")
	}
	stem := filepath.Join(b.Dir(), "prekeys", "2")
	key, _ := os.ReadFile(stem + ".agekey")
	for _, signed := range []string{".txt", ".txt.sig"} { // as a crash before the signature would leave it
		if err := os.Remove(stem + signed); err != nil {
			t.Fatal(err)
		}
	}
	p, err := b.Rekey(context.Background(), "")
	if err != nil || p.Serial != 2 {
		t.Fatalf("rekey: %+v, %v", p, err)
	}
	if now, _ := os.ReadFile(stem + ".agekey"); len(key) == 0 || !bytes.Equal(now, key) || !strings.Contains(string(key), p.Key) {
		t.Fatal("the key that was never signed was not the one published")
	}
}
