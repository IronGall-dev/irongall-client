package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/internal/forge"
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
	first := numberOf(t, b)
	e.clock.Add(24 * time.Hour)
	if res := receive(t, b); res.Renewed != nil || servedSerial(t, e, b) != first {
		t.Fatal("renewed a prekey only a day old")
	}
	e.clock.Add(time.Second)
	res := receive(t, b)
	if res.Renewed == nil || res.Renewed.Serial <= first || servedSerial(t, e, b) != res.Renewed.Serial {
		t.Fatalf("no renewal of a prekey more than a day old: %+v", res)
	}
	// The new number is the box's clock, in seconds.
	if now := e.clock.Now().Unix(); now < 0 || res.Renewed.Serial != uint64(now) {
		t.Fatalf("the renewal's number is %d, and the box's clock reads %d", res.Renewed.Serial, now)
	}
	if res.Renewed.Type() != protocol.Classic {
		t.Fatalf("the renewal changed the box's key type to %s", res.Renewed.Type())
	}
	if again := receive(t, b); again.Renewed != nil || servedSerial(t, e, b) != res.Renewed.Serial {
		t.Fatal("renewed again at the next receive")
	}
}

// A box its server forgot, once its record's expiry passed (PROTOCOL.md §7),
// comes back at its next receive: with no box served to number above, the
// renewal is numbered above what the box published, and goes as a
// registration. Mail reaches it again.
func TestAForgottenBoxRegistersAnewAtItsRenewal(t *testing.T) {
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	if _, err := b.Block(context.Background(), c.Address()); err != nil || e.srv.ACL(b.Address()) == nil {
		t.Fatalf("the block before the box was forgotten: %v", err)
	}
	first := numberOf(t, b)
	e.srv.Forget(b.Address())
	e.clock.Add(24*time.Hour + time.Second)
	res := receive(t, b)
	if res.Renewed == nil || res.Renewed.Serial <= first || servedSerial(t, e, b) != res.Renewed.Serial {
		t.Fatalf("a box its server forgot did not register anew at its renewal: %+v", res)
	}
	if res.Renewed.Type() != protocol.Classic {
		t.Fatalf("the registration changed the box's key type to %s", res.Renewed.Type())
	}
	send(t, a, b, "to a box registered anew")
	if got := receive(t, b); len(got.Delivered) != 1 {
		t.Fatalf("mail to a box registered anew: %+v", got)
	}
	// The server lost the box's ACL with the box, and the box sends it again.
	if acl := e.srv.ACL(b.Address()); acl == nil || !slices.Contains(acl.Deny.Addrs, c.Address()) {
		t.Fatalf("a box registered anew did not send its ACL again: %+v", acl)
	}
}

// A box restored from its identity alone (README: "put it alone in an empty
// box directory and run irongall prekey renew") at a server that forgot it:
// nothing is served to take a key type from and nothing was published, so it
// registers with init's default, post-quantum. The same in the remedy, on a
// restored box whose server does not answer its read. Control: the restore
// at a server that still serves the box.
func TestARestoredBoxRegistersWhereItsServerForgotIt(t *testing.T) {
	ctx := context.Background()
	for _, forgotten := range []bool{false, true} {
		e := newEnv(t)
		a := e.box(protocol.PostQuantum)
		if forgotten {
			e.srv.Forget(a.Address())
		}
		r := restoreWith(t, e, a, e.clock.Now)
		e.clock.Add(time.Minute)
		p, err := r.Rekey(ctx, "")
		if err != nil {
			t.Errorf("forgotten %v: prekey renew of a box restored from its identity alone: %v", forgotten, err)
			continue
		}
		if p.Type() != protocol.PostQuantum || servedSerial(t, e, r) != p.Serial {
			t.Errorf("forgotten %v: the restored box published a %s prekey at %d, and its server serves %d", forgotten, p.Type(), p.Serial, servedSerial(t, e, r))
		}
	}
	e := newEnv(t)
	a := e.box(protocol.PostQuantum)
	r := restoreWith(t, e, a, e.clock.Now)
	e.clock.Add(time.Minute)
	watch(e, func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method == http.MethodGet && req.URL.Path == boxPath(a) {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	if rm, err := r.RenewAndRevoke(ctx, ""); err != nil || rm == nil || rm.Unread == nil || rm.Prekey == nil || rm.Prekey.Type() != protocol.PostQuantum {
		t.Errorf("the remedy on a restored box whose server does not answer its read: %+v, %v", rm, err)
	}
}

// A renewal that fails does not stop the drain, says why, and is tried
// again an hour later, not at every poll: by any process of the box, which
// says within the hour why the last one failed (#10).
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
	if res := receive(t, b); res.RenewErr == nil || !strings.Contains(res.RenewErr.Error(), "tries it again from") || puts.Load() != 1 {
		t.Fatalf("within the hour: %v, %d tries; want the last failure said, and no try", res.RenewErr, puts.Load())
	}
	other, err := client.Open(b.Dir(), e.opts()) // another process of the box
	if err != nil {
		t.Fatal(err)
	}
	if res := receive(t, other); res.RenewErr == nil || puts.Load() != 1 {
		t.Fatalf("another process within the hour: %v, %d tries", res.RenewErr, puts.Load())
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
	if res := receive(t, b); res.Renewed == nil || servedSerial(t, e, b) != res.Renewed.Serial || has(b, "renew-failed") {
		t.Fatal("not renewed once the server took it, or the failure still kept")
	}
}

// A renewal that failed while the clock read ahead holds back no later one
// once the clock has gone back (#201): it is dated after the clock's reading,
// and a box whose clock steps back would otherwise renew nothing until the
// clock caught up, as its prekey ran out.
func TestAFailureDatedAheadHoldsBackNoRenewal(t *testing.T) {
	e := newEnv(t)
	var off time.Duration
	b, err := client.Init(context.Background(), t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
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
	off = 50 * time.Minute
	if res := receive(t, b); res.RenewErr == nil || puts.Load() != 1 {
		t.Fatalf("a renewal with the clock ahead: %v, %d tries", res.RenewErr, puts.Load())
	}
	e.srv.SetMiddle(nil)
	off = 0
	if res := receive(t, b); res.Renewed == nil {
		t.Fatalf("the clock set back: not renewed, %v", res.RenewErr)
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
	key := func(n uint64) string { return prekeyFile(b, n, "") }
	k1 := numberOf(t, b)
	send(t, a, b, "to the first key")
	e.clock.Add(25 * time.Hour)
	if res := receive(t, b); res.Renewed == nil || len(res.Delivered) != 1 {
		t.Fatalf("renewed %v, delivered %d", res.Renewed, len(res.Delivered))
	}
	k2 := numberOf(t, b)
	send(t, a, b, "to the second key")
	if _, err := b.Rekey(ctx, ""); err != nil { // retires the second key at once
		t.Fatal(err)
	}
	k3 := numberOf(t, b)
	e.clock.Add(time.Hour)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("mail to the newest retired prekey was not delivered")
	}
	if !exists(key(k1) + ".agekey") {
		t.Fatal("deleted an hour after the newest retired prekey was made, not more")
	}
	// Deleted by the date of the pass the list carried: the kept pass is
	// used until its last seconds, so the next is dated a pass's life on.
	e.clock.Add(protocol.PassLifetime)
	forge.FailOnce(e.srv, http.MethodGet, "/messages")
	if _, err := b.Receive(ctx); err == nil {
		t.Fatal("the failed drain succeeded")
	}
	if !exists(key(k1) + ".agekey") {
		t.Fatal("a drain that did not empty the box deleted a prekey")
	}
	receive(t, b)
	if exists(key(k1)+".agekey") || has(b, "prekeys/"+strconv.FormatUint(k1, 10)+".txt") {
		t.Fatal("the first prekey's key or statement was kept")
	}
	if !exists(key(k2)+".agekey") || !exists(key(k3)+".agekey") {
		t.Fatal("deleted the newest retired prekey or the current one")
	}
}

// A box received monthly deletes its older prekeys at the check-in that
// renews: a key is gone by the second renewal after it was retired.
func TestMonthlyBoxDeletesAtTheRenewingCheckIn(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	key1 := prekeyFile(b, numberOf(t, b), ".agekey")
	var second uint64
	for i := range 2 {
		e.clock.Add(30 * 24 * time.Hour)
		if res := receive(t, b); res.Renewed == nil {
			t.Fatal("a monthly check-in did not renew")
		}
		if i == 0 {
			second = numberOf(t, b)
		}
	}
	if exists(key1) {
		t.Fatal("key 1 outlived the second renewal after it was retired")
	}
	if !exists(prekeyFile(b, second, ".agekey")) {
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
	if res := receive(t, b); res.Renewed == nil || res.Renewed.Serial != begunAt(t, b) {
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
		// The certificate the server holds this box to was made on day 0
		// and lasts 65 days. Once it has ended the box can sign no pass the
		// server takes, so it cannot poll: it still offers a new prekey,
		// under a new certificate, each day.
		if _, err := b.Receive(context.Background()); (err != nil) != (day >= 65) {
			t.Fatalf("day %d: receive: %v", day, err)
		}
		for ; seen < len(*kept); seen++ {
			k := (*kept)[seen]
			p, _, err := protocol.VerifyPrekey(b.Identity(), k.Prekey, k.PrekeySignature, e.clock.Now())
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
		if life := l.p.NotAfter.Sub(l.signed); life > protocol.PrekeyLifetime {
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
		if r.Method == http.MethodGet && r.URL.Path == "/v1/"+b.Address().String() {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: doc, Prekey: first.st.Prekey, PrekeySignature: first.st.PrekeySignature})
			return
		}
		next.ServeHTTP(w, r)
	})
	// Its certificate, made the same day, has ended too, and that is what a
	// sender meets first.
	if _, err := a.Resolve(context.Background(), b.Address()); err == nil || !strings.Contains(err.Error(), "has ended") {
		t.Fatalf("a sender given the first key's statement on day 75: %v", err)
	}
	// Signed on day 2, expired on day 35, its deletion time day 68. No
	// server has taken a pass from the box since day 65, so it is kept: a
	// box deletes by its clock only what a server's answer dated by that
	// clock lets it (PROTOCOL.md §0), and this box cannot tell a lost pass
	// from a clock far ahead.
	stem := func(l lease) string { return filepath.Join(b.Dir(), "prekeys", strconv.FormatUint(l.p.Serial, 10)) }
	if !exists(stem(first) + ".agekey") {
		t.Error("a passed-over key was deleted by a clock no server has taken a pass dated by since day 65")
	}
	// The first time a server takes one again, here the waiting renewal
	// (recv tries it again within the hour), it goes, with its statement. The
	// key in service and the one before it are held.
	e.srv.SetMiddle(nil)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatalf("day 75, the server back: prekey renew: %v", err)
	}
	if exists(stem(first)+".agekey") || has(b, "prekeys/"+strconv.FormatUint(first.p.Serial, 10)+".txt.sig") {
		t.Error("a passed-over key outlived its not_after + 33 days once a server took a pass again")
	}
	for _, key := range order[1:] {
		if !exists(stem(byKey[key]) + ".agekey") {
			t.Errorf("serial %d's key is gone while mail to it may still wait", byKey[key].p.Serial)
		}
	}
}

// A key an attempt made and never signed went nowhere: the next attempt uses
// it, at the same serial, with a working key and certificate made then, never
// the attempt's, whose certificate began when it ran (#197).
func TestAKeyNeverSignedIsUsed(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	forge.FailOnce(e.srv, http.MethodPut, "/prekey")
	if _, err := b.Rekey(context.Background(), ""); err == nil {
		t.Fatal("the rekey should have failed")
	}
	at := begunAt(t, b)
	stem := prekeyFile(b, at, "")
	key, _ := os.ReadFile(stem + ".agekey")
	for _, signed := range []string{".txt", ".txt.sig"} { // as a crash before the statement was kept would leave it
		b.SetRecord(t, "prekeys/"+strconv.FormatUint(at, 10)+signed, nil)
	}
	work := mustRead(t, workFile(b, at, ""))
	p, err := b.Rekey(context.Background(), "")
	if err != nil || p.Serial != at {
		t.Fatalf("rekey: %+v, %v", p, err)
	}
	if now, _ := os.ReadFile(stem + ".agekey"); len(key) == 0 || !bytes.Equal(now, key) || !strings.Contains(string(key), p.Key) {
		t.Fatal("the key that was never signed was not the one published")
	}
	if bytes.Equal(mustRead(t, workFile(b, at, "")), work) {
		t.Fatal("the attempt's working key was used again")
	}
}

// A server that answers every list 404 no_such_mailbox, and takes every
// registration, is not mended by the renewal a drain so refused makes: the
// next such renewal waits an hour, as one that failed does, so the box makes
// one an hour there and not one at every Receive (#328). Control: a box its
// owner deleted twice comes back at its first recv each time.
func TestARenewalThatMendsNothingWaitsAnHour(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	own := "/v1/" + b.Address().String()
	var registrations int
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == own || r.URL.Path == own+"/messages"):
			forge.Refuse(w, protocol.CodeNoSuchMailbox)
		case r.Method == http.MethodGet && r.URL.Path == own+"/revocations":
			forge.Refuse(w, protocol.CodeNotRevoked)
		case r.Method == http.MethodPut && r.URL.Path == own:
			registrations++
			fakeserver.WriteJSON(w, http.StatusCreated, struct{}{})
		default:
			next.ServeHTTP(w, r)
		}
	})
	for range 10 {
		e.clock.Add(time.Minute)
		if _, err := b.Receive(ctx); err == nil {
			t.Fatal("a drain answered 404 went through")
		}
	}
	if registrations != 1 {
		t.Fatalf("10 Receives a minute apart registered %d times, want once", registrations)
	}
	e.clock.Add(time.Hour)
	if _, err := b.Receive(ctx); err == nil || registrations != 2 {
		t.Fatalf("an hour later: %d registrations, %v; want 2 and the drain refused", registrations, err)
	}

	e.srv.SetMiddle(nil)
	d := e.box(protocol.Classic)
	for i := range 2 {
		if err := d.DeleteAtServer(ctx); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Minute)
		if res := receive(t, d); res.Renewed == nil || servedSerial(t, e, d) != res.Renewed.Serial {
			t.Fatalf("the recv after delete %d: %+v", i+1, res)
		}
	}
}

// A drain mended part way says what its first pass delivered: what landed
// and was acked before the refusal is in the command's Result, beside what
// the drain after the renewal delivered (#332).
func TestADrainMendedPartWaySaysWhatItsFirstPassDelivered(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	for _, body := range []string{"one", "two", "three"} {
		send(t, a, b, body)
	}
	e.srv.SetPage(1)
	list := "/v1/" + b.Address().String() + "/messages"
	var refused atomic.Bool
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == list && r.URL.Query().Get("cursor") != "" && refused.CompareAndSwap(false, true) {
			forge.Refuse(w, protocol.CodeNoSuchMailbox)
			return
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	var got []string
	for _, d := range res.Delivered {
		got = append(got, string(d.Envelope.Body))
	}
	slices.Sort(got)
	if !refused.Load() || res.Renewed == nil || !slices.Equal(got, []string{`"one"`, `"three"`, `"two"`}) {
		t.Fatalf("a drain mended after its second page: renewed %v, delivered %q, want all three", res.Renewed != nil, got)
	}
}
