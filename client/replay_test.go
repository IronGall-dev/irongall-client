package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A reader whose clock steps back meets mail it has already delivered as
// fresh again. The server keeps what it was sent and lists it once more; the
// reader must refuse it whatever its clock read when it last pruned
// (PROTOCOL.md §5 check 9, §0).
func TestAReplayIsRefusedAfterTheClockStepsBack(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	ctx := context.Background()
	for _, c := range []struct {
		name        string
		wait        time.Duration // from sent_at to the drain while ahead
		ahead, back time.Duration // the reader's clock then, and at the replay
		serverToo   bool          // the server's clock is moved with the reader's: a hostile server that takes a pass from a clock an honest one refuses, and refuses the renewal it would make
	}{
		{"50m fast at a drain the server takes, then 9m slow", protocol.TTL - 49*time.Minute, 50 * time.Minute, -9 * time.Minute, false},
		{"40 days fast at a recv the server refuses, then right", 5 * 24 * time.Hour, 40 * 24 * time.Hour, 0, false},
		{"62 days fast at a drain a hostile server takes, then right", 5 * 24 * time.Hour, 62 * 24 * time.Hour, 0, true},
		{"control: never ahead", 5 * 24 * time.Hour, 0, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			off := time.Duration(0)
			r, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
			if err != nil {
				t.Fatal(err)
			}
			landAll(t, r)
			s := e.box(protocol.Classic)
			var kept []byte
			e.srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				if q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, "/messages") {
					kept, _ = io.ReadAll(q.Body)
					q.Body = io.NopCloser(bytes.NewReader(kept))
				}
				next.ServeHTTP(w, q)
			})
			send(t, s, r, "pay invoice 7 once")
			if res := receive(t, r); len(res.Delivered) != 1 {
				t.Fatalf("the first drain delivered %d", len(res.Delivered))
			}
			// Renewed just before, at the right clock, so the drain while
			// ahead makes no certificate dated by it: the replay is judged.
			e.clock.Add(c.wait - time.Minute)
			if _, err := r.Rekey(ctx, ""); err != nil {
				t.Fatal(err)
			}
			e.clock.Add(time.Minute)
			off = c.ahead
			if c.serverToo {
				e.clock.Add(c.ahead)
				off = 0
				e.srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
					if q.Method == http.MethodPut && strings.HasSuffix(q.URL.Path, "/prekey") {
						http.Error(w, "down", http.StatusServiceUnavailable)
						return
					}
					next.ServeHTTP(w, q)
				})
			}
			_, err = r.Receive(ctx)
			if c.serverToo {
				e.clock.Add(-c.ahead)
				e.srv.SetMiddle(nil)
			}
			off = c.back
			id := sha256.Sum256(kept)
			e.srv.Inject(r.Address(), hex.EncodeToString(id[:]), s.Address(), kept)
			res, err2 := r.Receive(ctx)
			t.Logf("the drain while ahead: %v; the replay: delivered %d, refused %v, %v", client.Code(err), len(res.Delivered), res.Refused, err2)
			if len(res.Delivered) != 0 || err2 != nil {
				t.Error("a message already delivered was delivered again, or the replay was not judged")
			}
			// Past what the replay set reaches back over, the prekey it was
			// sealed to is gone too, and it is refused as undecryptable: the
			// floor's own refusal, for a key kept longer than that, is
			// TestTheSeenFloor's.
			if c.serverToo && len(res.Refused) != 1 {
				t.Errorf("the replay after a step back of 62 days: refused %v, want one refusal", res.Refused)
			}
		})
	}
}

// A recv refused for its clock prunes nothing, whether its server refuses the
// pass or the box its own certificate first: the seen-set is pruned only once
// the server has taken a pass dated by that clock.
func TestARefusedDrainPrunesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	off := time.Duration(0)
	r, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, r)
	send(t, e.box(protocol.Classic), r, "hello")
	receive(t, r)
	before, ok := stateOf(r, "seen")
	if !ok || len(before) == 0 {
		t.Fatal("no replay set after a delivery")
	}
	// Far enough ahead that a prune by this clock would drop the line.
	off = protocol.SeenFor + 4*24*time.Hour
	if _, err := r.Receive(ctx); err == nil {
		t.Fatalf("a drain %v ahead was taken", off)
	}
	if after, _ := stateOf(r, "seen"); !bytes.Equal(before, after) {
		t.Errorf("a refused drain changed the replay set: %q, then %q", before, after)
	}
	if has(r, "seen-floor") {
		t.Error("a refused drain raised the floor")
	}
}

// The floor rises only when a prune drops a line, to the cutoff it dropped
// it at; a mail sent before it is refused as stale, and one after is taken.
// A floor that names no time stops the drain, with the mail left on the
// server.
func TestTheSeenFloor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	r := e.box(protocol.Classic)
	s := e.box(protocol.Classic)
	send(t, s, r, "first")
	receive(t, r)
	if has(r, "seen-floor") {
		t.Fatal("a floor before any line was dropped")
	}
	e.clock.Add(protocol.SeenFor + time.Second)
	receive(t, r) // prunes the line, and renews the prekey that ran out
	raw, _ := stateOf(r, "seen-floor")
	if want := strconv.FormatInt(e.clock.Now().Add(-protocol.SeenFor).Unix(), 10); string(raw) != want {
		t.Fatalf("the floor after a prune dropped a line: %q; want the cutoff it dropped it at, %q", raw, want)
	}

	s = e.box(protocol.Classic) // a sender whose certificate is valid now
	send(t, s, r, "second")
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d after the prune, want 1", len(res.Delivered))
	}

	// Mail sent before the floor is stale, whatever the clock reads.
	r.SetRecord(t, "seen-floor", []byte("9999999999"))
	send(t, s, r, "third")
	res := receive(t, r)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedStale {
		t.Errorf("mail sent before the floor: delivered %d, refused %v, want one stale", len(res.Delivered), res.Refused)
	}

	// A floor that names no time is an error, and the mail stays.
	r.SetRecord(t, "seen-floor", []byte("soon"))
	send(t, s, r, "fourth")
	if _, err := r.Receive(ctx); err == nil || !strings.Contains(err.Error(), "seen-floor") {
		t.Errorf("a drain with a floor that names no time: %v, want an error naming it", err)
	}
	r.SetRecord(t, "seen-floor", nil)
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Errorf("the mail left on the server: delivered %d once the floor was removed, want 1", len(res.Delivered))
	}
}
