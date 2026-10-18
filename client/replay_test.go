package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	ctx := context.Background()
	for _, c := range []struct {
		name        string
		wait        time.Duration // from sent_at to the drain while ahead
		ahead, back time.Duration // the reader's clock then, and at the replay
		serverToo   bool          // the server's clock is moved with the reader's: a hostile server that takes a pass from a clock an honest one refuses
	}{
		{"50m fast at a drain the server takes, then 9m slow", protocol.TTL - 49*time.Minute, 50 * time.Minute, -9 * time.Minute, false},
		{"40 days fast at a recv the server refuses, then right", 5 * 24 * time.Hour, 40 * 24 * time.Hour, 0, false},
		{"4 hours fast at a drain a hostile server takes, then right", protocol.TTL - 2*time.Hour, 4 * time.Hour, 0, true},
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
			}
			_, err = r.Receive(ctx)
			if c.serverToo {
				e.clock.Add(-c.ahead)
			}
			off = c.back
			id := sha256.Sum256(kept)
			e.srv.Inject(r.Address(), hex.EncodeToString(id[:]), s.Address(), kept)
			res, err2 := r.Receive(ctx)
			t.Logf("the drain while ahead: %v; the replay: delivered %d, refused %v, %v", client.Code(err), len(res.Delivered), res.Refused, err2)
			if len(res.Delivered) != 0 || err2 != nil {
				t.Error("a message already delivered was delivered again, or the replay was not judged")
			}
			// Past the hour, the floor is what refuses it.
			if c.serverToo && (len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedStale) {
				t.Errorf("the replay after a step back past the hour: refused %v, want one stale", res.Refused)
			}
		})
	}
}

// A recv the server refuses for its clock prunes nothing: the seen-set is
// pruned only once the server has taken a pass dated by that clock.
func TestARefusedDrainPrunesNothing(t *testing.T) {
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
	before, err := os.ReadFile(filepath.Join(r.Dir(), "seen"))
	if err != nil || len(before) == 0 {
		t.Fatalf("no seen-set after a delivery: %v", err)
	}
	off = 40 * 24 * time.Hour
	if _, err := r.Receive(ctx); client.Code(err) != protocol.CodePassExpired {
		t.Fatalf("a drain 40 days ahead: %v, want pass_expired", err)
	}
	after, err := os.ReadFile(filepath.Join(r.Dir(), "seen"))
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("a refused drain changed the seen-set: %q, then %q (%v)", before, after, err)
	}
	if _, err := os.Stat(filepath.Join(r.Dir(), "seen-floor")); err == nil {
		t.Error("a refused drain raised the floor")
	}
}

// The floor rises only when a prune drops a line, to the cutoff it dropped
// it at; a mail sent before it is refused as stale, and one after is taken.
// A floor file that names no time stops the drain, with the mail left on the
// server.
func TestTheSeenFloor(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r := e.box(protocol.Classic)
	s := e.box(protocol.Classic)
	send(t, s, r, "first")
	receive(t, r)
	floor := filepath.Join(r.Dir(), "seen-floor")
	if _, err := os.Stat(floor); err == nil {
		t.Fatal("a floor before any line was dropped")
	}
	e.clock.Add(protocol.SeenFor + time.Second)
	receive(t, r) // prunes the line, and renews the prekey that ran out
	raw, err := os.ReadFile(floor)
	if want := strconv.FormatInt(e.clock.Now().Add(-protocol.SeenFor).Unix(), 10) + "\n"; err != nil || string(raw) != want {
		t.Fatalf("the floor after a prune dropped a line: %q, %v; want the cutoff it dropped it at, %q", raw, err, want)
	}

	s = e.box(protocol.Classic) // a sender whose certificate is valid now
	send(t, s, r, "second")
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d after the prune, want 1", len(res.Delivered))
	}

	// Mail sent before the floor is stale, whatever the clock reads.
	if err := os.WriteFile(floor, []byte("9999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	send(t, s, r, "third")
	res := receive(t, r)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedStale {
		t.Errorf("mail sent before the floor: delivered %d, refused %v, want one stale", len(res.Delivered), res.Refused)
	}

	// A floor that names no time is an error, and the mail stays.
	if err := os.WriteFile(floor, []byte("soon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	send(t, s, r, "fourth")
	if _, err := r.Receive(ctx); err == nil || !strings.Contains(err.Error(), "seen-floor") {
		t.Errorf("a drain with a floor that names no time: %v, want an error naming the file", err)
	}
	if err := os.Remove(floor); err != nil {
		t.Fatal(err)
	}
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Errorf("the mail left on the server: delivered %d once the floor was removed, want 1", len(res.Delivered))
	}
}
