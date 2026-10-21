package sh_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// goneKeys names the files of keys that are no longer there.
func goneKeys(keys []string) []string {
	var g []string
	for _, k := range keys {
		if _, err := os.Stat(k); err != nil {
			g = append(g, filepath.Base(k))
		}
	}
	return g
}

// The script's side: ig_renew prunes by ig_now read after the server took
// the renewal. Here the clock jumps 70 days once the PUT …/prekey is
// answered. Keys are deleted by the reading the server took (AGENTS.md,
// #200, #209): the two messages waiting for the retired key are read once
// the clock is right.
func TestScriptAClockThatJumpsDuringARenewalDeletesNoKey(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if out, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatalf("init: %q, %v", out, err)
	}
	b, err := protocol.ParseAddress(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "address")))))
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"first, sealed to the prekey about to retire", "second, sealed to it too"} {
		if _, err := g.Send(ctx, b, m); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	keys, _ := filepath.Glob(filepath.Join(dir, "prekeys", "*.agekey"))
	jump := `ig_now(){ if [ -e "$IG/.jumped" ]; then echo $(($(date -u +%s) + 70*86400)); else date -u +%s; fi; }
eval "orig_$(declare -f ig_api)"
ig_api(){ orig_ig_api "$@"; local rc=$?; case "$1 $2" in "PUT /v1/"*/prekey) : > "$IG/.jumped" ;; esac; return $rc; }
`
	out, err := bash(t, env, jump+"ig_rekey --no-pq")
	t.Logf("the renewal, the clock jumping once it was taken: %q, %v; of %d prekeys, gone: %v", out, err, len(keys), goneKeys(keys))
	_ = os.Remove(filepath.Join(dir, ".jumped"))
	out, err = bash(t, env, "ig_recv")
	t.Logf("recv once the clock is right: %q, %v", out, err)
	if len(goneKeys(keys)) != 0 || strings.Count(out, `"type":"refused"`) != 0 {
		t.Errorf("a clock that jumped after the server took the renewal deleted %v, and the mail waiting for it is refused", goneKeys(keys))
	}
}

// shifted is a clock the fake server, a Go box and the script share, set
// apart from the machine's by off; the script reads it through ig_now.
type shifted struct{ off atomic.Int64 }

func (c *shifted) Now() time.Time      { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *shifted) Set(d time.Duration) { c.off.Store(int64(d)) }
func igNow(d time.Duration) string {
	return fmt.Sprintf("ig_now(){ echo $(($(date -u +%%s) + %d)); }\n", int64(d/time.Second))
}

// frozen is a clock that stands still at base + off, for edges to the
// second: the fake server, a Go box and the script (ig_now) read it.
type frozen struct {
	base time.Time
	off  atomic.Int64
}

func (c *frozen) Now() time.Time      { return c.base.Add(time.Duration(c.off.Load())) }
func (c *frozen) Set(d time.Duration) { c.off.Store(int64(d)) }
func (c *frozen) igNow(d time.Duration) string {
	return fmt.Sprintf("ig_now(){ echo %d; }\n", c.base.Add(d).Unix())
}

func mustAddress(t *testing.T, dir string) protocol.Address {
	t.Helper()
	a, err := protocol.ParseAddress(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "address")))))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func staleProblem(w http.ResponseWriter) {
	code := protocol.CodeStalePrekey
	w.Header().Set("Content-Type", protocol.ProblemContentType)
	w.WriteHeader(code.Status())
	_ = json.NewEncoder(w).Encode(protocol.Problem{Type: code.TypeURI(), Title: code.Title(), Status: int64(code.Status()), Code: code, Detail: "a newer prekey"})
}

// The script reading, the Go client sending: the retry above the floor of
// client/replay_retry_test.go. The owner renews the script box by hand on
// days 30 and 60; the server takes one ig_recv 1h32m ahead.
func TestTheScriptTakesARetryAboveTheFloor(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	day := 24 * time.Hour
	for _, c := range []struct {
		name  string
		ahead time.Duration
	}{
		{"one ig_recv 1h32m ahead, then right", 92 * time.Minute},
		{"control: never ahead", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			clk := &shifted{}
			srv := fakeserver.New(t, clk.Now)
			kt := protocol.PostQuantum
			dir := t.TempDir()
			sh := func(at time.Duration, cmd string) (string, error) {
				return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, igNow(at)+cmd)
			}
			if _, err := sh(0, "ig_init"); err != nil {
				t.Fatal(err)
			}
			to := mustAddress(t, dir)
			s, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clk.Now}, kt)
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/" + to.String() + "/messages"
			var retry []byte
			var phase atomic.Value
			phase.Store("lose")
			srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				if q.Method == http.MethodPost && q.URL.Path == path {
					switch phase.Load() {
					case "lose":
						next.ServeHTTP(httptest.NewRecorder(), q)
						http.Error(w, "lost", http.StatusServiceUnavailable)
						return
					case "keep":
						retry, _ = io.ReadAll(q.Body)
						http.Error(w, "down", http.StatusServiceUnavailable)
						return
					}
				}
				next.ServeHTTP(w, q)
			})
			if _, err := s.Send(ctx, to, "pay invoice 7 once"); err == nil {
				t.Fatal("the first post's answer was not lost")
			}
			out, err := sh(0, "ig_recv")
			if err != nil || strings.Count(out, `"type":"mail"`) != 1 {
				t.Fatalf("the first copy: %q, %v", out, err)
			}
			clk.Set(30 * day) // the owner renews by hand, monthly: the script never renews on its own
			if _, err := sh(30*day, "ig_rekey"); err != nil {
				t.Fatal(err)
			}
			clk.Set(33*day - 30*time.Minute)
			if _, err := s.Receive(ctx); err != nil { // renews, so its certificate outlasts what it signs
				t.Fatal(err)
			}
			phase.Store("keep")
			if _, err := s.Flush(ctx); err == nil || retry == nil {
				t.Fatalf("the retry: %v, kept %d bytes", err, len(retry))
			}
			phase.Store("")
			clk.Set(60 * day)
			if _, err := sh(60*day, "ig_rekey"); err != nil {
				t.Fatal(err)
			}
			at := 66*day - 31*time.Minute
			if c.ahead > 0 {
				clk.Set(at + c.ahead) // a hostile server takes the pass
				out, err := sh(at+c.ahead, "ig_recv")
				t.Logf("ig_recv %v ahead: %q, %v", c.ahead, out, err)
			}
			clk.Set(at)
			floor, _ := sh(at, "cat $IG/seen-floor 2> /dev/null")
			id := sha256.Sum256(retry)
			srv.Inject(to, hex.EncodeToString(id[:]), s.Address(), retry)
			out, err = sh(at, "ig_recv")
			t.Logf("the retry listed on day 66 less 31 minutes (floor %q): %q, %v", strings.TrimSpace(floor), out, err)
			if strings.Contains(out, `"type":"mail"`) {
				t.Error("the script delivered a message already delivered")
			}
		})
	}
}

// The script reading a Go sender's retry that the server stretched past the
// outbox's 33 days (59s on the box read, 59s on a post answered 409
// stale_prekey), with every pass one an honest server takes: the script's
// clock 50m fast at the drain that prunes, then 9m59s slow a second later.
func TestTheScriptTakesAStretchedRetryAtHonestClocks(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	day := 24 * time.Hour
	for _, stretch := range []bool{true, false} {
		name := "stretched"
		if !stretch {
			name = "control: not stretched"
		}
		t.Run(name, func(t *testing.T) {
			clk := &frozen{base: time.Now().UTC().Truncate(time.Second)}
			srv := fakeserver.New(t, clk.Now)
			kt := protocol.PostQuantum
			dir := t.TempDir()
			sh := func(at time.Duration, cmd string) (string, error) {
				return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, clk.igNow(at)+cmd)
			}
			if _, err := sh(0, "ig_init"); err != nil {
				t.Fatal(err)
			}
			to := mustAddress(t, dir)
			s, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clk.Now}, kt)
			if err != nil {
				t.Fatal(err)
			}
			box := "/v1/" + to.String()
			var retry []byte
			var phase atomic.Value
			phase.Store("lose")
			posts, reads := 0, 0
			srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				p := phase.Load()
				switch {
				case q.Method == http.MethodPost && q.URL.Path == box+"/messages" && p == "lose":
					next.ServeHTTP(httptest.NewRecorder(), q)
					http.Error(w, "lost", http.StatusServiceUnavailable)
					return
				case q.Method == http.MethodGet && q.URL.Path == box && p == "keep" && stretch:
					reads++
					if reads == 1 {
						clk.Set(time.Duration(clk.off.Load()) + 59*time.Second)
					}
				case q.Method == http.MethodPost && q.URL.Path == box+"/messages" && p == "keep":
					posts++
					if stretch && posts == 1 {
						clk.Set(time.Duration(clk.off.Load()) + 59*time.Second)
						staleProblem(w)
						return
					}
					retry, _ = io.ReadAll(q.Body)
					http.Error(w, "down", http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, q)
			})
			if _, err := s.Send(ctx, to, "pay invoice 15 once"); err == nil {
				t.Fatal("the answer came")
			}
			if out, err := sh(0, "ig_recv"); err != nil || !strings.Contains(out, `"type":"mail"`) {
				t.Fatalf("the first copy: %q, %v", out, err)
			}
			clk.Set(30 * day)
			if _, err := sh(30*day, "ig_rekey"); err != nil {
				t.Fatal(err)
			}
			clk.Set(protocol.TTL - time.Hour)
			if _, err := s.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			clk.Set(protocol.TTL)
			phase.Store("keep")
			_, err = s.Flush(ctx)
			phase.Store("")
			if retry == nil {
				if stretch {
					t.Logf("no retry was posted: %v", err)
					return
				}
				t.Fatalf("the retry at W+TTL: %v", err)
			}
			clk.Set(60 * day)
			if _, err := sh(60*day, "ig_rekey"); err != nil {
				t.Fatal(err)
			}
			server := 2*protocol.TTL + 10*time.Minute + time.Second
			clk.Set(server)
			out, err := sh(server+50*time.Minute, "ig_recv")
			if err != nil {
				t.Fatalf("ig_recv 50 minutes fast: %q, %v", out, err)
			}
			floor, _ := sh(server, "cat $IG/seen-floor 2> /dev/null")
			server += time.Second
			clk.Set(server)
			id := sha256.Sum256(retry)
			srv.Inject(to, hex.EncodeToString(id[:]), s.Address(), retry)
			out, err = sh(server-(9*time.Minute+59*time.Second), "ig_recv")
			t.Logf("floor %q (W %d); the retry, the script 9m59s slow: %q, %v", strings.TrimSpace(floor), clk.base.Unix(), out, err)
			if strings.Contains(out, `"type":"mail"`) {
				t.Error("the script delivered a message already delivered, at clocks an honest server takes")
			}
		})
	}
}

// The script's twin of TestAClockThatJumpsDuringADrainPrunesNoLine: ig_drain
// prunes the replay set by the date of the pass its list carried (ig_taken),
// which the server took, so a clock that jumps 70 days once the list is
// answered drops no line and raises no floor.
func TestScriptAClockThatJumpsDuringADrainPrunesNoLine(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if out, err := bash(t, env, "ig_init"); err != nil {
		t.Fatalf("init: %q, %v", out, err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Send(ctx, mustAddress(t, dir), "delivered once"); err != nil {
		t.Fatal(err)
	}
	if out, err := bash(t, env, "ig_recv"); err != nil || !strings.Contains(out, `"type":"mail"`) {
		t.Fatalf("the first drain: %q, %v", out, err)
	}
	before := mustRead(t, filepath.Join(dir, "seen"))
	jump := `ig_now(){ if [ -e "$IG/.jumped" ]; then echo $(($(date -u +%s) + 70*86400)); else date -u +%s; fi; }
eval "orig_$(declare -f ig_api)"
ig_api(){ orig_ig_api "$@"; local rc=$?; case "$1 $2" in "GET /v1/"*/messages | "GET /v1/"*"/messages?"*) : > "$IG/.jumped" ;; esac; return $rc; }
`
	out, err := bash(t, env, jump+"ig_recv")
	t.Logf("the drain whose clock jumped once its list was answered: %q, %v", out, err)
	after := mustRead(t, filepath.Join(dir, "seen"))
	if _, ferr := os.Stat(filepath.Join(dir, "seen-floor")); !bytes.Equal(before, after) || ferr == nil {
		t.Errorf("a clock that jumped after the server took the list pruned the replay set by where it went: %q, then %q", before, after)
	}
}
