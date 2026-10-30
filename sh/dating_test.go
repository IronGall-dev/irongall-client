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

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
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

// The script's side: dr_renew prunes by dr_now read after the server took
// the renewal. Here the clock jumps 70 days once the PUT …/prekey is
// answered. Keys are deleted by the reading the server took (AGENTS.md,
// #200, #209): the two messages waiting for the retired key are read once
// the clock is right.
func TestScriptAClockThatJumpsDuringARenewalDeletesNoKey(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}
	if out, err := bash(t, env, "dr_init --no-pq"); err != nil {
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
	jump := `dr_now(){ if [ -e "$DR/.jumped" ]; then echo $(($(date -u +%s) + 70*86400)); else date -u +%s; fi; }
eval "orig_$(declare -f dr_api)"
dr_api(){ orig_ig_api "$@"; local rc=$?; case "$1 $2" in "PUT /v1/"*/prekey) : > "$DR/.jumped" ;; esac; return $rc; }
`
	out, err := bash(t, env, jump+"dr_rekey --no-pq")
	t.Logf("the renewal, the clock jumping once it was taken: %q, %v; of %d prekeys, gone: %v", out, err, len(keys), goneKeys(keys))
	_ = os.Remove(filepath.Join(dir, ".jumped"))
	out, err = bash(t, env, "dr_recv")
	t.Logf("recv once the clock is right: %q, %v", out, err)
	if len(goneKeys(keys)) != 0 || strings.Count(out, `"type":"refused"`) != 0 {
		t.Errorf("a clock that jumped after the server took the renewal deleted %v, and the messages waiting for it are refused", goneKeys(keys))
	}
}

// shifted is a clock the fake server, a Go mailbox and the script share, set
// apart from the machine's by off; the script reads it through dr_now.
type shifted struct{ off atomic.Int64 }

func (c *shifted) Now() time.Time      { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *shifted) Set(d time.Duration) { c.off.Store(int64(d)) }
func igNow(d time.Duration) string {
	return fmt.Sprintf("dr_now(){ echo $(($(date -u +%%s) + %d)); }\n", int64(d/time.Second))
}

// frozen is a clock that stands still at base + off, for edges to the
// second: the fake server, a Go mailbox and the script (dr_now) read it.
type frozen struct {
	base time.Time
	off  atomic.Int64
}

func (c *frozen) Now() time.Time      { return c.base.Add(time.Duration(c.off.Load())) }
func (c *frozen) Set(d time.Duration) { c.off.Store(int64(d)) }
func (c *frozen) igNow(d time.Duration) string {
	return fmt.Sprintf("dr_now(){ echo %d; }\n", c.base.Add(d).Unix())
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
// client/replay_retry_test.go. The owner renews the script mailbox by hand on
// days 30 and 60; the server takes one dr_recv 1h32m ahead.
func TestTheScriptTakesARetryAboveTheFloor(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	day := 24 * time.Hour
	for _, c := range []struct {
		name  string
		ahead time.Duration
	}{
		{"one dr_recv 1h32m ahead, then right", 92 * time.Minute},
		{"control: never ahead", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			clk := &shifted{}
			srv := fakeserver.New(t, clk.Now)
			kt := protocol.PostQuantum
			dir := t.TempDir()
			sh := func(at time.Duration, cmd string) (string, error) {
				return bash(t, []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}, igNow(at)+cmd)
			}
			if _, err := sh(0, "dr_init"); err != nil {
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
			out, err := sh(0, "dr_recv")
			if err != nil || strings.Count(out, `"type":"message"`) != 1 {
				t.Fatalf("the first copy: %q, %v", out, err)
			}
			clk.Set(30 * day) // the owner renews by hand, monthly: the script never renews on its own
			if _, err := sh(30*day, "dr_rekey"); err != nil {
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
			if _, err := sh(60*day, "dr_rekey"); err != nil {
				t.Fatal(err)
			}
			at := 66*day - 31*time.Minute
			if c.ahead > 0 {
				clk.Set(at + c.ahead) // a hostile server takes the pass
				out, err := sh(at+c.ahead, "dr_recv")
				t.Logf("dr_recv %v ahead: %q, %v", c.ahead, out, err)
			}
			clk.Set(at)
			floor, _ := sh(at, "cat $DR/seen-floor 2> /dev/null")
			id := sha256.Sum256(retry)
			srv.Inject(to, hex.EncodeToString(id[:]), retry)
			out, err = sh(at, "dr_recv")
			t.Logf("the retry listed on day 66 less 31 minutes (floor %q): %q, %v", strings.TrimSpace(floor), out, err)
			if strings.Contains(out, `"type":"message"`) {
				t.Error("the script delivered a message already delivered")
			}
		})
	}
}

// The script reading a Go sender's retry that the server stretched past the
// outbox's 33 days (59s on the mailbox read, 59s on a post answered 409
// stale_prekey), with every pass one an honest server takes: the script's
// clock 50m fast at the drain that prunes, then 9m59s slow a second later.
func TestTheScriptTakesAStretchedRetryAtHonestClocks(t *testing.T) {
	t.Parallel()
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
				return bash(t, []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}, clk.igNow(at)+cmd)
			}
			if _, err := sh(0, "dr_init"); err != nil {
				t.Fatal(err)
			}
			to := mustAddress(t, dir)
			s, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clk.Now}, kt)
			if err != nil {
				t.Fatal(err)
			}
			mailbox := "/v1/" + to.String()
			var retry []byte
			var phase atomic.Value
			phase.Store("lose")
			posts, reads := 0, 0
			srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				p := phase.Load()
				switch {
				case q.Method == http.MethodPost && q.URL.Path == mailbox+"/messages" && p == "lose":
					next.ServeHTTP(httptest.NewRecorder(), q)
					http.Error(w, "lost", http.StatusServiceUnavailable)
					return
				case q.Method == http.MethodGet && q.URL.Path == mailbox && p == "keep" && stretch:
					reads++
					if reads == 1 {
						clk.Set(time.Duration(clk.off.Load()) + 59*time.Second)
					}
				case q.Method == http.MethodPost && q.URL.Path == mailbox+"/messages" && p == "keep":
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
			if out, err := sh(0, "dr_recv"); err != nil || !strings.Contains(out, `"type":"message"`) {
				t.Fatalf("the first copy: %q, %v", out, err)
			}
			clk.Set(30 * day)
			if _, err := sh(30*day, "dr_rekey"); err != nil {
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
			if _, err := sh(60*day, "dr_rekey"); err != nil {
				t.Fatal(err)
			}
			server := 2*protocol.TTL + 10*time.Minute + time.Second
			clk.Set(server)
			out, err := sh(server+50*time.Minute, "dr_recv")
			if err != nil {
				t.Fatalf("dr_recv 50 minutes fast: %q, %v", out, err)
			}
			floor, _ := sh(server, "cat $DR/seen-floor 2> /dev/null")
			server += time.Second
			clk.Set(server)
			id := sha256.Sum256(retry)
			srv.Inject(to, hex.EncodeToString(id[:]), retry)
			out, err = sh(server-(9*time.Minute+59*time.Second), "dr_recv")
			t.Logf("floor %q (W %d); the retry, the script 9m59s slow: %q, %v", strings.TrimSpace(floor), clk.base.Unix(), out, err)
			if strings.Contains(out, `"type":"message"`) {
				t.Error("the script delivered a message already delivered, at clocks an honest server takes")
			}
		})
	}
}

// The script's twin of TestAClockThatJumpsDuringADrainPrunesNoLine: dr_drain
// prunes the replay set by the date of the pass its list carried (dr_taken),
// which the server took, so a clock that jumps 70 days once the list is
// answered drops no line and raises no floor.
func TestScriptAClockThatJumpsDuringADrainPrunesNoLine(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}
	if out, err := bash(t, env, "dr_init"); err != nil {
		t.Fatalf("init: %q, %v", out, err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Send(ctx, mustAddress(t, dir), "delivered once"); err != nil {
		t.Fatal(err)
	}
	if out, err := bash(t, env, "dr_recv"); err != nil || !strings.Contains(out, `"type":"message"`) {
		t.Fatalf("the first drain: %q, %v", out, err)
	}
	before := mustRead(t, filepath.Join(dir, "seen"))
	jump := `dr_now(){ if [ -e "$DR/.jumped" ]; then echo $(($(date -u +%s) + 70*86400)); else date -u +%s; fi; }
eval "orig_$(declare -f dr_api)"
dr_api(){ orig_ig_api "$@"; local rc=$?; case "$1 $2" in "GET /v1/"*/messages | "GET /v1/"*"/messages?"*) : > "$DR/.jumped" ;; esac; return $rc; }
`
	out, err := bash(t, env, jump+"dr_recv")
	t.Logf("the drain whose clock jumped once its list was answered: %q, %v", out, err)
	after := mustRead(t, filepath.Join(dir, "seen"))
	if _, ferr := os.Stat(filepath.Join(dir, "seen-floor")); !bytes.Equal(before, after) || ferr == nil {
		t.Errorf("a clock that jumped after the server took the list pruned the replay set by where it went: %q, then %q", before, after)
	}
}

// The script dates its retry after 409 stale_prekey once the recipient's mailbox
// is read again, as it dates its first post (#341): dr_post reads the mailbox
// before each seal and seals to what it read. Here the retry's read is
// answered 59 seconds later, by the clock the script (dr_now), the server
// and the Go mailboxes share, and each message is dated after its retry's read
// was answered: the script's, and the Go client's sent the same way.
func TestTheScriptDatesARetryAfterItsMailboxRead(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	clk := &frozen{base: time.Now().UTC().Truncate(time.Second)}
	clockFile := filepath.Join(t.TempDir(), "now")
	set := func(d time.Duration) {
		clk.Set(d)
		if err := os.WriteFile(clockFile, []byte(fmt.Sprintln(clk.Now().Unix())), 0o600); err != nil {
			t.Error(err)
		}
	}
	set(0)
	srv := fakeserver.New(t, clk.Now)
	r, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clk.Now}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetPolicy(ctx, client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		t.Fatal(err)
	}
	env := []string{"DR_HOME=" + t.TempDir(), "DR_SERVER_URL=" + srv.URL}
	igNow := `dr_now(){ cat "` + clockFile + `"; }` + "\n"
	if out, err := bash(t, env, igNow+"dr_init --no-pq"); err != nil {
		t.Fatalf("init: %q, %v", out, err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clk.Now}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	mailbox := "/v1/" + r.Address().String()
	posts, reads := 0, 0
	srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
		switch {
		case q.Method == http.MethodPost && q.URL.Path == mailbox+"/messages":
			if posts++; posts%2 == 1 {
				staleProblem(w)
				return
			}
		case q.Method == http.MethodGet && q.URL.Path == mailbox:
			if reads++; reads%2 == 0 {
				set(time.Duration(clk.off.Load()) + 59*time.Second) // the retry's read, answered 59s later
			}
		}
		next.ServeHTTP(w, q)
	})
	if out, err := bash(t, env, igNow+"echo 'from the script' | dr_send "+r.Address().String()); err != nil {
		t.Fatalf("the script's send: %q, %v", out, err)
	}
	read := map[string]time.Time{"from the script": clk.Now()}
	if reads != 2 || posts != 2 {
		t.Errorf("the script's send read the mailbox %d times and posted %d, want twice each", reads, posts)
	}
	if _, err := g.Send(ctx, r.Address(), "from the Go client"); err != nil {
		t.Fatalf("the Go client's send: %v", err)
	}
	read["from the Go client"] = clk.Now()
	srv.SetMiddle(nil)
	res, err := r.Receive(ctx)
	if err != nil || len(res.Delivered) != 2 {
		t.Fatalf("delivered %d: %v", len(res.Delivered), err)
	}
	for _, d := range res.Delivered {
		var body string
		_ = json.Unmarshal(d.Envelope.Body, &body)
		at, ok := read[strings.TrimSpace(body)]
		t.Logf("%q dated %s, its retry's read answered at %s", body, d.Envelope.SentAt.Format(protocol.TimeLayout), at.Format(protocol.TimeLayout))
		if !ok || d.Envelope.SentAt.Before(at) {
			t.Errorf("%q is dated %v before its retry's mailbox read was answered", body, at.Sub(d.Envelope.SentAt))
		}
	}
}
