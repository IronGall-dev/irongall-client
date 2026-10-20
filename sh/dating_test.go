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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// One box run by both clients: the script keeps a message whose body holds
// U+2028, which jq writes raw, while its server is down; the Go client then
// flushes the same box. Its dating changes sent_at and no other byte, so the
// entry reads back as itself and is posted (#253).
func TestTheGoClientFlushesAScriptEntryWithALineSeparator(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	kt, mode := protocol.Classic, "--no-pq"
	if pq() {
		kt, mode = protocol.PostQuantum, ""
	}
	down := true
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	to, err := client.Init(ctx, t.TempDir(), opt, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, to)
	dir := t.TempDir()
	sh := func(commands string) (string, error) {
		return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, commands)
	}
	if _, err := sh("ig_init " + mode); err != nil {
		t.Fatal(err)
	}
	sep := string(rune(0x2028))
	for how, body := range map[string]string{"--json": `{"a":"x` + sep + `y"}`, "": "x" + sep + "y"} {
		f := filepath.Join(t.TempDir(), "body")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sh("ig_send " + how + " " + to.Address().String() + " " + f); err == nil {
			t.Fatal("the post was meant to fail")
		}
	}
	down = false
	s, err := client.Open(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		got, err := s.Flush(ctx)
		t.Logf("the Go client's flush %d: %d sent, %v", i+1, len(got), err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "outbox", "*.P"))
	res, err := to.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 || len(res.Delivered) != 2 {
		t.Fatalf("after two flushes by the Go client: %d entries still in the outbox, %d delivered", len(left), len(res.Delivered))
	}
}

// A post dates the envelope afresh, and changes nothing else, whichever
// client wrote the outbox entry and whichever posts it, five days after it
// was written (PROTOCOL.md §4.5). Bodies with a line or paragraph separator,
// which jq writes as it is and the Go client's line escapes, are among them.
func TestADatedPostAcrossClients(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	day := 24 * time.Hour
	kt, mode := protocol.Classic, "--no-pq"
	if pq() {
		kt, mode = protocol.PostQuantum, ""
	}
	const replyTo, supersedes = "0f0e0d0c-0b0a-4908-8706-050403020100", "00010203-0405-4607-8809-0a0b0c0d0e0f"
	for _, c := range []struct {
		name, body string
		json       bool
	}{
		{"text", "written five days before its post", false},
		{"text with U+2028", "line one" + string(rune(0x2028)) + "line two", false},
		{"JSON with U+2029", `{"a":"x` + string(rune(0x2029)) + `y","n":1.0}`, true},
	} {
		for _, writer := range []string{"script", "go"} {
			t.Run(c.name+", written by the "+writer, func(t *testing.T) {
				clk := &shifted{}
				srv := fakeserver.New(t, clk.Now)
				var down atomic.Bool
				down.Store(true)
				srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
					if q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, "/messages") && down.Load() {
						http.Error(w, "down", http.StatusServiceUnavailable)
						return
					}
					next.ServeHTTP(w, q)
				})
				opt := client.Options{Base: srv.URL, Now: clk.Now}
				to, err := client.Init(ctx, t.TempDir(), opt, kt)
				if err != nil {
					t.Fatal(err)
				}
				landAll(t, to)
				dir := t.TempDir()
				sh := func(at time.Duration, cmd string) (string, error) {
					return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, igNow(at)+cmd)
				}
				var g *client.Box
				if writer == "script" {
					if _, err := sh(0, "ig_init "+mode); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "body.in"), []byte(c.body), 0o600); err != nil {
						t.Fatal(err)
					}
					j := ""
					if c.json {
						j = "--json "
					}
					if _, err := sh(0, "ig_send "+j+"--subject 'a subject' --reply-to "+replyTo+" --supersedes "+supersedes+" "+to.Address().String()+" $IG/body.in"); err == nil {
						t.Fatal("the post was meant to fail")
					}
				} else {
					if g, err = client.Init(ctx, dir, opt, kt); err != nil {
						t.Fatal(err)
					}
					f := client.Fields{Subject: "a subject", InReplyTo: replyTo, Supersedes: supersedes}
					if c.json {
						_, err = g.SendJSON(ctx, to.Address(), []byte(c.body), f)
					} else {
						_, err = g.SendWith(ctx, to.Address(), c.body, f)
					}
					if err == nil {
						t.Fatal("the post was meant to fail")
					}
				}
				entries, _ := filepath.Glob(filepath.Join(dir, "outbox", "*.P"))
				if len(entries) != 1 {
					t.Fatalf("outbox: %v", entries)
				}
				written := mustRead(t, entries[0])
				w, err := protocol.OpenEnvelopeRecord(written, mustAddress(t, dir), to.Address())
				if err != nil {
					t.Fatal(err)
				}
				clk.Set(5 * day)
				down.Store(false)
				if writer == "script" { // the Go client posts what the script wrote
					s, err := client.Open(dir, opt)
					if err != nil {
						t.Fatal(err)
					}
					if sent, err := s.Flush(ctx); err != nil || len(sent) != 1 {
						t.Fatalf("the Go client's flush, five days after the script wrote it: %v, %v", sent, err)
					}
				} else if out, err := sh(5*day, "ig_flush"); err != nil {
					t.Fatalf("the script's flush, five days after the Go client wrote it: %q, %v", out, err)
				}
				res, err := to.Receive(ctx)
				if err != nil || len(res.Delivered) != 1 {
					t.Fatalf("delivered %+v, %v", res, err)
				}
				d := res.Delivered[0].Envelope
				t.Logf("written %s, posted %s; body %s", w.SentAt.Format(time.RFC3339), d.SentAt.Format(time.RFC3339), d.Body)
				if d.SentAt.Sub(w.SentAt) < 5*day || d.SentAt.Sub(w.SentAt) > 5*day+time.Minute {
					t.Errorf("sent_at %v, written %v: want the post's", d.SentAt, w.SentAt)
				}
				var wb, db any
				_ = json.Unmarshal(w.Body, &wb)
				_ = json.Unmarshal(d.Body, &db)
				if d.MsgID != w.MsgID || !reflect.DeepEqual(wb, db) || d.Subject != w.Subject || d.InReplyTo != w.InReplyTo || d.Supersedes != w.Supersedes || !bytes.Equal(d.Identity, w.Identity) && d.Identity != nil {
					t.Errorf("the post changed more than sent_at: %+v, written %+v", d, w)
				}
				recs, _ := filepath.Glob(filepath.Join(dir, "sent", "*.json"))
				if len(recs) != 1 || !strings.Contains(string(mustRead(t, recs[0])), `"sent_at":"`+d.SentAt.UTC().Format(protocol.TimeLayout)+`"`) {
					t.Errorf("sent/ does not keep the envelope as posted: %v", recs)
				}
			})
		}
	}
}

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
			mode, kt := "--no-pq", protocol.Classic
			if pq() {
				mode, kt = "", protocol.PostQuantum
			}
			dir := t.TempDir()
			sh := func(at time.Duration, cmd string) (string, error) {
				return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, igNow(at)+cmd)
			}
			if _, err := sh(0, "ig_init "+mode); err != nil {
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
			if _, err := sh(30*day, "ig_rekey "+mode); err != nil {
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
			if _, err := sh(60*day, "ig_rekey "+mode); err != nil {
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
			mode, kt := "--no-pq", protocol.Classic
			if pq() {
				mode, kt = "", protocol.PostQuantum
			}
			dir := t.TempDir()
			sh := func(at time.Duration, cmd string) (string, error) {
				return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, clk.igNow(at)+cmd)
			}
			if _, err := sh(0, "ig_init "+mode); err != nil {
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
			if _, err := sh(30*day, "ig_rekey "+mode); err != nil {
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
			if _, err := sh(60*day, "ig_rekey "+mode); err != nil {
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

// The script as sender dates no post past the outbox's 33 days: ig_seal
// holds the entry as written to ig_envcheck before it dates. The server
// answers the box read after 59s at W + TTL; the flush is refused as stale
// and nothing is posted. ig_now reads a file the server's middleware moves.
func TestTheScriptDatesNoPostPastItsOutbox(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	day := 24 * time.Hour
	base := time.Now().UTC().Truncate(time.Second)
	var off atomic.Int64
	now := func() time.Time { return base.Add(time.Duration(off.Load())) }
	nowFile := filepath.Join(t.TempDir(), "now")
	set := func(d time.Duration) {
		off.Store(int64(d))
		if err := os.WriteFile(nowFile, []byte(fmt.Sprint(now().Unix())), 0o600); err != nil {
			t.Error(err)
		}
	}
	set(0)
	srv := fakeserver.New(t, now)
	dir := t.TempDir()
	sh := func(cmd string) (string, error) {
		return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, `ig_now(){ cat "`+nowFile+`"; }`+"\n"+cmd)
	}
	mode, kt := "--no-pq", protocol.Classic
	if pq() {
		mode, kt = "", protocol.PostQuantum
	}
	r, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: now}, kt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh("ig_init " + mode); err != nil {
		t.Fatal(err)
	}
	box := "/v1/" + r.Address().String()
	var phase atomic.Value
	phase.Store("down")
	posts, reads := 0, 0
	srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
		p := phase.Load()
		switch {
		case q.Method == http.MethodPost && q.URL.Path == box+"/messages" && p == "down":
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		case q.Method == http.MethodGet && q.URL.Path == box && p == "slow":
			reads++
			if reads == 1 {
				set(time.Duration(off.Load()) + 59*time.Second)
			}
		case q.Method == http.MethodPost && q.URL.Path == box+"/messages" && p == "slow":
			posts++
		}
		next.ServeHTTP(w, q)
	})
	body := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(body, []byte("pay invoice 13 once"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := sh("ig_send " + r.Address().String() + " " + body); err == nil {
		t.Fatalf("the post was taken: %q", out)
	}
	set(30 * day)
	if _, err := r.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	set(protocol.TTL - time.Hour)
	if _, err := sh("ig_rekey " + mode); err != nil {
		t.Fatal(err)
	}
	set(protocol.TTL) // the entry was written at base: the outbox's last second
	phase.Store("slow")
	out, err := sh("ig_flush")
	t.Logf("ig_flush at W+TTL, the box read answered after 59s: %q, %v; posts %d", out, err, posts)
	if posts != 0 || err == nil || !strings.Contains(err.Error(), "stale") {
		t.Error("the script posted an entry past its outbox's 33 days")
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
	mode, kt := "--no-pq", protocol.Classic
	if pq() {
		mode, kt = "", protocol.PostQuantum
	}
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if out, err := bash(t, env, "ig_init "+mode); err != nil {
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
