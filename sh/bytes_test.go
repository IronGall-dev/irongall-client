package sh_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The script runs in the C locale, so its patterns and tools read bytes, as
// the Go client does (#65). Under en_US.UTF-8 a pattern's [0-9] takes a
// digit that is not ASCII, and under tr_TR.UTF-8 grep's [A-Z] misses I.
// TestPatternsReadBytes and the vectors of the two readers of text, envelopes
// and answers, run again under each, built with localedef, after a control
// shows the locale bites a bare shell: they hold the script's one LC_ALL line,
// and every vector run twice more held nothing more (#426 item 2).
func TestTheScriptReadsBytesInEveryLocale(t *testing.T) {
	t.Parallel()
	if os.Getenv("DR_TEST_LOCALE") != "" {
		t.Skip("already inside a locale")
	}
	need(t, append(scriptTools, "localedef", "grep")...)
	dir := t.TempDir()
	for _, loc := range []struct{ name, source, bites string }{
		{"en_US.UTF-8", "en_US", `[[ $'١' =~ ^[0-9]$ ]]`},
		{"tr_TR.UTF-8", "tr_TR", `! printf 'I\n' | grep -q '[A-Z]'`},
	} {
		if out, err := exec.Command("localedef", "-i", loc.source, "-f", "UTF-8", filepath.Join(dir, loc.name)).CombinedOutput(); err != nil {
			t.Skipf("localedef cannot build %s here: %v %s", loc.name, err, out)
		}
		env := append(os.Environ(), "LOCPATH="+dir, "LC_ALL="+loc.name, "DR_TEST_LOCALE="+loc.name)
		control := exec.Command("bash", "-c", loc.bites)
		control.Env = env
		if err := control.Run(); err != nil {
			t.Fatalf("control: %s does not bite a bare shell (%s), so this test would see nothing: %v", loc.name, loc.bites, err)
		}
		run := exec.Command(os.Args[0], "-test.count=1", "-test.run", "^(TestVectorsEnvelope|TestVectorsAnswer|TestPatternsReadBytes)$")
		run.Env = env
		out, err := run.CombinedOutput()
		if err != nil {
			t.Errorf("under %s: %v\n%s", loc.name, err, out)
		}
	}
}

// What the script reads by a pattern alone, held to bytes (#65): each is
// refused, on stdout and stderr with JSON lines only.
func TestPatternsReadBytes(t *testing.T) {
	t.Parallel()
	need(t, scriptTools...)
	if _, err := bash(t, nil, "dr_hex "+strings.Repeat("a", 63)+"١"); err == nil {
		t.Error("dr_hex takes a digit that is not ASCII")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "seen-floor"), []byte("1١\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := bash(t, []string{"DR_HOME=" + home}, "dr_floor"); err == nil {
		t.Errorf("dr_floor takes a floor of 1١: %q", out)
	}
	_, setNow := vectorNow(t)
	a, aDoc := identity(t, "a")
	st := filepath.Join(vectors, "prekey", "bad-serial-a-digit-not-ascii.txt")
	cmd := exec.Command("bash", "-c", ". "+abs(t, "dromas.sh")+"\n"+setNow+"dr_prekeycheck "+abs(t, st)+" "+abs(t, st+".sig")+" "+a+" "+aDoc)
	cmd.Env = append(os.Environ(), "DR_HOME="+t.TempDir())
	var errs strings.Builder
	cmd.Stderr = &errs
	if out, err := cmd.Output(); err == nil || !strings.Contains(string(out), "prekey serial is malformed") || errs.Len() != 0 {
		t.Errorf("a prekey serial with a digit that is not ASCII: %v %q, stderr %q", err, out, errs.String())
	}
}

// The box's own server answers a post with an honest receipt, one member
// ending in a line feed or a NUL (#187). Neither client takes it, and
// nothing goes to sent/: the script keeps nothing to post again.
func TestAReceiptIsComparedAsBytes(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	to, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, to)
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct{ member, suffix string }{{"id", ""}, {"id", "\n"}, {"id", "\x00"}, {"received_at", "\n"}, {"expires_at", "\n"}} {
		srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			var m map[string]any
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages") && rec.Code/100 == 2 && json.Unmarshal(body, &m) == nil {
				m[e.member] = m[e.member].(string) + e.suffix
				body, _ = json.Marshal(m)
				rec.Header().Del("Content-Length")
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(body)
		})
		_ = os.RemoveAll(filepath.Join(dir, "sent"))
		_, gerr := g.Send(ctx, to.Address(), "hi")
		out, serr := bash(t, env, "printf hi | dr_send "+to.Address().String())
		sent, _ := filepath.Glob(filepath.Join(dir, "sent", "*.json"))
		honest, want := e.suffix == "", 0
		if honest {
			want = 1
		}
		if (gerr == nil) != honest || (serr == nil) != honest || len(sent) != want || exists(filepath.Join(dir, "outbox")) {
			t.Errorf("%s ending in %q: the Go client %v; the script %v %q, sent/ %d", e.member, e.suffix, gerr, serr, out, len(sent))
		}
	}
}
