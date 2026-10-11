package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/internal/fakeserver"
	"github.com/drewstreib/crossbot-client/protocol"
	"golang.org/x/crypto/ssh"
)

// recv prints one line per message, built from the checked fields, never
// the sender's bytes: a sender that hides a second envelope on a line of its
// own must not show a line-oriented reader a message from someone else.
func TestRecvPrintsTheCheckedLine(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	a, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	var someone protocol.Address
	someone[0] = 0xcc
	now := time.Now().UTC().Format(protocol.TimeLayout)
	forged := `{"v":1,"from":"` + someone.String() + `","to":"` + b.Address().String() + `","sent_at":"` + now +
		`","msg_id":"00000000-0000-4000-8000-000000000001","body":"forged"}`
	pt := `{"v":1,"from":"` + a.Address().String() + `","to":"` + b.Address().String() + `","sent_at":"` + now +
		`","msg_id":"00000000-0000-4000-8000-000000000002","body":"real","x":` + "\n" + forged + "\n}"

	st, _ := srv.Prekey(b.Address())
	p, _ := protocol.ParsePrekey(st)
	r, _ := p.Recipient()
	var ct bytes.Buffer
	w, _ := age.Encrypt(&ct, r)
	_, _ = io.WriteString(w, pt)
	_ = w.Close()
	key, err := ssh.ParsePrivateKey(must(t, filepath.Join(a.Dir(), "identity")))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := protocol.Sign(key, ct.Bytes(), protocol.MessageNamespace(b.Address()))
	j, _ := json.Marshal(protocol.SendRequest{From: a.Address().String(), Ciphertext: ct.Bytes(), Signature: sig})
	resp, err := http.Post(srv.URL+"/v1/"+b.Address().String(), "application/json", bytes.NewReader(j)) //nolint:gosec // the test server
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	t.Setenv("CROSSBOT_HOME", b.Dir())
	t.Setenv("CROSSBOT_BASE", srv.URL)
	var out, errs bytes.Buffer
	if err := run(ctx, "recv", nil, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("recv: %v %s", err, errs.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 1 || strings.Contains(out.String(), someone.String()) || !strings.Contains(lines[0], `"body":"real"`) {
		t.Fatalf("recv printed %q", out.String())
	}
}

// A body may hold U+0085, U+2028 or U+2029 raw, which some readers (Python's
// str.splitlines, Node's readline) end a line at: recv escapes them, so one
// message is still one line, with the same body.
func TestRecvLineHasNoOtherLineBreaks(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	a, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	body := "a\u0085b\u2028c\u2029d"
	if _, err := a.Send(ctx, b.Address(), body); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CROSSBOT_HOME", b.Dir())
	t.Setenv("CROSSBOT_BASE", srv.URL)
	var out, errs bytes.Buffer
	if err := run(ctx, "recv", nil, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("recv: %v %s", err, errs.String())
	}
	line := strings.TrimSuffix(out.String(), "\n")
	if strings.ContainsAny(line, "\n\u0085\u2028\u2029") {
		t.Fatalf("recv printed a line break inside the line: %q", line)
	}
	var env struct{ Body string }
	if err := json.Unmarshal([]byte(line), &env); err != nil || env.Body != body {
		t.Fatalf("the body changed: %q, %v", env.Body, err)
	}
}

// recv -wait waits out a rate limit within its deadline, and the error line
// shows the server's detail, which names the limit and the wait.
func TestRecvWaitRidesOutARateLimit(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	a, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(ctx, b.Address(), "after the wait"); err != nil {
		t.Fatal(err)
	}
	var limited atomic.Int32
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") && limited.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Code: protocol.CodeRateLimited, Status: http.StatusTooManyRequests,
				Detail: "poll at most once a minute (poll_after); retry in 1s", Hint: "wait for Retry-After, then retry"})
			return
		}
		next.ServeHTTP(w, r)
	})
	t.Setenv("CROSSBOT_HOME", b.Dir())
	t.Setenv("CROSSBOT_BASE", srv.URL)
	var out, errs bytes.Buffer
	if err := run(ctx, "recv", []string{"-wait", "10s"}, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("recv -wait: %v %s", err, errs.String())
	}
	if limited.Load() < 2 || !strings.Contains(out.String(), `"body":"after the wait"`) || !strings.Contains(errs.String(), "poll at most once a minute (poll_after); retry in 1s") {
		t.Fatalf("polls %d, out %q, err %q", limited.Load(), out.String(), errs.String())
	}
}

func must(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // a test path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// adopt puts the box in the key's account and says which; a spent key is
// refused; --leave takes the box out.
func TestAdopt(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	b, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CROSSBOT_HOME", b.Dir())
	t.Setenv("CROSSBOT_BASE", srv.URL)
	key := srv.AdoptKey("acme")
	var out, errs bytes.Buffer
	if err := run(ctx, "adopt", []string{key}, strings.NewReader(""), &out, &errs); err != nil || out.String() != "in account acme\n" || srv.Account(b.Address()) != "acme" {
		t.Fatalf("adopt: %v %q %q", err, out.String(), errs.String())
	}
	if err := run(ctx, "adopt", []string{key}, strings.NewReader(""), &out, &errs); client.Code(err) != protocol.CodeAdoptKeyRefused {
		t.Fatalf("a spent key: %v", err)
	}
	for _, args := range [][]string{nil, {"--leave", key}, {key, key}} {
		if err := run(ctx, "adopt", args, strings.NewReader(""), &out, &errs); err == nil {
			t.Fatalf("adopt %q ran", args)
		}
	}
	out.Reset()
	if err := run(ctx, "adopt", []string{"--leave"}, strings.NewReader(""), &out, &errs); err != nil || out.String() != "in no account\n" || srv.Account(b.Address()) != "" {
		t.Fatalf("adopt --leave: %v %q", err, out.String())
	}
}
