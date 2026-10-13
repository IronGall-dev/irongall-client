package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// recv prints one line per message, built from the checked fields, never
// the bytes that arrived: a second envelope hidden after the first one's
// signature must not show a line-oriented reader a message from someone else.
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
	c, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	someone := c.Address()
	// What a box encrypts is its envelope's one line, the signature over it,
	// then padding. Here A's is followed by a second, well-signed envelope
	// from someone else, where the padding goes: nothing after the first
	// signature is read.
	signed := func(from *client.Box, msgID, body string) []byte {
		env := &protocol.Envelope{From: from.Address(), To: b.Address(), SentAt: time.Now().UTC().Truncate(time.Second), MsgID: msgID,
			Identity: from.Identity().Document(), Body: []byte(`"` + body + `"`)}
		work, err := ssh.ParsePrivateKey(must(t, filepath.Join(from.Dir(), "work", "1")))
		if err != nil {
			t.Fatal(err)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(must(t, filepath.Join(from.Dir(), "work", "1-cert.pub")))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewCertSigner(key.(*ssh.Certificate), work)
		if err != nil {
			t.Fatal(err)
		}
		line, sig, err := protocol.SignEnvelope(env, signer)
		if err != nil {
			t.Fatal(err)
		}
		return append(line, sig...)
	}
	pt := append(signed(a, "00000000-0000-4000-8000-000000000002", "real"), signed(c, "00000000-0000-4000-8000-000000000001", "forged")...)

	st, _ := srv.Prekey(b.Address())
	p, _ := protocol.ParsePrekey(st)
	r, _ := p.Recipient()
	var ct bytes.Buffer
	w, _ := age.Encrypt(&ct, r)
	_, _ = w.Write(pt)
	_ = w.Close()
	h := sha256.Sum256(ct.Bytes())
	srv.Inject(b.Address(), hex.EncodeToString(h[:]), a.Address(), ct.Bytes())

	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
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
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
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

// recv --wait waits out a rate limit within its deadline, and the error line
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
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
	var out, errs bytes.Buffer
	if err := run(ctx, "recv", []string{"--wait", "10s"}, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("recv --wait: %v %s", err, errs.String())
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
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
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

// The echo box's address is an address, and the help and the README both
// give its link: the one constant is what they publish.
func TestHelpAndREADMENameTheEchoBox(t *testing.T) {
	if _, err := protocol.ParseAddress(client.EchoAddress); err != nil {
		t.Fatal(err)
	}
	link := client.DefaultBase + "/to/" + client.EchoAddress
	var out bytes.Buffer
	if err := run(context.Background(), "help", nil, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), link+"\n") {
		t.Error("the help does not give the echo box's link")
	}
	if !strings.HasSuffix(out.String(), "https://github.com/IronGall-dev/irongall-client#readme\n") {
		t.Error("the help does not end by saying where the README is")
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "irongall send "+link+"\n") {
		t.Error("the README does not give the echo box's link")
	}
	// The second echo box, for age 1.2, is the stock script's: the README
	// gives its link, and the help, which is this client's, does not need it.
	if _, err := protocol.ParseAddress(client.EchoAddressNoPQ); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "irongall.sh send "+client.DefaultBase+"/to/"+client.EchoAddressNoPQ+"\n") {
		t.Error("the README does not give the no-pq echo box's link")
	}
}

// init and addr print the box's link; send takes a link to its own server or
// a bare address, and refuses a link to another server, or anything else,
// before it makes any mail.
func TestTheLink(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	home := t.TempDir()
	t.Setenv("IRONGALL_HOME", home)
	t.Setenv("IRONGALL_BASE", srv.URL)
	var out bytes.Buffer
	if err := run(ctx, "init", []string{"--no-pq"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	a, err := client.Open(home, opt)
	if err != nil {
		t.Fatal(err)
	}
	link := srv.URL + "/to/" + a.Address().String()
	if out.String() != link+"\n" {
		t.Fatalf("init printed %q, not %q", out.String(), link)
	}
	out.Reset()
	if err := run(ctx, "addr", nil, nil, &out, io.Discard); err != nil || out.String() != link+"\n" {
		t.Fatalf("addr: %v %q", err, out.String())
	}
	b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{b.Link(), b.Address().String()} {
		if err := run(ctx, "send", []string{to}, strings.NewReader("to "+to), io.Discard, io.Discard); err != nil {
			t.Fatalf("send %s: %v", to, err)
		}
	}
	if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 2 {
		t.Fatalf("receive: %v %+v", err, res)
	}
	for to, want := range map[string]string{
		"https://elsewhere.example/to/" + b.Address().String(): "a link to another server: this box's server is " + srv.URL,
		srv.URL + ".example/to/" + b.Address().String():        "a link to another server",
		b.Link() + "/":                          "not an address, a link to one, or an alias",
		srv.URL + "/v1/" + b.Address().String(): "not an address, a link to one, or an alias",
		strings.ToUpper(b.Address().String()):   "not an address, a link to one, or an alias",
	} {
		err := run(ctx, "send", []string{to}, strings.NewReader("x"), io.Discard, io.Discard)
		var r *client.RefusedError
		if !errors.As(err, &r) || !strings.Contains(r.Reason, want) {
			t.Errorf("send %s: %v, want %q", to, err, want)
		}
	}
	if made, _ := filepath.Glob(filepath.Join(home, "outbox", "*.P")); len(made) != 0 {
		t.Fatalf("a refused destination left mail in the outbox: %v", made)
	}
}

// recv says when the prekey was due for renewal and the renewal failed, on
// stderr and by its exit status, and still prints the mail it received.
func TestRecvSaysARenewalFailed(t *testing.T) {
	ctx := context.Background()
	// The box is made 25 hours ago, by a clock the server shares: a pass is
	// good for minutes, so a box and its server cannot be a day apart.
	var ago atomic.Int64
	ago.Store(int64(25 * time.Hour))
	clock := func() time.Time { return time.Now().Add(-time.Duration(ago.Load())) }
	srv := fakeserver.New(t, clock)
	b, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, Now: clock}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	ago.Store(0)
	a, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(ctx, b.Address(), "while the renewal fails"); err != nil {
		t.Fatal(err)
	}
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
	var out, errs bytes.Buffer
	var look *needsALook
	if err := run(ctx, "recv", nil, nil, &out, &errs); !errors.As(err, &look) || !strings.Contains(look.why, "the prekey was not renewed") {
		t.Fatalf("a failed renewal must give exit status 3, not %v", err)
	}
	if !strings.Contains(errs.String(), "due for renewal and was not renewed") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout %q, stderr %q", out.String(), errs.String())
	}
	// status says so too, from the box's files, to a wrapper that kept
	// neither recv's stderr nor its exit status.
	out.Reset()
	if err := run(ctx, "status", nil, nil, &out, io.Discard); !errors.As(err, &look) {
		t.Fatalf("status after a failed renewal: %v", err)
	}
	var st client.Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil || st.RenewalPendingSince == "" || len(st.Attention) != 1 || !strings.Contains(st.Attention[0], "was never seen published") {
		t.Fatalf("status printed %q: %v", out.String(), err)
	}
	// Once the server takes the renewal, recv and status are quiet again.
	srv.SetMiddle(nil)
	out.Reset()
	if err := run(ctx, "recv", nil, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("recv after the server came back: %v", err)
	}
	if err := run(ctx, "status", nil, nil, &out, io.Discard); err != nil || !strings.Contains(out.String(), `"attention":[]`) || strings.Contains(out.String(), "renewal_pending_since") {
		t.Fatalf("status after the renewal went through: %v %q", err, out.String())
	}
}

// A refused message is told on stderr and kept in quarantine/, and does not
// change recv's exit status: any sender can cause one, so a stranger must not
// be able to make a box's recv fail. status is what reports it.
func TestRefusedMailDoesNotFailRecv(t *testing.T) {
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
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
	var out bytes.Buffer
	if err := run(ctx, "status", nil, nil, &out, io.Discard); err != nil || !strings.Contains(out.String(), `"quarantine":0,"attention":[]`) {
		t.Fatalf("status of a new box: %v %q", err, out.String())
	}
	forged := []byte("not a ciphertext its claimed sender ever signed")
	h := sha256.Sum256(forged)
	srv.Inject(b.Address(), hex.EncodeToString(h[:]), a.Address(), forged)
	var errs bytes.Buffer
	out.Reset()
	if err := run(ctx, "recv", nil, nil, &out, &errs); err != nil {
		t.Fatalf("recv after refusing mail: %v", err)
	}
	if out.Len() != 0 || !strings.HasPrefix(errs.String(), "REFUSED "+hex.EncodeToString(h[:])+": undecryptable: it does not decrypt with this box's prekeys\n") {
		t.Fatalf("stdout %q, stderr %q", out.String(), errs.String())
	}
	var look *needsALook
	if err := run(ctx, "status", nil, nil, &out, io.Discard); !errors.As(err, &look) {
		t.Fatalf("status with mail in quarantine/: %v", err)
	}
	var st client.Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil || st.Quarantine != 1 || len(st.Attention) != 1 || !strings.Contains(st.Attention[0], "1 refused in quarantine/ (undecryptable)") {
		t.Fatalf("status printed %q: %v", out.String(), err)
	}
}

// send's flags set the envelope's optional fields, and the recipient's recv
// prints them. A --reply-to that is not a msg_id, or a flag after the link,
// is refused before any mail is made.
func TestSendFlags(t *testing.T) {
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
	t.Setenv("IRONGALL_BASE", srv.URL)
	t.Setenv("IRONGALL_HOME", a.Dir())
	const first, old = "11111111-2222-4333-8444-555555555555", "22222222-2222-4333-8444-555555555555"
	var id bytes.Buffer
	args := []string{"--subject", "re: yours", "--reply-to", first, "--supersedes", old, b.Link()}
	if err := run(ctx, "send", args, strings.NewReader("the answer"), &id, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--reply-to", strings.TrimSpace(id.String()), b.Link()},
		{b.Link(), "--subject", "after the link"},
		{"--urgent", b.Link()},
	} {
		if err := run(ctx, "send", args, strings.NewReader("refused"), io.Discard, io.Discard); err == nil {
			t.Errorf("send %v was taken", args)
		}
	}
	if made, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P")); len(made) != 0 {
		t.Fatalf("a refused send left mail in the outbox: %v", made)
	}

	// sent/ keeps it, with the receipt whose id send printed.
	recs, _ := filepath.Glob(filepath.Join(a.Dir(), "sent", b.Address().String()+".*.json"))
	if len(recs) != 1 {
		t.Fatalf("sent/ holds %v", recs)
	}
	var rec struct {
		Body    string
		Subject string
		Receipt protocol.Receipt
	}
	if err := json.Unmarshal(must(t, recs[0]), &rec); err != nil || rec.Body != "the answer" || rec.Subject != "re: yours" || rec.Receipt.ID+"\n" != id.String() {
		t.Fatalf("the record: %+v, %v; send printed %q", rec, err, id.String())
	}

	t.Setenv("IRONGALL_HOME", b.Dir())
	var out, errs bytes.Buffer
	if err := run(ctx, "recv", nil, strings.NewReader(""), &out, &errs); err != nil {
		t.Fatalf("recv: %v %s", err, errs.String())
	}
	var line struct {
		Body       string `json:"body"`
		Subject    string `json:"subject"`
		InReplyTo  string `json:"in_reply_to"`
		Supersedes string `json:"supersedes"`
	}
	if err := json.Unmarshal(out.Bytes(), &line); err != nil || line.Body != "the answer" || line.Subject != "re: yours" || line.InReplyTo != first || line.Supersedes != old {
		t.Fatalf("recv printed %q: %v", out.String(), err)
	}
}

// alias names a peer for this box, lists the names and removes one, and send
// takes a name where it takes a link.
func TestAliasCommand(t *testing.T) {
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
	c, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("IRONGALL_BASE", srv.URL)
	t.Setenv("IRONGALL_HOME", a.Dir())
	cmd := func(name string, args ...string) (string, error) {
		var out bytes.Buffer
		err := run(ctx, name, args, strings.NewReader("to a name"), &out, io.Discard)
		return out.String(), err
	}
	bob, zed := "bob "+b.Address().String()+"\n", "zed "+c.Address().String()+"\n"
	if out, err := cmd("alias", "zed", c.Address().String()); err != nil || out != zed {
		t.Fatalf("alias zed: %q %v", out, err)
	}
	if out, err := cmd("alias", "bob", b.Link()); err != nil || out != bob {
		t.Fatalf("alias bob: %q %v", out, err)
	}
	if out, err := cmd("alias"); err != nil || out != bob+zed {
		t.Fatalf("alias printed %q, %v", out, err)
	}
	if _, err := cmd("send", "bob"); err != nil {
		t.Fatalf("send bob: %v", err)
	}
	if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 1 {
		t.Fatalf("bob received %+v, %v", res, err)
	}
	if res, err := c.Receive(ctx); err != nil || len(res.Delivered) != 0 {
		t.Fatalf("zed received %+v, %v", res, err)
	}
	// Swapped arguments are told what an alias is; a name is never moved; a
	// name nobody made is no destination.
	for want, args := range map[string][]string{
		"not an alias":  {b.Link(), "bob"},
		"already names": {"bob", c.Link()},
		"usage":         {"bob"},
	} {
		if _, err := cmd("alias", args...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("alias %v: %v, want %q", args, err, want)
		}
	}
	if _, err := cmd("send", "carol"); err == nil || !strings.Contains(err.Error(), "no alias named carol") {
		t.Errorf("send carol: %v", err)
	}
	if _, err := cmd("alias", "--rm", "bob"); err != nil {
		t.Fatalf("alias --rm: %v", err)
	}
	if out, err := cmd("alias"); err != nil || out != zed {
		t.Fatalf("after --rm, alias printed %q, %v", out, err)
	}
	if _, err := cmd("send", "bob"); err == nil {
		t.Fatal("sent to a removed alias")
	}
	if made, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P")); len(made) != 0 {
		t.Fatalf("a refused destination left mail in the outbox: %v", made)
	}
}

// Flags are written with two dashes: in the help, in a command's own flag
// list and in a bad flag's error. One dash is taken too, as the same flag.
func TestFlagsAreWrittenWithTwoDashes(t *testing.T) {
	ctx := context.Background()
	t.Setenv("IRONGALL_HOME", t.TempDir())
	oneDash := regexp.MustCompile(`(^|[\s\[(])-[a-z]`)
	var help bytes.Buffer
	if err := run(ctx, "help", nil, nil, &help, io.Discard); err != nil {
		t.Fatal(err)
	}
	if m := oneDash.FindString(help.String()); m != "" || !strings.Contains(help.String(), "--wait") || !strings.Contains(help.String(), "--reply-to") {
		t.Errorf("the help writes a flag with one dash (%q), or lacks one:\n%s", m, help.String())
	}
	for _, h := range []string{"-h", "--help"} {
		var errs bytes.Buffer
		err := run(ctx, "send", []string{h}, nil, io.Discard, &errs)
		if !errors.Is(err, flag.ErrHelp) || oneDash.MatchString(errs.String()) {
			t.Errorf("send %s: %v\n%s", h, err, errs.String())
		}
		for _, want := range []string{"--subject <text>", "--reply-to <msg_id>", "--supersedes <msg_id>"} {
			if !strings.Contains(errs.String(), want) {
				t.Errorf("send %s does not list %s:\n%s", h, want, errs.String())
			}
		}
	}
	for args, want := range map[string]string{
		"send -urgent x":  "flag provided but not defined: --urgent",
		"send --urgent x": "flag provided but not defined: --urgent",
		"send -subject":   "flag needs an argument: --subject",
		"recv -wait soon": `for flag --wait`,
		"adopt -leave=x":  "for --leave",
	} {
		f := strings.Fields(args)
		var errs bytes.Buffer
		err := run(ctx, f[0], f[1:], strings.NewReader(""), io.Discard, &errs)
		if err == nil || !strings.Contains(err.Error(), want) || errs.Len() != 0 {
			t.Errorf("%s: %v (and on stderr %q), want %q once", args, err, errs.String(), want)
		}
	}
}
