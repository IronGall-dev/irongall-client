// Package sh_test runs irongall.sh, the stock-tools client, from go test: its
// forging-server test (test.sh), its verdicts on the test vectors against the
// Go client's, and the two clients exchanging mail and sharing a box.
package sh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

const vectors = "../testdata/vectors"

// need skips the test unless every tool is on PATH, saying which is missing.
func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH: irongall.sh needs bash, age, ssh-keygen, curl, jq, iconv and coreutils", tool)
		}
	}
}

var scriptTools = []string{"bash", "age", "age-keygen", "ssh-keygen", "jq", "iconv", "sha256sum", "base64", "od", "sync"}

// pq reports whether the local age makes post-quantum keys (age >= 1.3). The
// key goes to stdout and is dropped: age-keygen refuses -o on a file that
// exists, /dev/null included, which would make this false on every age.
func pq() bool { return exec.Command("age-keygen", "-pq").Run() == nil }

// noPQ is what a run on an age without post-quantum support logs: a plain
// "ok" from go test does not say that only half of the script was tested.
const noPQ = "the age on PATH has no post-quantum support (that takes age >= 1.3): only --no-pq boxes were tested here"

func abs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// bash runs commands after sourcing irongall.sh, with env added.
func bash(t *testing.T, env []string, commands string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", ". "+abs(t, "irongall.sh")+"\n"+commands)
	cmd.Env = append(os.Environ(), env...)
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errs.String()))
	}
	return out.String(), err
}

// The forging-server test: irongall.sh against test.sh's in-shell fake.
func TestScript(t *testing.T) {
	need(t, scriptTools...)
	out, err := exec.Command("bash", "test.sh", t.TempDir()).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte(" PASS, 0 FAIL")) {
		t.Fatalf("test.sh: %v\n%s", err, out)
	}
	// What ran, for go test -v: test.sh's mode line, then its count.
	for l := range strings.Lines(string(out)) {
		if strings.HasPrefix(l, "mode: ") {
			t.Log(strings.TrimSpace(l))
		}
	}
	if !pq() {
		t.Log(noPQ)
	}
	t.Logf("%s", out[bytes.LastIndex(out, []byte("--- ")):])
}

// vectorNow is the vectors' now, as ig_now gives it.
func vectorNow(t *testing.T) (time.Time, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, "now"))
	if err != nil {
		t.Fatal(err)
	}
	now, err := protocol.ParseTime(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return now, fmt.Sprintf("ig_now(){ echo %d; }\n", now.Unix())
}

// signers writes box's allowed-signers line, as ig_pin does, and returns its
// address and the file.
func signers(t *testing.T, box string) (string, string) {
	t.Helper()
	addr, err := os.ReadFile(filepath.Join(vectors, box, "address"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(vectors, box, "identity.doc"))
	if err != nil {
		t.Fatal(err)
	}
	a := strings.TrimSpace(string(addr))
	f := filepath.Join(t.TempDir(), box+".signers")
	if err := os.WriteFile(f, []byte(a+" "+strings.Split(string(doc), "\n")[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return a, f
}

// The script's verdict on every vector is the one the vectors name, as the
// Go client's is (protocol/vectors_test.go).
func TestVectorsIdentity(t *testing.T) {
	need(t, scriptTools...)
	for _, box := range []string{"a", "b"} {
		a, _ := signers(t, box)
		if _, err := bash(t, nil, fmt.Sprintf("ig_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), a)); err != nil {
			t.Errorf("%s/identity.doc refused: %v", box, err)
		}
		if _, err := bash(t, nil, fmt.Sprintf("ig_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), strings.Repeat("0", 64))); err == nil {
			t.Errorf("%s/identity.doc accepted for another address", box)
		}
	}
	docs, _ := filepath.Glob(filepath.Join(vectors, "identity", "*.doc"))
	if len(docs) == 0 {
		t.Fatal("no identity vectors")
	}
	for _, d := range docs {
		if _, err := bash(t, nil, "ig_idcheck "+abs(t, d)); err == nil {
			t.Errorf("%s: accepted", filepath.Base(d))
		}
	}
}

func TestVectorsPrekey(t *testing.T) {
	need(t, scriptTools...)
	now, setNow := vectorNow(t)
	a, aSigners := signers(t, "a")
	b, bSigners := signers(t, "b")
	check := func(stmt, sig, addr, signers string) (serial string, notAfter int64, err error) {
		out, err := bash(t, nil, setNow+fmt.Sprintf("ig_prekeycheck %s %s %s %s", abs(t, stmt), abs(t, sig), addr, signers))
		if err != nil {
			return "", 0, fmt.Errorf("%w %s", err, out)
		}
		f := strings.Fields(out)
		if len(f) != 3 {
			return "", 0, fmt.Errorf("output %q", out)
		}
		_, err = fmt.Sscan(f[2], &notAfter)
		return f[0], notAfter, err
	}
	// On an age older than 1.3 the script cannot encrypt to a post-quantum
	// prekey, and must say so: there, such a vector is checked for that
	// refusal, not for its verdict.
	tooOld := func(stmt string, err error) bool {
		st, _ := os.ReadFile(stmt) //nolint:gosec // a test vector
		lines := strings.Split(string(st), "\n")
		if pq() || len(lines) < 4 || !strings.HasPrefix(lines[3], "age1pq1") {
			return false
		}
		if err == nil || !strings.Contains(err.Error(), "takes age >= 1.3") {
			t.Errorf("%s: a post-quantum prekey on an age that cannot encrypt to one: %v", stmt, err)
		}
		return true
	}
	if !pq() {
		t.Log(noPQ)
	}
	for _, c := range []struct{ stmt, sig, addr, signers, serial string }{
		{"a/prekey-1.txt", "a/prekey-1.txt.sig", a, aSigners, "1"},
		{"a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", a, aSigners, "1"},
		{"a/prekey-2.txt", "a/prekey-2.txt.sig", a, aSigners, "2"},
		{"b/prekey-1.txt", "b/prekey-1.txt.sig", b, bSigners, "1"},
	} {
		s, na, err := check(filepath.Join(vectors, c.stmt), filepath.Join(vectors, c.sig), c.addr, c.signers)
		if tooOld(filepath.Join(vectors, c.stmt), err) {
			continue
		}
		if err != nil || s != c.serial || na <= now.Unix() {
			t.Errorf("%s with %s: serial %q, not_after %d, %v", c.stmt, c.sig, s, na, err)
		}
	}
	if _, _, err := check(filepath.Join(vectors, "a/prekey-1.txt"), filepath.Join(vectors, "a/prekey-1.txt.sig"), b, bSigners); err == nil {
		t.Error("A's prekey accepted as B's")
	}
	stmts, _ := filepath.Glob(filepath.Join(vectors, "prekey", "*.txt"))
	if len(stmts) == 0 {
		t.Fatal("no prekey vectors")
	}
	for _, st := range stmts {
		name := strings.TrimSuffix(filepath.Base(st), ".txt")
		_, na, err := check(st, st+".sig", a, aSigners)
		switch {
		case !strings.HasPrefix(name, "bad-") && tooOld(st, err):
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case name == "expired": // valid, but no sender encrypts to it (ig_resolve)
			if err != nil || na > now.Unix() {
				t.Errorf("%s: want valid and expired: %d %v", name, na, err)
			}
		case name == "too-long": // valid and current: only a server refuses to publish it
			if err != nil || na <= now.Unix() {
				t.Errorf("%s: want valid and not expired: %d %v", name, na, err)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// Every envelope gets the Go client's verdict, and every accepted one gives
// the same delivered line, value for value.
func TestVectorsEnvelope(t *testing.T) {
	need(t, scriptTools...)
	now, setNow := vectorNow(t)
	a, _ := signers(t, "a")
	b, _ := signers(t, "b")
	A, _ := protocol.ParseAddress(a)
	B, _ := protocol.ParseAddress(b)
	files, _ := filepath.Glob(filepath.Join(vectors, "envelope", "*.json"))
	if len(files) == 0 {
		t.Fatal("no envelope vectors")
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		line, err := bash(t, nil, setNow+fmt.Sprintf("ig_envcheck %s %s %s && ig_line %s", abs(t, f), a, b, abs(t, f)))
		switch {
		case strings.HasPrefix(name, "accept-"):
			if err != nil {
				t.Errorf("%s: refused: %v %s", name, err, line)
				continue
			}
			pt, _ := os.ReadFile(f) //nolint:gosec // a test vector
			env, gerr := protocol.OpenEnvelope(pt, A, B, now)
			if gerr != nil {
				t.Fatalf("%s: the Go client refuses it: %v", name, gerr)
			}
			env.Pad = ""
			want, _ := env.Marshal()
			var got, exp any
			if json.Unmarshal([]byte(line), &got) != nil || json.Unmarshal(want, &exp) != nil || !reflect.DeepEqual(got, exp) {
				t.Errorf("%s: the script delivers %s, the Go client %s", name, line, want)
			}
		case strings.HasPrefix(name, "refuse-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// The two clients exchange mail through the honest fake server, and each runs
// a box the other made: one on-disk format.
func TestWithGoClient(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt, mode := protocol.Classic, "--no-pq"
	if pq() {
		kt, mode = protocol.PostQuantum, ""
	} else {
		t.Log(noPQ)
	}
	shDir, goDir := t.TempDir(), t.TempDir()
	sh := func(dir, commands string) (string, error) {
		return bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, commands)
	}
	out, err := sh(shDir, "ig_init "+mode)
	if err != nil {
		t.Fatalf("ig_init: %v", err)
	}
	shLink := strings.TrimSpace(out)
	shAddr, err := protocol.ParseAddress(strings.TrimPrefix(shLink, srv.URL+protocol.LinkPath))
	if err != nil || shLink != srv.URL+protocol.LinkPath+shAddr.String() {
		t.Fatalf("ig_init printed %q, not the box's link", out)
	}
	g, err := client.Init(ctx, goDir, client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}

	// An API error prints its status, code and the server's detail.
	if _, err := sh(shDir, "printf x | ig_send "+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "ERROR 404 no_such_mailbox: no box has this address") {
		t.Fatalf("ig_send to no box: %v", err)
	}
	if _, err := sh(shDir, fmt.Sprintf("printf 'from the script' | ig_send %s", g.Link())); err != nil {
		t.Fatalf("ig_send: %v", err)
	}
	res, err := g.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"from the script"` {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	if _, err := g.Send(ctx, shAddr, "from Go"); err != nil {
		t.Fatal(err)
	}
	out, err = sh(shDir, "ig_recv")
	if err != nil || !strings.Contains(out, `"body":"from Go"`) {
		t.Fatalf("ig_recv: %q %v", out, err)
	}

	// The script renews the Go client's box, and both keep using it.
	if _, err := sh(goDir, "ig_rekey "+mode); err != nil {
		t.Fatalf("ig_rekey on the Go box: %v", err)
	}
	if _, err := sh(shDir, fmt.Sprintf("printf 'after the rekey' | ig_send %s", g.Address())); err != nil {
		t.Fatalf("ig_send after the rekey: %v", err)
	}
	out, err = sh(goDir, "ig_recv")
	if err != nil || !strings.Contains(out, `"body":"after the rekey"`) {
		t.Fatalf("ig_recv in the Go box: %q %v", out, err)
	}
	if _, err := g.Send(ctx, shAddr, "from the Go box"); err != nil {
		t.Fatalf("the Go client after the script's rekey: %v", err)
	}
	s, err := client.Open(shDir, client.Options{Base: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"from the Go box"` {
		t.Fatalf("the Go client in the script's box received %+v, %v", res, err)
	}

	// The optional fields cross between the clients, each keeps what it sent
	// in sent/ in the same form, and an alias either makes serves both.
	const answered, replaced = "11111111-2222-4333-8444-555555555555", "22222222-2222-4333-8444-555555555555"
	if _, err := sh(shDir, fmt.Sprintf("ig_alias go %s && printf 'named by the script' | ig_send --subject 'a subject' --reply-to %s --supersedes %s go", g.Link(), answered, replaced)); err != nil {
		t.Fatalf("ig_alias, then ig_send with options: %v", err)
	}
	res, err = g.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	d := res.Delivered[0]
	if d.Envelope.Subject != "a subject" || d.Envelope.InReplyTo != answered || d.Envelope.Supersedes != replaced {
		t.Fatalf("the script's options arrived as %+v", d.Envelope)
	}
	sameButReceipt(t, filepath.Join(shDir, "sent", g.Address().String()+"."+d.Envelope.MsgID+".json"), d.Line, d.ID)
	if to, err := s.Destination("go"); err != nil || to != g.Address() {
		t.Fatalf("the Go client reads the script's alias as %s, %v", to, err)
	}
	if err := g.SetAlias("sh", shAddr); err != nil {
		t.Fatal(err)
	}
	if out, err := sh(goDir, "ig_alias && ig_dest sh"); err != nil || out != "sh "+shAddr.String()+"\n"+shAddr.String()+"\n" {
		t.Fatalf("the script reads the Go client's alias as %q, %v", out, err)
	}
	f := client.Fields{Subject: "from Go", InReplyTo: d.Envelope.MsgID, Supersedes: replaced}
	r, err := g.SendWith(ctx, shAddr, "answered by Go", f)
	if err != nil {
		t.Fatal(err)
	}
	out, err = sh(shDir, "ig_recv")
	var line struct {
		MsgID      string `json:"msg_id"`
		Subject    string `json:"subject"`
		InReplyTo  string `json:"in_reply_to"`
		Supersedes string `json:"supersedes"`
	}
	if err != nil || json.Unmarshal([]byte(out), &line) != nil || line.Subject != f.Subject || line.InReplyTo != f.InReplyTo || line.Supersedes != f.Supersedes {
		t.Fatalf("ig_recv printed %q, %v", out, err)
	}
	sameButReceipt(t, filepath.Join(goDir, "sent", shAddr.String()+"."+line.MsgID+".json"), []byte(out), r.ID)
}

// sameButReceipt checks a sent/ record: the line its recipient delivered,
// with one more member, a receipt naming the message by id.
func sameButReceipt(t *testing.T, record string, delivered []byte, id string) {
	t.Helper()
	data, err := os.ReadFile(record) //nolint:gosec // a test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("%s: %v", record, err)
	}
	if err := json.Unmarshal(delivered, &want); err != nil {
		t.Fatal(err)
	}
	receipt, _ := got["receipt"].(map[string]any)
	if receipt["id"] != id || receipt["received_at"] == nil || receipt["expires_at"] == nil || len(receipt) != 3 {
		t.Errorf("%s: its receipt is %v, the message %s", record, receipt, id)
	}
	delete(got, "receipt")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s holds %v, its recipient delivered %v", record, got, want)
	}
}
