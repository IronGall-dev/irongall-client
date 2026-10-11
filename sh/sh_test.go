// Package sh_test runs crossbot.sh, the stock-tools client, from go test: its
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

	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/internal/fakeserver"
	"github.com/drewstreib/crossbot-client/protocol"
)

const vectors = "../testdata/vectors"

// need skips the test unless every tool is on PATH, saying which is missing.
func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH: crossbot.sh needs bash, age, ssh-keygen, curl, jq, iconv and coreutils", tool)
		}
	}
}

var scriptTools = []string{"bash", "age", "age-keygen", "ssh-keygen", "jq", "iconv", "sha256sum", "base64", "od", "sync"}

// pq reports whether the local age makes post-quantum keys (age >= 1.3).
func pq() bool { return exec.Command("age-keygen", "-pq", "-o", os.DevNull).Run() == nil }

func abs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// bash runs commands after sourcing crossbot.sh, with env added.
func bash(t *testing.T, env []string, commands string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", ". "+abs(t, "crossbot.sh")+"\n"+commands)
	cmd.Env = append(os.Environ(), env...)
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errs.String()))
	}
	return out.String(), err
}

// The forging-server test: crossbot.sh against test.sh's in-shell fake.
func TestScript(t *testing.T) {
	need(t, scriptTools...)
	out, err := exec.Command("bash", "test.sh", t.TempDir()).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte(" PASS, 0 FAIL")) {
		t.Fatalf("test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out[bytes.LastIndex(out, []byte("--- ")):])
}

// vectorNow is the vectors' now, as cb_now gives it.
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
	return now, fmt.Sprintf("cb_now(){ echo %d; }\n", now.Unix())
}

// signers writes box's allowed-signers line, as cb_pin does, and returns its
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
		if _, err := bash(t, nil, fmt.Sprintf("cb_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), a)); err != nil {
			t.Errorf("%s/identity.doc refused: %v", box, err)
		}
		if _, err := bash(t, nil, fmt.Sprintf("cb_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), strings.Repeat("0", 64))); err == nil {
			t.Errorf("%s/identity.doc accepted for another address", box)
		}
	}
	docs, _ := filepath.Glob(filepath.Join(vectors, "identity", "*.doc"))
	if len(docs) == 0 {
		t.Fatal("no identity vectors")
	}
	for _, d := range docs {
		if _, err := bash(t, nil, "cb_idcheck "+abs(t, d)); err == nil {
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
		out, err := bash(t, nil, setNow+fmt.Sprintf("cb_prekeycheck %s %s %s %s", abs(t, stmt), abs(t, sig), addr, signers))
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
	for _, c := range []struct{ stmt, sig, addr, signers, serial string }{
		{"a/prekey-1.txt", "a/prekey-1.txt.sig", a, aSigners, "1"},
		{"a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", a, aSigners, "1"},
		{"a/prekey-2.txt", "a/prekey-2.txt.sig", a, aSigners, "2"},
		{"b/prekey-1.txt", "b/prekey-1.txt.sig", b, bSigners, "1"},
	} {
		s, na, err := check(filepath.Join(vectors, c.stmt), filepath.Join(vectors, c.sig), c.addr, c.signers)
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
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case name == "expired": // valid, but no sender encrypts to it (cb_resolve)
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
		line, err := bash(t, nil, setNow+fmt.Sprintf("cb_envcheck %s %s %s && cb_line %s", abs(t, f), a, b, abs(t, f)))
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
	}
	shDir, goDir := t.TempDir(), t.TempDir()
	sh := func(dir, commands string) (string, error) {
		return bash(t, []string{"CROSSBOT_HOME=" + dir, "CB_BASE=" + srv.URL}, commands)
	}
	out, err := sh(shDir, "cb_init "+mode)
	if err != nil {
		t.Fatalf("cb_init: %v", err)
	}
	shLink := strings.TrimSpace(out)
	shAddr, err := protocol.ParseAddress(strings.TrimPrefix(shLink, srv.URL+protocol.LinkPath))
	if err != nil || shLink != srv.URL+protocol.LinkPath+shAddr.String() {
		t.Fatalf("cb_init printed %q, not the box's link", out)
	}
	g, err := client.Init(ctx, goDir, client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}

	// An API error prints its status, code and the server's detail.
	if _, err := sh(shDir, "printf x | cb_send "+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "ERROR 404 no_such_mailbox: no box has this address") {
		t.Fatalf("cb_send to no box: %v", err)
	}
	if _, err := sh(shDir, fmt.Sprintf("printf 'from the script' | cb_send %s", g.Link())); err != nil {
		t.Fatalf("cb_send: %v", err)
	}
	res, err := g.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"from the script"` {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	if _, err := g.Send(ctx, shAddr, "from Go"); err != nil {
		t.Fatal(err)
	}
	out, err = sh(shDir, "cb_recv")
	if err != nil || !strings.Contains(out, `"body":"from Go"`) {
		t.Fatalf("cb_recv: %q %v", out, err)
	}

	// The script renews the Go client's box, and both keep using it.
	if _, err := sh(goDir, "cb_rekey "+mode); err != nil {
		t.Fatalf("cb_rekey on the Go box: %v", err)
	}
	if _, err := sh(shDir, fmt.Sprintf("printf 'after the rekey' | cb_send %s", g.Address())); err != nil {
		t.Fatalf("cb_send after the rekey: %v", err)
	}
	out, err = sh(goDir, "cb_recv")
	if err != nil || !strings.Contains(out, `"body":"after the rekey"`) {
		t.Fatalf("cb_recv in the Go box: %q %v", out, err)
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
}
