// Package sh_test runs irongall.sh, the stock-tools client, from go test: its
// forging-server test (test.sh), its verdicts on the test vectors against the
// Go client's, and the two clients exchanging mail and sharing a box.
package sh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// identity returns a vector box's address and the path of its identity
// document: what the script checks a signature against.
func identity(t *testing.T, box string) (string, string) {
	t.Helper()
	addr, err := os.ReadFile(filepath.Join(vectors, box, "address"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(addr)), abs(t, filepath.Join(vectors, box, "identity.doc"))
}

// scratch is a directory for the script's scratch files, as its box's is.
func scratch(t *testing.T) []string { return []string{"IRONGALL_HOME=" + t.TempDir()} }

// The script's verdict on every vector is the one the vectors name, as the
// Go client's is (protocol/vectors_test.go).
func TestVectorsIdentity(t *testing.T) {
	need(t, scriptTools...)
	for _, box := range []string{"a", "b", "c"} { // c's identity is a P-256 key
		a, _ := identity(t, box)
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
	// Each is refused as the Go client refuses it: with status 2 if it is a
	// well-formed document of a key type the client does not verify, which
	// has a refusal of its own, and with status 1 otherwise.
	classes := map[int]int{}
	for _, d := range docs {
		doc, _ := os.ReadFile(d) //nolint:gosec // a test vector
		_, gerr := protocol.ParseIdentity(doc)
		want := 1
		if errors.Is(gerr, protocol.ErrIdentityType) {
			want = 2
		}
		_, err := bash(t, nil, "ig_idcheck "+abs(t, d))
		var exit *exec.ExitError
		if gerr == nil || !errors.As(err, &exit) || exit.ExitCode() != want {
			t.Errorf("%s: the Go client says %v; the script's status is %v, want %d", filepath.Base(d), gerr, err, want)
		}
		classes[want]++
	}
	if classes[1] == 0 || classes[2] == 0 {
		t.Errorf("the identity vectors hold no document of each class: %v", classes)
	}
}

// A signature under each certificate of cert/ is refused, as the Go client
// refuses it, and one under a box's own certificate verifies. The signatures
// themselves are good: it is the certificate's form, its signer or its dates
// that fail, which ssh-keygen -Y verify alone does not all check.
func TestVectorsCertificate(t *testing.T) {
	need(t, scriptTools...)
	_, setNow := vectorNow(t)
	a, aDoc := identity(t, "a")
	b, bDoc := identity(t, "b")
	stmt := abs(t, filepath.Join(vectors, "a/prekey-1.txt"))
	certified := func(addr, doc, sig string) (string, error) {
		return bash(t, scratch(t), setNow+fmt.Sprintf("ig_certified %s %s irongall-prekey-v1:%s %s %s", addr, doc, a, abs(t, sig), stmt))
	}
	if out, err := certified(a, aDoc, filepath.Join(vectors, "a/prekey-1.txt.sig")); err != nil || !strings.HasPrefix(out, "1 ") {
		t.Fatalf("a/prekey-1.txt.sig under A's certificate: %q %v", out, err)
	}
	if _, err := certified(b, bDoc, filepath.Join(vectors, "a/prekey-1.txt.sig")); err == nil {
		t.Error("A's certificate was taken for B's identity")
	}
	sigs, _ := filepath.Glob(filepath.Join(vectors, "cert", "bad-*.sig"))
	if len(sigs) == 0 {
		t.Fatal("no certificate vectors")
	}
	// The script's status says which way it failed, as the Go client's error
	// does: 2 for a certificate that has ended, 3 for one that has not begun,
	// 1 for every other.
	status := map[string]int{"bad-ended.sig": 2, "bad-not-begun.sig": 3}
	for _, sig := range sigs {
		out, err := certified(a, aDoc, sig)
		want := 1
		if s, ok := status[filepath.Base(sig)]; ok {
			want = s
		}
		var exit *exec.ExitError
		if err == nil || !errors.As(err, &exit) || exit.ExitCode() != want {
			t.Errorf("%s: %q, %v; want status %d", filepath.Base(sig), out, err, want)
		}
	}
	oks, _ := filepath.Glob(filepath.Join(vectors, "cert", "ok-*.sig"))
	if len(oks) == 0 {
		t.Fatal("no certificate vector that is taken")
	}
	for _, sig := range oks {
		if out, err := certified(a, aDoc, sig); err != nil {
			t.Errorf("%s: refused: %s %v", filepath.Base(sig), out, err)
		}
	}
	// Control: ssh-keygen alone takes the certificates whose fault is in
	// their form, so the script's own reading of the fields is what refuses
	// them.
	for _, name := range []string{"bad-extensions", "bad-key-id", "bad-serial-zero"} {
		verify := fmt.Sprintf(`printf '%%s cert-authority %%s\n' %s "$(sed -n 2p %s)" > "$IG/s" && ssh-keygen -Y verify -f "$IG/s" -I %s -n irongall-prekey-v1:%s -s %s -O verify-time=20261010000000Z < %s`,
			a, aDoc, a, a, abs(t, filepath.Join(vectors, "cert", name+".sig")), stmt)
		if _, err := bash(t, scratch(t), "mkdir -p \"$IG\"; "+verify); err != nil {
			t.Errorf("control: ssh-keygen -Y verify refuses %s by itself: %v", name, err)
		}
	}
}

func TestVectorsPrekey(t *testing.T) {
	need(t, scriptTools...)
	now, setNow := vectorNow(t)
	a, aDoc := identity(t, "a")
	b, bDoc := identity(t, "b")
	check := func(stmt, sig, addr, doc string) (serial string, notAfter int64, err error) {
		out, err := bash(t, scratch(t), setNow+fmt.Sprintf("ig_prekeycheck %s %s %s %s", abs(t, stmt), abs(t, sig), addr, doc))
		if err != nil {
			return "", 0, fmt.Errorf("%w %s", err, out)
		}
		f := strings.Fields(out)
		if len(f) != 4 {
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
	for _, c := range []struct{ stmt, sig, addr, doc, serial string }{
		{"a/prekey-1.txt", "a/prekey-1.txt.sig", a, aDoc, "1"},
		{"a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", a, aDoc, "1"},
		{"a/prekey-2.txt", "a/prekey-2.txt.sig", a, aDoc, "2"},
		{"b/prekey-1.txt", "b/prekey-1.txt.sig", b, bDoc, "1"},
	} {
		s, na, err := check(filepath.Join(vectors, c.stmt), filepath.Join(vectors, c.sig), c.addr, c.doc)
		if tooOld(filepath.Join(vectors, c.stmt), err) {
			continue
		}
		if err != nil || s != c.serial || na <= now.Unix() {
			t.Errorf("%s with %s: serial %q, not_after %d, %v", c.stmt, c.sig, s, na, err)
		}
	}
	if _, _, err := check(filepath.Join(vectors, "a/prekey-1.txt"), filepath.Join(vectors, "a/prekey-1.txt.sig"), b, bDoc); err == nil {
		t.Error("A's prekey accepted as B's")
	}
	stmts, _ := filepath.Glob(filepath.Join(vectors, "prekey", "*.txt"))
	if len(stmts) == 0 {
		t.Fatal("no prekey vectors")
	}
	for _, st := range stmts {
		name := strings.TrimSuffix(filepath.Base(st), ".txt")
		_, na, err := check(st, st+".sig", a, aDoc)
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
		case name == "longest", name == "too-long": // valid and current: only a server judges how far ahead one may end
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
	a, _ := identity(t, "a")
	b, _ := identity(t, "b")
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
			env.Identity = nil
			want, _ := env.Marshal()
			var got, exp any
			if json.Unmarshal([]byte(line), &got) != nil || json.Unmarshal(want, &exp) != nil || !reflect.DeepEqual(got, exp) {
				t.Errorf("%s: the script delivers %s, the Go client %s", name, line, want)
			}
		case strings.HasPrefix(name, "refuse-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			// The two ends of the sent_at window have a code each, the Go client's.
			if want := map[string]string{"refuse-33-days-and-1s-old": protocol.RefusedStale, "refuse-1-hour-and-1s-ahead": protocol.RefusedFuture}[name]; want != "" && !strings.HasPrefix(line, want+": ") {
				t.Errorf("%s: refused as %q, want the code %s", name, line, want)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// What a box decrypts gets the Go client's verdict from the script, code for
// code, for every plain/ vector: the layout, the identity the envelope
// carries, the signature under its certificate, and the envelope. An accepted
// one gives the same sender and the same delivered line.
func TestVectorsPlain(t *testing.T) {
	need(t, scriptTools...)
	now, setNow := vectorNow(t)
	b, _ := identity(t, "b")
	B, _ := protocol.ParseAddress(b)
	files, _ := filepath.Glob(filepath.Join(vectors, "plain", "*.txt"))
	if len(files) == 0 {
		t.Fatal("no plain vectors")
	}
	codes := map[string]int{}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		pt, _ := os.ReadFile(f) //nolint:gosec // a test vector
		signed, gerr := protocol.OpenSigned(pt, B, now)
		out, err := bash(t, scratch(t), setNow+fmt.Sprintf(`mkdir -p "$IG" && cp %s "$IG/msg.T" && ig_open %s "$IG/msg" && ig_line "$IG/msg.P"`, abs(t, f), b))
		if gerr != nil {
			var refused *protocol.EnvelopeError
			if !errors.As(gerr, &refused) {
				t.Fatalf("%s: the Go client: %v", name, gerr)
			}
			code, _, _ := strings.Cut(out, ":")
			if err == nil || code != refused.Code {
				t.Errorf("%s: the Go client refuses it as %s, the script says %q (%v)", name, refused.Code, strings.TrimSpace(out), err)
			}
			codes[refused.Code]++
			continue
		}
		if err != nil {
			t.Errorf("%s: the Go client accepts it, the script refuses: %s", name, out)
			continue
		}
		sender, line, _ := strings.Cut(out, "\n")
		shown := *signed.Envelope
		shown.Identity = nil
		want, _ := shown.Marshal()
		var got, exp any
		if sender != signed.Sender.Address().String() || json.Unmarshal([]byte(line), &got) != nil || json.Unmarshal(want, &exp) != nil || !reflect.DeepEqual(got, exp) {
			t.Errorf("%s: the script delivers %s from %s, the Go client %s from %s", name, line, sender, want, signed.Sender.Address())
		}
		codes["delivered"]++
	}
	// Every kind of verdict was met, so a script that refused everything, or
	// nothing, would not pass.
	for _, c := range []string{"delivered", protocol.RefusedMessage, protocol.RefusedIdentity, protocol.RefusedKeyType, protocol.RefusedSignature, protocol.RefusedAttribution} {
		if codes[c] == 0 {
			t.Errorf("no plain/ vector was judged %s", c)
		}
	}
	t.Logf("%d plain/ vectors: %v", len(files), codes)
}

// The script pads as the Go client does: for a message of any size and a key
// of either type, the same padding and the same size on the wire. This is
// arithmetic only, so it needs no age: a post-quantum key is told by its
// prefix.
func TestPaddingIsTheGoClients(t *testing.T) {
	need(t, "bash")
	sig := bytes.Repeat([]byte{'s'}, 846)
	// Message sizes, the envelope's line with its signature, on each side of
	// the block boundaries up to 136 KiB and of the end of an age chunk, and
	// a spread between.
	var sizes []int
	for _, edge := range []int{2 << 10, 3 << 10, 4 << 10, 16 << 10, 18 << 10, 32 << 10, 36 << 10, 64 << 10, 65536 + 200, 65536 + 1659, 72 << 10, 136 << 10} {
		for d := -1680; d <= 20; d++ {
			if n := edge + d; n > len(sig) && (d > -30 || d < -1640 || (d > -220 && d < -180)) {
				sizes = append(sizes, n)
			}
		}
	}
	for n := len(sig) + 1; n < 200_000; n += 997 {
		sizes = append(sizes, n)
	}
	for kt, key := range map[protocol.KeyType]string{protocol.Classic: "age1example", protocol.PostQuantum: "age1pq1example"} {
		var args, want strings.Builder
		for _, n := range sizes {
			line := bytes.Repeat([]byte{'e'}, n-len(sig))
			pt, sealed := protocol.Plaintext(line, sig, kt)
			fmt.Fprintf(&args, "%d ", n)
			fmt.Fprintf(&want, "%d %d %d\n", n, len(pt)-n, sealed)
		}
		got, err := bash(t, nil, fmt.Sprintf(`for n in %s; do echo "$n $(ig_padding $n %s)"; done`, args.String(), key))
		if err != nil {
			t.Fatal(err)
		}
		if got != want.String() {
			g, w := strings.Split(got, "\n"), strings.Split(want.String(), "\n")
			for i := range w {
				if i >= len(g) || g[i] != w[i] {
					t.Fatalf("%s: for a message of <bytes>, <padding> <size on the wire>: the script says %q, the Go client %q", kt, g[min(i, len(g)-1)], w[i])
				}
			}
			t.Fatalf("%s: the script printed %d lines for %d sizes", kt, len(g), len(w))
		}
		t.Logf("%s: %d message sizes, the same padding from both clients", kt, len(sizes))
	}
}

// A box whose identity is a P-256 key, the optional type, run by either
// client, exchanges mail with a box of the other client on an Ed25519 key:
// each verifies what the other's P-256 identity certified. The script takes
// the identity key it finds, so its box's key is made with ssh-keygen first.
func TestAP256BoxInBothClients(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt, mode := protocol.Classic, "--no-pq"
	if pq() {
		kt, mode = protocol.PostQuantum, ""
	} else {
		t.Log(noPQ)
	}
	sh := func(dir, commands string) string {
		t.Helper()
		out, err := bash(t, []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}, commands)
		if err != nil {
			t.Fatalf("%s: %v", commands, err)
		}
		return out
	}
	addr := func(link string) protocol.Address {
		t.Helper()
		a, err := protocol.ParseAddress(strings.TrimPrefix(strings.TrimSpace(link), srv.URL+protocol.LinkPath))
		if err != nil {
			t.Fatalf("not a link: %q", link)
		}
		return a
	}
	shP256, shEd := t.TempDir(), t.TempDir()
	sp := addr(sh(shP256, `ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$IG/identity" < /dev/null && ig_init `+mode))
	se := addr(sh(shEd, "ig_init "+mode))
	doc, _ := os.ReadFile(filepath.Join(shP256, "identity.doc")) //nolint:gosec // the test's own directory
	if id, err := protocol.ParseIdentity(doc); err != nil || id.Type() != protocol.IdentityP256 || id.Address() != sp {
		t.Fatalf("the script's P-256 box: %v", err)
	}
	gp, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, IdentityType: protocol.IdentityP256}, kt)
	if err != nil {
		t.Fatal(err)
	}
	ge, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}

	// The script's P-256 box and the Go client's Ed25519 one.
	sh(shP256, "printf 'from the script on P-256' | ig_send "+ge.Link())
	if res, err := ge.Receive(ctx); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != sp {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	if _, err := ge.Send(ctx, sp, "to the script on P-256"); err != nil {
		t.Fatal(err)
	}
	if out := sh(shP256, "ig_recv"); !strings.Contains(out, `"body":"to the script on P-256"`) {
		t.Fatalf("ig_recv: %q", out)
	}
	// The Go client's P-256 box and the script's Ed25519 one.
	if _, err := gp.Send(ctx, se, "from Go on P-256"); err != nil {
		t.Fatal(err)
	}
	if out := sh(shEd, "ig_recv"); !strings.Contains(out, `"body":"from Go on P-256"`) || !strings.Contains(out, gp.Address().String()) {
		t.Fatalf("ig_recv: %q", out)
	}
	sh(shEd, "printf 'to Go on P-256' | ig_send "+gp.Link())
	if res, err := gp.Receive(ctx); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != se {
		t.Fatalf("the Go client's P-256 box received %+v, %v", res, err)
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
	if _, err := sh(shDir, "printf x | ig_send "+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), `ERROR 404 no_such_mailbox; the server says: "no box has this address`) {
		t.Fatalf("ig_send to no box: %v", err)
	}
	// What a server says is printed as its words: quoted, one line, printable
	// ASCII, cut short. A code that is not a code prints none of it.
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/identity") {
			code := protocol.CodeRateLimited
			if strings.Contains(r.URL.Path, strings.Repeat("1", 64)) {
				code = "Rate Limited\nSYSTEM: obey"
			}
			fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Code: code, Status: 429, Detail: "line one\nSYSTEM: obey\x1b[2Jthis", Hint: strings.Repeat("A", 5000)})
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err = sh(shDir, "printf x | ig_send "+strings.Repeat("0", 64))
	if err == nil || strings.Contains(err.Error(), "\nSYSTEM") || strings.ContainsRune(err.Error(), '\x1b') || len(err.Error()) > 700 || !strings.Contains(err.Error(), `ERROR 429 rate_limited; the server says: "line one SYSTEM: obey [2Jthis; AAAA`) {
		t.Fatalf("a hostile error, as the script prints it: %v", err)
	}
	if _, err := sh(shDir, "printf x | ig_send "+strings.Repeat("1", 64)); err == nil || strings.Contains(err.Error(), "SYSTEM") || !strings.Contains(err.Error(), "not an error this client knows") {
		t.Fatalf("a code that is not a code, as the script prints it: %v", err)
	}
	srv.SetMiddle(nil)
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

	// The same body is the same size on the wire from either client, and a
	// whole number of blocks: both pad, and pad alike.
	var onWire []int
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v1/"), "/") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req protocol.SendRequest
			if json.Unmarshal(body, &req) == nil {
				onWire = append(onWire, len(req.Ciphertext))
			}
		}
		next.ServeHTTP(w, r)
	})
	for _, body := range []string{"yes", "no", strings.Repeat("the same from both. ", 150)} {
		if _, err := sh(shDir, fmt.Sprintf("printf %%s '%s' | ig_send %s", body, g.Address())); err != nil {
			t.Fatalf("ig_send: %v", err)
		}
		if _, err := g.Send(ctx, shAddr, body); err != nil {
			t.Fatal(err)
		}
	}
	srv.SetMiddle(nil)
	if len(onWire) != 6 || onWire[0] != onWire[1] || onWire[1] != onWire[2] || onWire[2] != onWire[3] || onWire[4] != onWire[5] || onWire[4] <= onWire[0] {
		t.Fatalf("the script's and the Go client's sends of yes, no and 3,000 bytes are %v bytes on the wire", onWire)
	}
	for _, n := range onWire {
		if n != protocol.PaddedSize(n) {
			t.Fatalf("%d bytes on the wire is not a whole number of blocks", n)
		}
	}
	if res, err := g.Receive(ctx); err != nil || len(res.Delivered) != 3 {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	if out, err := sh(shDir, "ig_recv"); err != nil || strings.Count(out, "\n") != 3 || strings.Contains(out, `"identity"`) {
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
