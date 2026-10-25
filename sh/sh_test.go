// Package sh_test runs dromas.sh, the stock-tools client, from go test:
// against the fake server, which a test makes forge, a shell per command
// (world_test.go); its verdicts on the test vectors against the Go client's;
// and the two clients exchanging mail.
package sh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/agetool"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

const vectors = "../testdata/vectors"

// need skips the test unless every tool is on PATH, saying which is missing.
func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH: dromas.sh needs bash, age, ssh-keygen, curl, jq, iconv and coreutils", tool)
		}
	}
}

var scriptTools = []string{"bash", "age", "age-keygen", "ssh-keygen", "jq", "iconv", "sha256sum", "base64", "od", "sync"}

// TestMain puts an age that makes post-quantum boxes first in PATH for every
// test and every shell they run: the local one when it can, else go.mod's.
func TestMain(m *testing.M) {
	path, err := agetool.Path()
	if err != nil {
		fmt.Fprintln(os.Stderr, "no age that makes post-quantum keys:", err)
		os.Exit(1)
	}
	if err := os.Setenv("PATH", path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// p256 reports whether the local ssh-keygen reads a P-256 key. One built
// without OpenSSL cannot, so the script refuses every P-256 identity there:
// a known variance of OpenSSH's builds (PROTOCOL.md Appendix A).
func p256() bool {
	doc, err := os.ReadFile(filepath.Join(vectors, "c", "identity.doc"))
	if err != nil {
		return false
	}
	_, line, _ := strings.Cut(string(doc), "\n")
	cmd := exec.Command("ssh-keygen", "-l", "-f", "-")
	cmd.Stdin = strings.NewReader(line)
	return cmd.Run() == nil
}

// mustRead reads a file the test needs.
func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // a test vector
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sshBuild names the OpenSSH on PATH, as `ssh -V` does, for a test's log: a
// verdict that rests on ssh-keygen holds for the build it was run on.
func sshBuild() string {
	out, _ := exec.Command("ssh", "-V").CombinedOutput()
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "an ssh-keygen with no ssh beside it to name its build"
}

func abs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// exists reports whether name is a file that is not empty.
func exists(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.Size() > 0
}

// linkIn is the link in the box line init and addr print: one line of JSON,
// its type first, whose link ends in its address.
func linkIn(t *testing.T, out string) string {
	t.Helper()
	var l struct{ Type, Address, Link string }
	if !strings.HasPrefix(out, `{"type":"box",`) || strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &l) != nil || l.Address == "" || !strings.HasSuffix(l.Link, "/"+l.Address) {
		t.Fatalf("not a box line: %q", out)
	}
	return l.Link
}

// bash runs commands after sourcing dromas.sh, with env added.
func bash(t *testing.T, env []string, commands string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", ". "+abs(t, "dromas.sh")+"\n"+commands)
	cmd.Env = append(os.Environ(), env...)
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errs.String()))
	}
	return out.String(), err
}

// vectorNow is the vectors' now, as dr_now gives it.
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
	return now, fmt.Sprintf("dr_now(){ echo %d; }\n", now.Unix())
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
func scratch(t *testing.T) []string { return []string{"DR_HOME=" + t.TempDir()} }

// The script's verdict on every vector is the one the vectors name, as the
// Go client's is (protocol/vectors_test.go).
func TestVectorsIdentity(t *testing.T) {
	need(t, scriptTools...)
	t.Logf("ssh-keygen: %s", sshBuild())
	for _, box := range []string{"a", "b", "c"} { // c's identity is a P-256 key
		if box == "c" && !p256() {
			t.Logf("%s reads no P-256 key, so the script refuses c/identity.doc: a known variance (PROTOCOL.md Appendix A)", sshBuild())
			continue
		}
		a, _ := identity(t, box)
		if _, err := bash(t, nil, fmt.Sprintf("dr_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), a)); err != nil {
			t.Errorf("%s/identity.doc refused: %v", box, err)
		}
		if _, err := bash(t, nil, fmt.Sprintf("dr_idcheck %s %s", abs(t, filepath.Join(vectors, box, "identity.doc")), strings.Repeat("0", 64))); err == nil {
			t.Errorf("%s/identity.doc accepted for another address", box)
		}
	}
	docs, _ := filepath.Glob(filepath.Join(vectors, "identity", "*.doc"))
	if len(docs) == 0 {
		t.Fatal("no identity vectors")
	}
	// Each is refused as the Go client refuses it: with status 2 if it is a
	// well-formed document of a key type the client does not verify, which
	// has a refusal of its own, and with status 1 otherwise. The ok- ones
	// are taken.
	//
	// OpenSSH's builds disagree on those two (PROTOCOL.md §4.1, Appendix A): a P-256
	// key with a coordinate of 128 bits or fewer, or of the group's order
	// less one or more, is taken by the Go client and by OpenSSH from 10.3p1
	// (9bea0818), and refused up to 10.2p1, which the script's ssh-keygen
	// decides. The script taking both is the Go client's verdict, on any
	// build. Both refused is the known variance only where ssh-keygen -l
	// itself refuses both, as TestVectorsSignatureForm asks it of each R
	// vector; anything else fails.
	classes := map[int]int{}
	coordinates := map[string][2]bool{} // the script's verdict and ssh-keygen's alone: taken or not
	for _, d := range docs {
		name := filepath.Base(d)
		doc, _ := os.ReadFile(d) //nolint:gosec // a test vector
		_, gerr := protocol.ParseIdentity(doc)
		_, err := bash(t, nil, "dr_idcheck "+abs(t, d))
		if strings.HasPrefix(name, "ok-") {
			if gerr != nil {
				t.Errorf("%s: the Go client refuses it: %v", name, gerr)
			}
			_, line, _ := strings.Cut(string(doc), "\n")
			keygen := exec.Command("ssh-keygen", "-l", "-f", "-")
			keygen.Stdin = strings.NewReader(line)
			coordinates[name] = [2]bool{err == nil, keygen.Run() == nil}
			continue
		}
		want := 1
		if errors.Is(gerr, protocol.ErrIdentityType) {
			want = 2
		}
		var exit *exec.ExitError
		if gerr == nil || !errors.As(err, &exit) || exit.ExitCode() != want {
			t.Errorf("%s: the Go client says %v; the script's status is %v, want %d", name, gerr, err, want)
		}
		classes[want]++
	}
	switch short, over := coordinates["ok-p256-short-coordinate.doc"], coordinates["ok-p256-coordinate-over-order.doc"]; {
	case len(coordinates) != 2:
		t.Errorf("the ok- identity vectors: %v, want the two P-256 coordinate ones", coordinates)
	case short[0] && over[0]:
	case short != [2]bool{} || over != [2]bool{}:
		t.Errorf("the P-256 coordinate vectors, as [the script, ssh-keygen] taken: short %v, over the order %v; neither the Go client's verdict nor the known variance", short, over)
	case !p256():
		t.Logf("%s reads no P-256 key, so the script refuses both ok- identity vectors: a known variance (PROTOCOL.md Appendix A)", sshBuild())
	default:
		t.Logf("%s refuses a P-256 key whose coordinate is 128 bits or shorter or at the order less one or more, as OpenSSH did up to 10.2p1, and the script with it: a known variance (PROTOCOL.md Appendix A)", sshBuild())
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
		return bash(t, scratch(t), setNow+fmt.Sprintf("dr_certified %s %s dromas-prekey-v1:%s %s %s", addr, doc, a, abs(t, sig), stmt))
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
	for _, name := range []string{"bad-extension-twice", "bad-extension-value-an-empty-string", "bad-key-id", "bad-serial-zero"} {
		verify := fmt.Sprintf(`printf '%%s cert-authority %%s\n' %s "$(sed -n 2p %s)" > "$DR/s" && ssh-keygen -Y verify -f "$DR/s" -I %s -n dromas-prekey-v1:%s -s %s -O verify-time=20261010000000Z < %s`,
			a, aDoc, a, a, abs(t, filepath.Join(vectors, "cert", name+".sig")), stmt)
		if _, err := bash(t, scratch(t), "mkdir -p \"$DR\"; "+verify); err != nil {
			t.Errorf("control: ssh-keygen -Y verify refuses %s by itself: %v", name, err)
		}
	}
}

// One signature in the forms sig/ holds, as the Go client judges them
// (protocol/vectors_test.go): each ok-* taken, each bad-* refused. Control:
// ssh-keygen -Y verify gives the same verdict on every one but those named
// here, which it takes and a verifier here refuses: over the bound, and an
// Ed25519 S that is not below L. So the script reads a signature as OpenSSH
// does, and its own checks are what refuse those.
//
// An Ed25519 R is where OpenSSH's builds disagree (PROTOCOL.md Appendix A): Go's
// crypto/ed25519, OpenSSL and OpenSSH's own code before 10.6p1 take a
// neutral R and refuse R plus a point of order 2, and OpenSSH's own from
// 10.6p1, libsodium's, judges both the other way. The script says what its
// ssh-keygen says of those two, so on such a build it is held to that
// shape, a known variance, and anything else fails.
func TestVectorsSignatureForm(t *testing.T) {
	need(t, scriptTools...)
	t.Logf("ssh-keygen: %s", sshBuild())
	_, setNow := vectorNow(t)
	a, aDoc := identity(t, "a")
	stmt := abs(t, filepath.Join(vectors, "a/prekey-1.txt"))
	sigs, _ := filepath.Glob(filepath.Join(vectors, "sig", "*.sig"))
	if len(sigs) < 20 {
		t.Fatalf("%d sig/ vectors", len(sigs))
	}
	beyondSSHKeygen := map[string]bool{"bad-4097-bytes.sig": true, "bad-4097-bytes-before-end.sig": true, "bad-s-plus-l.sig": true, "bad-certificate-s-plus-l.sig": true, "bad-type-nul-s-plus-l.sig": true}
	edR := map[string][2]bool{} // the script's verdict and ssh-keygen's on each R vector: taken or not
	for _, sig := range sigs {
		name := filepath.Base(sig)
		ok := strings.HasPrefix(name, "ok-")
		_, err := bash(t, scratch(t), setNow+fmt.Sprintf(`mkdir -p "$DR"; dr_certified %s %s dromas-prekey-v1:%s %s %s`, a, aDoc, a, abs(t, sig), stmt))
		verify := fmt.Sprintf(`mkdir -p "$DR"; printf '%%s cert-authority %%s\n' %s "$(sed -n 2p %s)" > "$DR/s" && ssh-keygen -Y verify -f "$DR/s" -I %s -n dromas-prekey-v1:%s -s %s -O verify-time=20261010000000Z < %s`,
			a, aDoc, a, a, abs(t, sig), stmt)
		_, kerr := bash(t, scratch(t), verify)
		if name == "ok-r-small-order.sig" || name == "bad-r-plus-order-2.sig" {
			edR[name] = [2]bool{err == nil, kerr == nil}
			continue
		}
		if ok != (err == nil) {
			t.Errorf("%s: the script says %v", name, err)
		}
		switch {
		case beyondSSHKeygen[name] && kerr != nil && strings.Contains(name, "s-plus-l"):
			t.Logf("%s: this ssh-keygen refuses it by itself (one built on another Ed25519 may)", name)
		case beyondSSHKeygen[name] && kerr != nil:
			t.Errorf("control: ssh-keygen refuses %s by itself, so the bound is not what refuses it: %v", name, kerr)
		case !beyondSSHKeygen[name] && ok != (kerr == nil):
			t.Errorf("control: ssh-keygen -Y verify's verdict on %s differs: %v", name, kerr)
		}
	}
	small, plus2 := edR["ok-r-small-order.sig"], edR["bad-r-plus-order-2.sig"]
	switch {
	case small == [2]bool{true, true} && plus2 == [2]bool{false, false}:
	case small == [2]bool{false, false} && plus2 == [2]bool{true, true}:
		t.Logf("%s judges an Ed25519 R as libsodium does (OpenSSH's own Ed25519 from 10.6p1), and the script with it: it refuses sig/ok-r-small-order.sig and takes sig/bad-r-plus-order-2.sig, a known variance (PROTOCOL.md Appendix A)", sshBuild())
	default:
		t.Errorf("the R vectors, as [the script, ssh-keygen] taken: ok-r-small-order %v, bad-r-plus-order-2 %v; neither the Go client's verdict nor the known variance", small, plus2)
	}
}

func TestVectorsPrekey(t *testing.T) {
	need(t, scriptTools...)
	now, setNow := vectorNow(t)
	a, aDoc := identity(t, "a")
	b, bDoc := identity(t, "b")
	check := func(stmt, sig, addr, doc string) (serial string, notAfter int64, err error) {
		out, err := bash(t, scratch(t), setNow+fmt.Sprintf("dr_prekeycheck %s %s %s %s", abs(t, stmt), abs(t, sig), addr, doc))
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
	for _, c := range []struct{ stmt, sig, addr, doc, serial string }{
		{"a/prekey-1.txt", "a/prekey-1.txt.sig", a, aDoc, "1"},
		{"a/prekey-1.txt", "a/prekey-1.txt.sha256.sig", a, aDoc, "1"},
		{"a/prekey-2.txt", "a/prekey-2.txt.sig", a, aDoc, "2"},
		{"b/prekey-1.txt", "b/prekey-1.txt.sig", b, bDoc, "1"},
	} {
		s, na, err := check(filepath.Join(vectors, c.stmt), filepath.Join(vectors, c.sig), c.addr, c.doc)
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
		case strings.HasPrefix(name, "bad-"):
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case name == "expired": // valid, but no sender encrypts to it (dr_resolve)
			if err != nil || na > now.Unix() {
				t.Errorf("%s: want valid and expired: %d %v", name, na, err)
			}
		case name == "longest", name == "too-long": // valid and current: only a server judges how far ahead one may end
			if err != nil || na <= now.Unix() {
				t.Errorf("%s: want valid and not expired: %d %v", name, na, err)
			}
		case name == "unsupported-type": // good in every way but its key's type: a verdict of its own, as the Go client's ErrPrekeyType
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(err.Error(), "a type this script cannot encrypt to") {
				t.Errorf("%s: %v, want 2, a key of a type this script lacks", name, err)
			}
		default:
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// envelopeFive are the envelope/ refusals the script is held to, each one
// that would let through a forgery (a sender or recipient not the signed
// one, a text read as two values) or a replay (a msg_id or sent_at the
// replay set cannot key by). The others are PROTOCOL.md §3.3's JSON-text rules
// and the members' types, which the Go client holds (AGENTS.md § The shell
// client).
var envelopeFive = map[string]bool{
	"refuse-from-not-signer": true, "refuse-from-null": true, "refuse-from-uppercase": true,
	"refuse-to-another-box": true, "refuse-to-uppercase": true,
	"refuse-duplicate-key": true, "refuse-key-twice-in-the-body": true, "refuse-not-json": true, "refuse-two-objects": true,
	"refuse-no-msg-id": true, "refuse-msg-id-grouped-wrongly": true, "refuse-msg-id-newline": true, "refuse-msg-id-uppercase": true,
	"refuse-sent-at-ending-in-a-line-feed": true, "refuse-sent-at-ending-in-a-nul": true, "refuse-sent-at-malformed": true, "refuse-sent-at-second-60": true,
	"refuse-33-days-and-1s-old": true, "refuse-1-hour-and-1s-ahead": true,
}

// sameLine holds the script's delivered line to the Go client's, byte for
// byte, or, where jq spells a number or a string otherwise, to the Go
// client's line in jq's spelling, which dr_line writes from it: the one
// difference the two may have, which guards none of the five (AGENTS.md § The
// shell client). It reports whether the spelling differed.
func sameLine(t *testing.T, goLine []byte, shLine string) (respelled bool, ok bool) {
	t.Helper()
	if string(goLine) == shLine {
		return false, true
	}
	f := filepath.Join(t.TempDir(), "go.line")
	if err := os.WriteFile(f, goLine, 0o600); err != nil {
		t.Fatal(err)
	}
	spelled, err := bash(t, nil, "dr_line "+f)
	return true, err == nil && spelled == shLine
}

// sameValue reports whether two lines hold the same value, token for token:
// the same members in the same order (a sender sends them in the order
// given, PROTOCOL.md §9.1, and jq keeps it), each string the same once
// unescaped, and each number the same decimal value, a zero's sign included.
// That allows jq's spelling and nothing else. sameLine's reference is
// the script's own dr_line, so this is the check that holds the script to
// the Go client where dr_line itself went wrong for both: read as binary64,
// 9007199254740993 and 9007199254740992 would be one value.
func sameValue(goLine []byte, shLine string) bool {
	a, b := jsontext.NewDecoder(bytes.NewReader(goLine)), jsontext.NewDecoder(strings.NewReader(shLine))
	for {
		x, errA := a.ReadToken()
		y, errB := b.ReadToken()
		switch {
		case errA == io.EOF && errB == io.EOF:
			return true
		case errA != nil || errB != nil || x.Kind() != y.Kind():
			return false
		case x.Kind() == '"' && x.String() != y.String():
			return false
		case x.Kind() == '0' && !sameNumber(x.String(), y.String()):
			return false
		}
	}
}

// sameNumber reports whether two JSON numbers have one exact decimal value
// and, for a zero, one sign.
func sameNumber(x, y string) bool {
	p, okP := new(big.Rat).SetString(x)
	q, okQ := new(big.Rat).SetString(y)
	return okP && okQ && p.Cmp(q) == 0 && strings.HasPrefix(x, "-") == strings.HasPrefix(y, "-")
}

// The script takes every envelope the Go client takes, and delivers the same
// line, byte for byte but for jq's spelling (sameLine), and refuses each of
// envelopeFive.
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
	for name := range envelopeFive {
		if _, err := os.Stat(filepath.Join(vectors, "envelope", name+".json")); err != nil {
			t.Errorf("envelopeFive names %s, which is no vector", name)
		}
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		line, err := bash(t, nil, setNow+fmt.Sprintf("dr_envcheck %s %s %s && dr_line %s", abs(t, f), a, b, abs(t, f)))
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
			respelled, ok := sameLine(t, want, line)
			switch {
			case !ok || !sameValue(want, line):
				t.Errorf("%s: the script delivers %s, the Go client %s", name, line, want)
			case respelled:
				t.Logf("%s: the script delivers it in jq's spelling, %s, where the Go client delivers %s: a difference that guards none of the five", name, line, want)
			case name == "accept-body-jq-spells-otherwise":
				t.Errorf("%s: control: the script delivers it as the Go client does, so no run meets the difference", name)
			}
		case envelopeFive[name]:
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			// The two ends of the sent_at window have a code each, the Go client's.
			if want := map[string]string{"refuse-33-days-and-1s-old": protocol.RefusedStale, "refuse-1-hour-and-1s-ahead": protocol.RefusedFuture}[name]; want != "" && !strings.HasPrefix(line, want+": ") {
				t.Errorf("%s: refused as %q, want the code %s", name, line, want)
			}
		case !strings.HasPrefix(name, "refuse-"):
			t.Errorf("%s: unknown vector", name)
		}
	}
}

// answerBytes names each kind of answer's byte members, which the script
// reads with dr_bytes.
var answerBytes = map[string]string{
	"box":    "identity prekey prekey_signature revoked_certificates revoked_certificates_signature",
	"record": "identity revocation_signature revoked_certificates revoked_certificates_signature",
}

// answerTypes is what the Go client reads each kind of answer into.
var answerTypes = map[string]func() any{
	"box":     func() any { return new(protocol.BoxResponse) },
	"list":    func() any { return new(protocol.MessageList) },
	"record":  func() any { return new(protocol.Revocations) },
	"receipt": func() any { return new(protocol.Receipt) },
	"problem": func() any { return new(protocol.Problem) },
}

// answerRead are the answer/ vectors the script refuses: those that are not one
// object, or break a member the script reads (a byte member it decodes, an id
// or a size it uses, the cursor it puts in a query). Every other bad-* vector
// breaks a member it never reads, and is the Go client's to refuse.
var answerRead = map[string]bool{
	"box-bad-prekey-a-number": true, "box-bad-revoked-certificates-a-number": true, "box-bad-signature-unpadded": true,
	"list-bad-cursor-a-number": true, "list-bad-cursor-a-percent": true, "list-bad-cursor-a-slash": true, "list-bad-cursor-empty": true,
	"list-bad-messages-an-object": true, "list-bad-size-a-string": true, "list-bad-size-past-the-largest": true, "receipt-bad-id-an-array": true,
	"record-bad-a-second-value": true, "record-bad-an-array": true, "record-bad-empty": true, "record-bad-identity-a-number": true,
	"record-bad-identity-wrapped": true, "record-bad-revocation-signature-unpadded": true, "record-bad-revocation-signature-unused-bits-set": true,
}

// The script reads every answer/ vector the Go client takes, a whole answer of
// a server of each kind: with dr_shape, and each byte member with dr_bytes,
// and refuses each of answerRead.
func TestVectorsAnswer(t *testing.T) {
	need(t, scriptTools...)
	files, _ := filepath.Glob(filepath.Join(vectors, "answer", "*.json"))
	if len(files) != 60 {
		t.Fatalf("%d answer/ vectors, want 60", len(files))
	}
	for name := range answerRead {
		if _, err := os.Stat(filepath.Join(vectors, "answer", name+".json")); err != nil {
			t.Errorf("answerRead names %s, which is no vector", name)
		}
	}
	dir := t.TempDir()
	var script strings.Builder
	for _, f := range files {
		kind, _, _ := strings.Cut(filepath.Base(f), "-")
		fmt.Fprintf(&script, "{ dr_shape %s %s", abs(t, f), kind)
		for _, m := range strings.Fields(answerBytes[kind]) {
			fmt.Fprintf(&script, " && dr_bytes %s %s %s", abs(t, f), m, filepath.Join(dir, m))
		}
		script.WriteString("; } && echo 0 || echo 1\n")
	}
	out, err := bash(t, nil, script.String())
	if err != nil {
		t.Fatal(err)
	}
	verdicts := strings.Fields(out)
	if len(verdicts) != len(files) {
		t.Fatalf("%d verdicts for %d vectors", len(verdicts), len(files))
	}
	for i, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		kind, verdict, _ := strings.Cut(name, "-")
		data, _ := os.ReadFile(f) //nolint:gosec // a test vector
		goTakes, shTakes := protocol.Unmarshal(data, answerTypes[kind]()) == nil, verdicts[i] == "0"
		if goTakes != strings.HasPrefix(verdict, "ok") {
			t.Errorf("%s: the Go client takes it: %v", name, goTakes)
		}
		if goTakes && !shTakes {
			t.Errorf("%s: the Go client takes it, and the script does not", name)
		}
		if answerRead[name] && shTakes {
			t.Errorf("%s: the script takes it", name)
		}
	}
}

// What a box decrypts gets the Go client's verdict from the script, code for
// code, for every plain/ vector. The script need not give a code it cannot;
// none differs today, and one that comes to is named here as a known variance: the layout, the identity the envelope
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
		out, err := bash(t, scratch(t), setNow+fmt.Sprintf(`mkdir -p "$DR" && cp %s "$DR/msg.T" && dr_open %s "$DR/msg" && dr_line "$DR/msg.P"`, abs(t, f), b))
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
		if err != nil && signed.Sender.Type() == protocol.IdentityP256 && !p256() {
			t.Logf("%s: %s reads no P-256 key, so the script refuses a P-256 sender: a known variance (PROTOCOL.md Appendix A)", name, sshBuild())
			codes["delivered"]++
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
		respelled, ok := sameLine(t, want, line)
		if sender != signed.Sender.Address().String() || !ok || !sameValue(want, line) {
			t.Errorf("%s: the script delivers %s from %s, the Go client %s from %s", name, line, sender, want, signed.Sender.Address())
		} else if respelled {
			t.Logf("%s: the script delivers it in jq's spelling, %s, where the Go client delivers %s: a difference that guards none of the five", name, line, want)
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
		got, err := bash(t, nil, fmt.Sprintf(`for n in %s; do echo "$n $(dr_padding $n %s)"; done`, args.String(), key))
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
	if !p256() {
		t.Skipf("%s reads no P-256 key, so the script runs no P-256 box: a known variance (PROTOCOL.md Appendix A)", sshBuild())
	}
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	sh := func(dir, commands string) string {
		t.Helper()
		out, err := bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}, commands)
		if err != nil {
			t.Fatalf("%s: %v", commands, err)
		}
		return out
	}
	addr := func(link string) protocol.Address {
		t.Helper()
		a, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, link), srv.URL+protocol.LinkPath))
		if err != nil {
			t.Fatalf("not a link: %q", link)
		}
		return a
	}
	shP256, shEd := t.TempDir(), t.TempDir()
	sp := addr(sh(shP256, `ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$DR/identity" < /dev/null && dr_init`))
	se := addr(sh(shEd, "dr_init"))
	doc, _ := os.ReadFile(filepath.Join(shP256, "identity.doc")) //nolint:gosec // the test's own directory
	if id, err := protocol.ParseIdentity(doc); err != nil || id.Type() != protocol.IdentityP256 || id.Address() != sp {
		t.Fatalf("the script's P-256 box: %v", err)
	}
	gp, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL, IdentityType: protocol.IdentityP256}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, gp)
	ge, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, ge)

	// The script's P-256 box and the Go client's Ed25519 one.
	sh(shP256, "printf 'from the script on P-256' | dr_send "+ge.Link())
	if res, err := ge.Receive(ctx); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != sp {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	if _, err := ge.Send(ctx, sp, "to the script on P-256"); err != nil {
		t.Fatal(err)
	}
	if out := sh(shP256, "dr_recv"); !strings.Contains(out, `"body":"to the script on P-256"`) {
		t.Fatalf("dr_recv: %q", out)
	}
	// The Go client's P-256 box and the script's Ed25519 one.
	if _, err := gp.Send(ctx, se, "from Go on P-256"); err != nil {
		t.Fatal(err)
	}
	if out := sh(shEd, "dr_recv"); !strings.Contains(out, `"body":"from Go on P-256"`) || !strings.Contains(out, gp.Address().String()) {
		t.Fatalf("dr_recv: %q", out)
	}
	sh(shEd, "printf 'to Go on P-256' | dr_send "+gp.Link())
	if res, err := gp.Receive(ctx); err != nil || len(res.Delivered) != 1 || res.Delivered[0].Envelope.From != se {
		t.Fatalf("the Go client's P-256 box received %+v, %v", res, err)
	}
}

// A box declares the identity key types its build verifies, at init and at
// each renewal (PROTOCOL.md §7; #358): ecdsa-sha2-nistp256 only where its
// ssh-keygen reads a P-256 key. A build without OpenSSL reads none, and the
// script refuses every P-256 identity there; here an ssh-keygen that reads
// no P-256 key stands for one.
func TestTheScriptDeclaresTheKeyTypesItsBuildVerifies(t *testing.T) {
	w := newWorld(t)
	declared := func(b *sbox) string {
		t.Helper()
		return strings.TrimSpace(b.must(`dr_look "$(cat "$DR/address")" | jq -c .sender_key_types`))
	}
	noP256 := `ssh-keygen(){ local k; if [ "$1" = -l ]; then k=$(cat); case $k in "ecdsa-sha2-nistp256 "*) return 255 ;; esac; command ssh-keygen "$@" <<< "$k"; else command ssh-keygen "$@"; fi; }` + "\n"
	both, ed := `["ssh-ed25519","ecdsa-sha2-nistp256"]`, `["ssh-ed25519"]`
	here := both
	if !p256() {
		here = ed
		t.Logf("%s reads no P-256 key, so the script declares ssh-ed25519 alone: a known variance (PROTOCOL.md Appendix A)", sshBuild())
	}
	b := w.box()
	n := w.empty()
	n.must(noP256 + "dr_init")
	n.addr = mustAddress(t, n.dir)
	if got, gotN := declared(b), declared(n); got != here || gotN != ed {
		t.Errorf("init declares %s here and %s on a build that reads no P-256 key, want %s and %s", got, gotN, here, ed)
	}
	b.must(noP256 + "dr_rekey")
	n.must("dr_rekey")
	if got, gotN := declared(b), declared(n); got != ed || gotN != here {
		t.Errorf("a renewal declares %s on a build that reads no P-256 key and %s here, want %s and %s", got, gotN, ed, here)
	}
}

// A box whose ACL does not admit the script's box refuses its send, and the
// script says so and keeps nothing: only the recipient can change that.
func TestTheScriptsSendABoxDeniesFails(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	shDir := t.TempDir()
	sh := func(commands string) (string, error) {
		return bash(t, []string{"DR_HOME=" + shDir, "DR_BASE=" + srv.URL}, commands)
	}
	out, err := sh("dr_init")
	if err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	shAddr, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, out), srv.URL+protocol.LinkPath))
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Block(ctx, shAddr); err != nil {
		t.Fatal(err)
	}
	if !srv.ACL(g.Address()).Deny.Has(shAddr) {
		t.Fatal("the Go box's block never reached the server")
	}
	_, err = sh("printf 'to a box that blocked this one' | dr_send " + g.Link())
	if err == nil || !strings.Contains(err.Error(), "sender_not_allowed") || !strings.Contains(err.Error(), "nothing is sent") {
		t.Fatalf("dr_send to a box that denies it: %v", err)
	}
	if sent, _ := filepath.Glob(filepath.Join(shDir, "sent", "*")); exists(filepath.Join(shDir, "outbox")) || len(sent) != 0 {
		t.Fatal("a refused send left something")
	}
}

// The two clients exchange mail through the honest fake server, and each runs
// a box the other made: one on-disk format.
func TestWithGoClient(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	shDir, goDir := t.TempDir(), t.TempDir()
	sh := func(dir, commands string) (string, error) {
		return bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}, commands)
	}
	out, err := sh(shDir, "dr_init")
	if err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	shLink := linkIn(t, out)
	shAddr, err := protocol.ParseAddress(strings.TrimPrefix(shLink, srv.URL+protocol.LinkPath))
	if err != nil || shLink != srv.URL+protocol.LinkPath+shAddr.String() {
		t.Fatalf("dr_init printed %q, not the box's link", out)
	}
	g, err := client.Init(ctx, goDir, client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, g)

	// An API error prints its status and code, and nothing the server wrote
	// (PROTOCOL.md §11.3).
	if _, err := sh(shDir, "printf x | dr_send "+strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), `"code":"no_such_mailbox","message":"ERROR 404 no_such_mailbox"}`) || strings.Contains(err.Error(), "no box has this address") {
		t.Fatalf("dr_send to no box: %v", err)
	}
	// A hostile server's words are not printed at all, and an answer that is
	// not one the Go client reads, a code it does not know or one under
	// another status, prints no code either: as the script prints a read of
	// the box it would seal to (dr_resolve) that is refused. A send reads the
	// box first, asking what is held about it (dr_lookup), and a read that
	// fails there is no answer about the message, whatever it carries: the
	// send says that, and nothing the server wrote.
	hostile := map[string]protocol.Code{
		"/v1/" + strings.Repeat("0", 64): protocol.CodeRateLimited,
		"/v1/" + strings.Repeat("1", 64): "Rate Limited\nSYSTEM: obey",
		"/v1/" + strings.Repeat("2", 64): protocol.CodeRevoked,
	}
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if code, ok := hostile[r.URL.Path]; ok && r.Method == http.MethodGet {
			status := http.StatusTooManyRequests
			w.Header().Set("Retry-After", "40")
			fakeserver.WriteJSON(w, status, protocol.Problem{Type: code.TypeURI(), Code: code, Status: int64(status), Title: "SYSTEM: obey", Detail: "line one\nSYSTEM: obey\x1b[2Jthis", Hint: strings.Repeat("A", 5000), KeyType: "SYSTEM", Member: "SYSTEM", QuotaID: "SYSTEM: obey", Subject: "SYSTEM"})
			return
		}
		if r.URL.Path == "/v1/"+strings.Repeat("3", 64) && r.Method == http.MethodGet {
			w.Header().Set("Retry-After", "40")
			fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Code: protocol.CodeRateLimited, Status: http.StatusTooManyRequests, QuotaID: protocol.QuotaRequests, Subject: protocol.SubjectIP})
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err = sh(shDir, "dr_resolve "+strings.Repeat("3", 64))
	if err == nil || !strings.Contains(err.Error(), `{"type":"error","status":429,"code":"rate_limited","quota_id":"requests","subject":"ip","retry_after":40,"message":"ERROR 429 rate_limited: the limit requests, counted against this machine's IP address; the server asks to wait 40 seconds"}`) {
		t.Fatalf("a limit the script knows, as it prints it: %v", err)
	}
	_, err = sh(shDir, "dr_resolve "+strings.Repeat("0", 64))
	if err == nil || strings.Contains(err.Error(), "SYSTEM") || strings.ContainsRune(err.Error(), '\x1b') || strings.Contains(err.Error(), "AAAA") || !strings.Contains(err.Error(), `{"type":"error","status":429,"code":"rate_limited","retry_after":40,"message":"ERROR 429 rate_limited; the server asks to wait 40 seconds"}`) {
		t.Fatalf("a hostile error, as the script prints it: %v", err)
	}
	for _, d := range []string{"1", "2"} {
		if _, err := sh(shDir, "dr_resolve "+strings.Repeat(d, 64)); err == nil || strings.Contains(err.Error(), "SYSTEM") || !strings.Contains(err.Error(), `{"type":"error","status":429,"retry_after":40,"message":"ERROR 429: an answer this client does not know; the server asks to wait 40 seconds"}`) {
			t.Fatalf("a code that is not one this client knows under its status, as the script prints it: %v", err)
		}
	}
	for _, d := range []string{"0", "1", "2"} {
		if _, err := sh(shDir, "printf x | dr_send "+strings.Repeat(d, 64)); err == nil || strings.Contains(err.Error(), "SYSTEM") || strings.ContainsRune(err.Error(), '\x1b') || strings.Contains(err.Error(), "AAAA") || !strings.Contains(err.Error(), "could not be read, so nothing is sent") {
			t.Fatalf("a send whose read of the box is refused, as the script prints it: %v", err)
		}
	}
	// A receipt that names another ciphertext is no receipt, nor is one whose
	// times are not times: nothing is recorded in sent/, and the script keeps
	// nothing to post again (#5). The same send, to an honest server, goes.
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			fakeserver.WriteJSON(w, http.StatusCreated, protocol.Receipt{ID: strings.Repeat("0", 64), ReceivedAt: "2026-10-16T00:00:00Z", ExpiresAt: "2026-11-18T00:00:00Z"})
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err = sh(shDir, fmt.Sprintf("printf 'from the script' | dr_send %s", g.Link()))
	if sent, _ := filepath.Glob(filepath.Join(shDir, "sent", "*")); err == nil || !strings.Contains(err.Error(), "does not name the ciphertext this box posted") || len(sent) != 0 {
		t.Fatalf("dr_send with a receipt for another ciphertext: %v, sent/ %v", err, sent)
	}
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost {
			fakeserver.TakeAs(w, r, func(rec *protocol.Receipt) { rec.ExpiresAt = "soon" })
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err = sh(shDir, fmt.Sprintf("printf 'from the script' | dr_send %s", g.Link()))
	if sent, _ := filepath.Glob(filepath.Join(shDir, "sent", "*")); err == nil || !strings.Contains(err.Error(), "its times are not times") || len(sent) != 0 {
		t.Fatalf("dr_send with a receipt whose time is not a time: %v, sent/ %v", err, sent)
	}
	srv.SetMiddle(nil)
	if _, err := sh(shDir, fmt.Sprintf("printf 'from the script' | dr_send %s", g.Link())); err != nil {
		t.Fatalf("dr_send to an honest server: %v", err)
	}
	if sent, _ := filepath.Glob(filepath.Join(shDir, "sent", g.Address().String()+".*")); len(sent) != 1 {
		t.Fatalf("dr_send to an honest server: sent/ %v", sent)
	}
	res, err := g.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"from the script"` {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}
	sameButReceipt(t, filepath.Join(shDir, "sent", g.Address().String()+"."+res.Delivered[0].Envelope.MsgID+".json"), res.Delivered[0].Line, res.Delivered[0].ID)
	if _, err := g.Send(ctx, shAddr, "from Go"); err != nil {
		t.Fatal(err)
	}
	out, err = sh(shDir, "dr_recv")
	if err != nil || !strings.Contains(out, `"body":"from Go"`) {
		t.Fatalf("dr_recv: %q %v", out, err)
	}

	// The same body is the same size on the wire from either client, and a
	// whole number of blocks: both pad, and pad alike.
	var onWire []int
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			onWire = append(onWire, len(body)) // the body is the ciphertext
		}
		next.ServeHTTP(w, r)
	})
	for _, body := range []string{"yes", "no", strings.Repeat("the same from both. ", 150)} {
		if _, err := sh(shDir, fmt.Sprintf("printf %%s '%s' | dr_send %s", body, g.Address())); err != nil {
			t.Fatalf("dr_send: %v", err)
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
	if out, err := sh(shDir, "dr_recv"); err != nil || strings.Count(out, "\n") != 3 || strings.Contains(out, `"identity"`) {
		t.Fatalf("dr_recv: %q %v", out, err)
	}

	// The script renews its box, and both keep exchanging mail.
	if _, err := sh(shDir, "dr_rekey"); err != nil {
		t.Fatalf("dr_rekey: %v", err)
	}
	if _, err := sh(shDir, fmt.Sprintf("printf 'after the rekey' | dr_send %s", g.Address())); err != nil {
		t.Fatalf("dr_send after the rekey: %v", err)
	}
	if res, err := g.Receive(ctx); err != nil || len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"after the rekey"` {
		t.Fatalf("the Go client received %+v, %v", res, err)
	}

	// The Go client's optional fields reach the script, which prints them in
	// the line it delivers, as the Go client keeps that line in sent/.
	f := client.Fields{Subject: "from Go", InReplyTo: "11111111-2222-4333-8444-555555555555", Supersedes: "22222222-2222-4333-8444-555555555555"}
	r, err := g.SendWith(ctx, shAddr, "answered by Go", f)
	if err != nil {
		t.Fatal(err)
	}
	out, err = sh(shDir, "dr_recv")
	var line struct {
		Envelope struct {
			MsgID      string `json:"msg_id"`
			Subject    string `json:"subject"`
			InReplyTo  string `json:"in_reply_to"`
			Supersedes string `json:"supersedes"`
		}
	}
	if err != nil || json.Unmarshal([]byte(out), &line) != nil || line.Envelope.Subject != f.Subject || line.Envelope.InReplyTo != f.InReplyTo || line.Envelope.Supersedes != f.Supersedes {
		t.Fatalf("dr_recv printed %q, %v", out, err)
	}
	sameButReceipt(t, filepath.Join(goDir, "sent", shAddr.String()+"."+line.Envelope.MsgID+".json"), []byte(out), r.ID)
}

// sameButReceipt checks a sent/ record: the line its recipient delivered, as
// inbox/ keeps it, as its envelope, and a receipt naming the message by id
// beside it, and nothing else (#356).
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
	// A mail line as recv prints it carries the line inbox/ keeps as its
	// envelope, behind its type and its id, which is the receipt's.
	if _, printed := want["type"]; printed {
		if want["type"] != "mail" || want["id"] != id || len(want) != 3 {
			t.Errorf("the line delivered is %v, the message %s", want, id)
		}
		want, _ = want["envelope"].(map[string]any)
	}
	receipt, _ := got["receipt"].(map[string]any)
	if receipt["id"] != id || receipt["received_at"] == nil || receipt["expires_at"] == nil || len(receipt) != 3 {
		t.Errorf("%s: its receipt is %v, the message %s", record, receipt, id)
	}
	if len(got) != 2 || !reflect.DeepEqual(got["envelope"], want) {
		t.Errorf("%s holds %v, its recipient delivered %v", record, got, want)
	}
}

// A revocation is taken or refused by the script exactly as the Go client
// takes or refuses it, on every vector. One of the refused is a good
// signature under the box's own certificate, which ssh-keygen verifies when
// it is told the identity is a certificate authority: the script's signers
// line for a revocation never says so.
func TestVectorsRevocation(t *testing.T) {
	need(t, scriptTools...)
	a, aDoc := identity(t, "a")
	b, bDoc := identity(t, "b")
	c, cDoc := identity(t, "c")
	addr := func(s string) protocol.Address {
		t.Helper()
		x, err := protocol.ParseAddress(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	type vector struct{ addr, doc, sig string }
	cases := []vector{
		{a, aDoc, "a/revoke.sig"}, {a, aDoc, "a/revoke.sha256.sig"}, {c, cDoc, "c/revoke.sig"},
		{b, aDoc, "a/revoke.sig"}, {a, bDoc, "a/revoke.sig"}, {b, bDoc, "revoke/bad-of-another-box.sig"}, {a, aDoc, "a/prekey-1.txt.sig"},
	}
	bads, _ := filepath.Glob(filepath.Join(vectors, "revoke", "bad-*.sig"))
	if len(bads) != 5 {
		t.Fatalf("%d revoke/bad-* vectors, want 5", len(bads))
	}
	for _, f := range bads {
		cases = append(cases, vector{a, aDoc, "revoke/" + filepath.Base(f)})
	}
	// Forms every OpenSSH build reads the same way: A's with a NUL ending its
	// key's type, and C's (c-*) with one ending its curve and with r at the
	// most OpenSSH reads and a byte over (PROTOCOL.md §3.2).
	oks, _ := filepath.Glob(filepath.Join(vectors, "revoke", "ok-*.sig"))
	cs, _ := filepath.Glob(filepath.Join(vectors, "revoke", "c-*.sig"))
	if len(oks) == 0 || len(cs) < 2 {
		t.Fatalf("%d revoke/ok-* and %d revoke/c-* vectors", len(oks), len(cs))
	}
	want := 3 + len(oks)
	for _, f := range oks {
		cases = append(cases, vector{a, aDoc, "revoke/" + filepath.Base(f)})
	}
	for _, f := range cs {
		cases = append(cases, vector{c, cDoc, "revoke/" + filepath.Base(f)})
		if strings.HasPrefix(filepath.Base(f), "c-ok-") {
			want++
		}
	}
	if !p256() {
		t.Logf("%s reads no P-256 key, so the script refuses every revocation of box C: a known variance (PROTOCOL.md Appendix A), and those are not compared", sshBuild())
		kept := cases[:0]
		for _, v := range cases {
			if v.addr != c {
				kept = append(kept, v)
			} else if _, err := protocol.VerifyRevocation(addr(v.addr), mustRead(t, v.doc), mustRead(t, filepath.Join(vectors, v.sig))); err == nil {
				want--
			}
		}
		cases = kept
	}
	taken := 0
	for _, v := range cases {
		doc, err := os.ReadFile(v.doc)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := os.ReadFile(filepath.Join(vectors, v.sig))
		if err != nil {
			t.Fatal(err)
		}
		_, goErr := protocol.VerifyRevocation(addr(v.addr), doc, sig)
		_, shErr := bash(t, scratch(t), fmt.Sprintf(`mkdir -p "$DR"; dr_revcheck %s %s %s`, v.addr, v.doc, abs(t, filepath.Join(vectors, v.sig))))
		if (goErr == nil) != (shErr == nil) {
			t.Errorf("%s as a revocation of %s…: the Go client says %v, the script %v", v.sig, v.addr[:8], goErr, shErr)
		}
		if goErr == nil {
			taken++
		}
	}
	if taken != want {
		t.Errorf("%d vectors taken as revocations, want the %d that are", taken, want)
	}
	// Control: the working key's signature is one ssh-keygen takes once the
	// identity is named a certificate authority, so it is the signers line
	// that refuses it and not a bad signature.
	verify := fmt.Sprintf(`mkdir -p "$DR"; printf '%%s cert-authority %%s\n' %s "$(sed -n 2p %s)" > "$DR/s" && ssh-keygen -Y verify -f "$DR/s" -I %s -n dromas-revoke-v1:%s -s %s -O verify-time=20261010000000Z < %s`,
		a, aDoc, a, a, abs(t, filepath.Join(vectors, "revoke/bad-by-a-working-key.sig")), abs(t, filepath.Join(vectors, "a/revoke.txt")))
	if _, err := bash(t, scratch(t), verify); err != nil {
		t.Errorf("control: ssh-keygen refuses the working key's signature even under a cert-authority line, so the vector tests nothing: %v", err)
	}
}

// A revocation checked by each client for itself, against one server: the
// record of a script box is one the Go client takes, and mail from a revoked
// box is refused by whichever reads it.
func TestRevocationInBothClients(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	kt := protocol.PostQuantum
	sh := func(dir, commands string) (string, error) {
		return bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}, commands)
	}
	scriptBox := func() (string, protocol.Address) {
		t.Helper()
		dir := t.TempDir()
		out, err := sh(dir, "dr_init")
		if err != nil {
			t.Fatalf("dr_init: %v", err)
		}
		a, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, out), srv.URL+protocol.LinkPath))
		if err != nil {
			t.Fatal(err)
		}
		return dir, a
	}
	goBox := func() *client.Box {
		t.Helper()
		b, err := client.Init(ctx, t.TempDir(), opt, kt)
		if err != nil {
			t.Fatal(err)
		}
		landAll(t, b)
		return b
	}
	var gone *client.RevokedError

	// A box's record, made from a script box's identity with ssh-keygen as
	// PROTOCOL.md §10.3 shows it: the script makes and publishes none, and the
	// Go client takes it.
	record := func(dir string) *protocol.Revocations {
		t.Helper()
		out, err := sh(dir, `A=$(cat "$DR/address"); printf 'dromas-revoke-v1\n%s\n' "$A" | ssh-keygen -q -Y sign -n "dromas-revoke-v1:$A" -f "$DR/identity" > "$DR/r.sig" && jq -cn --arg i "$(dr_b64 "$DR/identity.doc")" --arg s "$(dr_b64 "$DR/r.sig")" '{type:"revocation_record", identity:$i, revocation_signature:$s}'`)
		if err != nil {
			t.Fatal(err)
		}
		var r protocol.Revocations
		if err := protocol.UnmarshalRequest([]byte(out), &r); err != nil {
			t.Fatalf("the record is not the body a server takes: %v: %q", err, out)
		}
		return &r
	}
	s1, s1Addr := scriptBox()
	g1 := goBox()
	if a, _, err := g1.KeepRevocation(t.Context(), record(s1)); err != nil || a != s1Addr {
		t.Fatalf("the Go client refuses the record of the script's box: %v", err)
	}
	if _, err := g1.Send(ctx, s1Addr, "to a box whose record was handed over"); !errors.As(err, &gone) {
		t.Fatalf("the Go client sent to it: %v", err)
	}

	// A script box's address revoked at the server: the Go client is shown
	// the proof, checks it, and refuses the mail that box had sent it.
	s2, s2Addr := scriptBox()
	g2 := goBox()
	if _, err := sh(s2, "printf 'sent before the revocation' | dr_send "+g2.Address().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Revoke(ctx, opt, record(s2)); err != nil {
		t.Fatal(err)
	}
	res, err := g2.Receive(ctx)
	if err != nil || len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("the Go client's drain of mail from a revoked script box: %+v %v", res, err)
	}
	if _, err := g2.Send(ctx, s2Addr, "to a revoked script box"); !errors.As(err, &gone) {
		t.Fatalf("the Go client sent to it: %v", err)
	}

	// And the other way: the Go client revokes, and the script refuses.
	s3, _ := scriptBox()
	g3 := goBox()
	s3Addr, err := sh(s3, `cat "$DR/address"`)
	if err != nil {
		t.Fatal(err)
	}
	to, err := protocol.ParseAddress(strings.TrimSpace(s3Addr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g3.Send(ctx, to, "sent before the revocation"); err != nil {
		t.Fatal(err)
	}
	rec, err := g3.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Revoke(ctx, opt, rec); err != nil {
		t.Fatal(err)
	}
	out, err := sh(s3, "dr_recv 2>&1")
	if err != nil || !strings.Contains(out, `"code":"revoked"`) || strings.Contains(out, `"body"`) {
		t.Fatalf("the script's drain of mail from a box the Go client revoked: %q %v", out, err)
	}
	if _, err := sh(s3, "printf x | dr_send "+g3.Address().String()); err == nil || !strings.Contains(err.Error(), "REVOKED") {
		t.Fatalf("the script sent to it: %v", err)
	}
}

// A revocation of certificates is taken or refused by the script exactly as
// the Go client takes or refuses it, on every vector, and one both take runs
// through the same serial for both. One of the refused is a good signature
// under the box's own certificate: the script's signers line for it, as for
// a revocation of the address, never names the identity a certificate
// authority.
func TestVectorsRevokedCertificates(t *testing.T) {
	need(t, scriptTools...)
	a, aDoc := identity(t, "a")
	b, bDoc := identity(t, "b")
	addr := func(s string) protocol.Address {
		t.Helper()
		x, err := protocol.ParseAddress(s)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	type vector struct{ addr, doc, statement, sig string }
	cases := []vector{
		{a, aDoc, "ok-through-4.txt", "ok-through-4.sig"}, {a, aDoc, "ok-through-4.txt", "ok-through-4.sha256.sig"},
		{a, aDoc, "ok-through-the-highest.txt", "ok-through-the-highest.sig"},
		{b, bDoc, "ok-through-4.txt", "ok-through-4.sig"}, {a, bDoc, "ok-through-4.txt", "ok-through-4.sig"}, {b, aDoc, "ok-through-4.txt", "ok-through-4.sig"},
		{a, aDoc, "ok-through-4.txt", "ok-through-the-highest.sig"},
	}
	bads, _ := filepath.Glob(filepath.Join(vectors, "revoked", "bad-*.txt"))
	if len(bads) != 20 {
		t.Fatalf("%d revoked/bad-* vectors, want 20", len(bads))
	}
	for _, f := range bads {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		cases = append(cases, vector{a, aDoc, name + ".txt", name + ".sig"})
	}
	taken := 0
	var four *protocol.RevokedCertificates
	for _, v := range cases {
		statement, sig := filepath.Join(vectors, "revoked", v.statement), filepath.Join(vectors, "revoked", v.sig)
		doc, err := os.ReadFile(v.doc)
		if err != nil {
			t.Fatal(err)
		}
		text, err := os.ReadFile(statement)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := os.ReadFile(sig)
		if err != nil {
			t.Fatal(err)
		}
		got, goErr := protocol.VerifyRevokedCertificates(addr(v.addr), doc, text, signature)
		out, shErr := bash(t, scratch(t), fmt.Sprintf(`mkdir -p "$DR"; dr_certscheck %s %s %s %s`, v.addr, v.doc, abs(t, statement), abs(t, sig)))
		if (goErr == nil) != (shErr == nil) {
			t.Errorf("%s with %s as a revocation of %s…'s certificates: the Go client says %v, the script %v", v.statement, v.sig, v.addr[:8], goErr, shErr)
			continue
		}
		if goErr != nil {
			continue
		}
		taken++
		if strings.TrimSpace(out) != fmt.Sprint(got.Through) {
			t.Errorf("%s: the Go client reads through %d, the script %q", v.statement, got.Through, out)
		}
		if v.statement == "ok-through-4.txt" {
			four = got
		}
	}
	if taken != 3 || four == nil {
		t.Fatalf("%d vectors taken as revocations of certificates, want the three that are", taken)
	}

	// A kept one revokes the same serials for both, at 2^53 - 1 too.
	box := t.TempDir()
	kept := filepath.Join(box, "peers", a)
	if err := os.MkdirAll(kept, 0o700); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// A box keeps it as the record that carries it, one line of JSON.
	keep := func(statement, sig []byte) {
		t.Helper()
		line, err := json.Marshal(protocol.Revocations{Identity: read(aDoc), RevokedCertificates: statement, RevokedCertificatesSignature: sig})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(kept, "revoked-certs.json"), append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(kept, "identity.doc"), read(aDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"DR_HOME=" + box}
	for _, c := range []struct {
		name  string
		certs *protocol.RevokedCertificates
	}{{"ok-through-4", four}, {"ok-through-the-highest", &protocol.RevokedCertificates{Through: protocol.MaxSerial}}} {
		keep(read(filepath.Join(vectors, "revoked", c.name+".txt")), read(filepath.Join(vectors, "revoked", c.name+".sig")))
		for _, serial := range []uint64{1, 3, 4, 5, protocol.MaxSerial - 1, protocol.MaxSerial} {
			out, err := bash(t, env, fmt.Sprintf(`dr_certrevoked %s %d; echo $?`, a, serial))
			if err != nil {
				t.Fatal(err)
			}
			want := "1"
			if c.certs.Revokes(serial) {
				want = "0"
			}
			if strings.TrimSpace(out) != want {
				t.Errorf("%s, serial %d: the Go client says revoked is %v, and the script's dr_certrevoked returned %s", c.name, serial, c.certs.Revokes(serial), strings.TrimSpace(out))
			}
		}
	}
	// A kept one that no longer verifies is a fault, never "not revoked":
	// one under another's signature, and a file that holds none.
	keep(read(filepath.Join(vectors, "revoked", "ok-through-4.txt")), read(filepath.Join(vectors, "revoked", "ok-through-the-highest.sig")))
	if out, err := bash(t, env, fmt.Sprintf(`dr_certrevoked %s 3; echo $?`, a)); err != nil || strings.TrimSpace(out) != "3" {
		t.Errorf("a kept revocation under another's signature: dr_certrevoked returned %q %v, want 3", out, err)
	}
	if err := os.WriteFile(filepath.Join(kept, "revoked-certs.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := bash(t, env, fmt.Sprintf(`dr_certrevoked %s 3; echo $?`, a)); err != nil || strings.TrimSpace(out) != "3" {
		t.Errorf("a kept file that holds no revocation of certificates: dr_certrevoked returned %q %v, want 3", out, err)
	}

	// Control: the working key's signature is one ssh-keygen takes once the
	// identity is named a certificate authority, so it is the signers line
	// that refuses it and not a bad signature.
	verify := fmt.Sprintf(`mkdir -p "$DR"; printf '%%s cert-authority %%s\n' %s "$(sed -n 2p %s)" > "$DR/s" && ssh-keygen -Y verify -f "$DR/s" -I %s -n %s:%s -s %s -O verify-time=20261010000000Z < %s`,
		a, aDoc, a, protocol.RevokedCertsTag, a, abs(t, filepath.Join(vectors, "revoked/bad-by-a-working-key.sig")), abs(t, filepath.Join(vectors, "revoked/bad-by-a-working-key.txt")))
	if _, err := bash(t, scratch(t), verify); err != nil {
		t.Errorf("control: ssh-keygen refuses the working key's signature even under a cert-authority line, so the vector tests nothing: %v", err)
	}
}

// Certificates revoked, across the two clients and one server: the Go
// client's revocation is one the script checks for itself, keeps and applies, and
// each follows the other to a later certificate, naming a prekey by both
// serials.
func TestRevokedCertificatesInBothClients(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	kt := protocol.PostQuantum
	dir := t.TempDir()
	sh := func(commands string) (string, error) {
		return bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}, commands)
	}
	out, err := sh("dr_init")
	if err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	script, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, out), srv.URL+protocol.LinkPath))
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), opt, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, g)
	gAddr := g.Address().String()
	first := numberOf(t, g)

	// Mail under the Go box's first certificate, then a renewal and the
	// revocation of every certificate before the new one, then mail under
	// the second: the script reads all of it in one drain.
	if _, err := g.Send(ctx, script, "under the first certificate"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Rekey(ctx, kt); err != nil {
		t.Fatal(err)
	}
	certs, err := g.RevokeEarlier(ctx)
	if err != nil || certs == nil || !certs.Revokes(first) || certs.Revokes(numberOf(t, g)) {
		t.Fatalf("RevokeEarlier: %+v %v", certs, err)
	}
	if _, err := g.Send(ctx, script, "under the second certificate"); err != nil {
		t.Fatal(err)
	}
	out, err = sh("dr_recv 2>&1")
	if err != nil || strings.Count(out, `"code":"certificate_revoked"`) != 1 || !strings.Contains(out, `"body":"under the second certificate"`) || strings.Contains(out, "under the first certificate") {
		t.Fatalf("the script's drain of mail from a box that revoked its first certificate: %q %v", out, err)
	}
	// The script keeps it as the Go client does: one file, the record that
	// carries it, which verifies with nothing else.
	raw, err := os.ReadFile(filepath.Join(dir, "peers", gAddr, "revoked-certs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kept protocol.Revocations
	if err := json.Unmarshal(raw, &kept); err != nil || bytes.Count(raw, []byte("\n")) != 1 || !bytes.Equal(kept.RevokedCertificates, certs.Statement()) {
		t.Fatalf("the script did not keep the Go client's revocation of certificates as one record: %q %v", raw, err)
	}
	if _, err := protocol.VerifyRevokedCertificates(g.Address(), kept.Identity, kept.RevokedCertificates, kept.RevokedCertificatesSignature); err != nil {
		t.Fatalf("the record the script kept does not verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "peers", gAddr, "revoke.sig")); err == nil {
		t.Fatal("the script took a revocation of certificates as a revocation of the address")
	}

	// The script writes to the Go box under its second certificate, and the
	// Go box reads it: the send named both serials, or the server would
	// have called the prekey stale without end.
	if _, err := sh("printf 'to the box at its second certificate' | dr_send " + gAddr); err != nil {
		t.Fatalf("the script's send to a box that moved to a later certificate: %v", err)
	}
	if out, err := sh(fmt.Sprintf(`cat "$DR/peers/%s/serial" "$DR/peers/%s/cert-serial"`, gAddr, gAddr)); err != nil || out != fmt.Sprintf("%d\n%d\n", numberOf(t, g), numberOf(t, g)) {
		t.Fatalf("what the script recorded of the box's statement: %q %v", out, err)
	}
	res, err := g.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 || string(res.Delivered[0].Envelope.Body) != `"to the box at its second certificate"` {
		t.Fatalf("the Go client's drain of the script's mail: %+v %v", res, err)
	}

	// The script's box renews, and the Go client follows it.
	if _, err := sh("dr_rekey"); err != nil {
		t.Fatalf("dr_rekey: %v", err)
	}
	if _, err := g.Send(ctx, script, "to the script's box at its second certificate"); err != nil {
		t.Fatalf("the Go client's send to a script box that renewed: %v", err)
	}
	out, err = sh("dr_recv 2>&1")
	if err != nil || !strings.Contains(out, `"body":"to the script's box at its second certificate"`) {
		t.Fatalf("the script's drain after its renewal: %q %v", out, err)
	}
}

// numberOf is the number of the prekey a Go box published last, which is its
// working key's and its certificate's too: its serial file. A box takes each
// number from its clock, so a test reads the number and never assumes one.
func numberOf(t *testing.T, b *client.Box) uint64 {
	t.Helper()
	st, err := b.Status(t.Context())
	if err != nil || st.PrekeySerial == 0 {
		t.Fatalf("the Go box's status: %+v, %v", st, err)
	}
	return st.PrekeySerial
}

// A JSON body the Go client sends reaches the script as the value it is
// (PROTOCOL.md §3.3). The Go client's own refusals are client/sent_test.go's.
func TestAJSONBodyFromTheGoClient(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	kt := protocol.PostQuantum
	dir := t.TempDir()
	sh := func(commands string) (string, error) {
		return bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}, commands)
	}
	if _, err := sh("dr_init"); err != nil {
		t.Fatal(err)
	}
	s, err := protocol.ParseAddress(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "address")))))
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, g)
	value := func(b []byte) any {
		t.Helper()
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("not JSON: %s", b)
		}
		return v
	}
	scriptGot := func() []any { // the bodies of the mail lines dr_recv prints
		t.Helper()
		out, err := sh("dr_recv")
		if err != nil {
			t.Fatalf("dr_recv: %v", err)
		}
		var bodies []any
		for l := range strings.Lines(out) {
			var line struct {
				Type     string
				Envelope struct{ Body json.RawMessage }
			}
			if err := json.Unmarshal([]byte(l), &line); err != nil || line.Type != "mail" {
				t.Fatalf("dr_recv printed %q", out)
			}
			bodies = append(bodies, value(line.Envelope.Body))
		}
		return bodies
	}

	in := "{\"action\": \"approve\",\n \"ids\": [3, 1.50, 2e3], \"note\": \"<&>\", \"none\": null}\n"
	if _, err := g.SendJSON(ctx, s, []byte(in), client.Fields{}); err != nil {
		t.Fatal(err)
	}
	if got := scriptGot(); len(got) != 1 || !reflect.DeepEqual(got[0], value([]byte(in))) {
		t.Fatalf("the script received %v", got)
	}
}

// landAll gives a Go box the policy that lands every sender's mail in
// inbox/: these tests are of what the two clients send each other, and where
// mail from a sender not allowed lands is the Go client's own (client/).
func landAll(t *testing.T, b *client.Box) {
	t.Helper()
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		t.Fatal(err)
	}
}

// dromas.sh run as a command takes the Go client's command line for the
// commands it has, and gives help as the Go client does: asked for, on stdout
// with exit 0, and --help after a command runs nothing, as -h does, which
// says on stderr that --help is the flag; a bare group, or a command it does
// not have, on stderr with exit 2.
func TestTheCommandLine(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	home := t.TempDir()
	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{abs(t, "dromas.sh")}, args...)...)
		cmd.Env = append(os.Environ(), "DR_HOME="+home, "DR_BASE="+srv.URL)
		cmd.Stdin = strings.NewReader(stdin)
		var out, errs bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errs
		err := cmd.Run()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatal(err)
		}
		return out.String(), errs.String(), cmd.ProcessState.ExitCode()
	}
	if _, errs, code := run("", "init", "--no-pq"); code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, g)
	for want, lines := range map[string][][]string{
		"bash dromas.sh init ":         {{"help"}, {"-h"}, {"--help"}},
		"bash dromas.sh send ":         {{"help", "send"}, {"send", g.Link(), "-h"}, {"send", g.Link(), "--help"}},
		"bash dromas.sh prekey renew ": {{"help", "prekey"}, {"prekey", "help"}, {"prekey", "renew", "--help"}},
	} {
		for _, line := range lines {
			pointer := ""
			if strings.Contains(" "+strings.Join(line, " ")+" ", " -h ") {
				pointer = "Flag shorthand -h has been deprecated, use --help\n"
			}
			if out, errs, code := run("", line...); code != 0 || errs != pointer || !strings.HasPrefix(out, want) {
				t.Errorf("dromas.sh %v: %d %q\n%s", line, code, errs, out)
			}
		}
	}
	// A line that is wrong runs nothing: no command, one the script does not
	// have, a word a command does not take, or the wrong number of them.
	for _, line := range [][]string{nil, {"alias"}, {"alias", "add", "bob", g.Link()}, {"revocation", "publish", g.Address().String()}, {"outbox", "flush"}, {"nosuch"}, {"help", "nosuch"}, {"rekey"},
		{"send"}, {"send", g.Link(), "body", "more"}, {"send", "--subject", "x", g.Link()}, {"send", g.Link(), "--json"}, {"recv", "--headers"}, {"addr", "x"}, {"init", "--classic"}, {"prekey", "renew", "--now"}} {
		if out, errs, code := run("never sent", line...); code != 2 || out != "" || !strings.HasPrefix(errs, `{"type":"usage_error",`) || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, `"help":"bash dromas.sh help`) {
			t.Errorf("dromas.sh %v: %d %q, stderr %q", line, code, out, errs)
		}
	}
	if _, errs, _ := run("", "send"); errs != `{"type":"usage_error","usage":"bash dromas.sh send <link> [file]","help":"bash dromas.sh help send","message":"dromas.sh send takes 1 to 2 arguments, and was given 0"}`+"\n" {
		t.Errorf("a wrong number of arguments: %q", errs)
	}
	if res, err := g.Receive(ctx); err != nil || len(res.Delivered) != 0 {
		t.Fatalf("a wrong command line sent mail: %v %v", res, err)
	}
	// And the commands run.
	if out, errs, code := run("from the command line", "send", g.Link()); code != 0 || !strings.HasPrefix(out, `{"type":"sent","id":"`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("send: %d %q %s", code, out, errs)
	}
	if res, err := g.Receive(ctx); err != nil || len(res.Delivered) != 1 {
		t.Fatalf("the Go box did not get the script's mail: %v %v", res, err)
	}
	if out, errs, code := run("", "prekey", "renew", "--no-pq"); code != 0 || !strings.HasPrefix(out, `{"type":"prekey","serial":`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("prekey renew: %d %q %s", code, out, errs)
	}
	if out, errs, code := run("", "recv"); code != 0 || out != "" {
		t.Fatalf("recv: %d %q %s", code, out, errs)
	}
}

// A send that starts while recv drains waits for the drain's lock, so it
// cannot rewrite a file the drain has yet to read (#96, and #62's other
// direction): the drain still sees the sender's revocation and refuses its
// mail. The hook runs a whole send, in a shell of its own on the same box,
// after the drain has read the sender's revocation and before it takes it.
func TestASendDuringADrainHidesNoRevocation(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx, srv := context.Background(), fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	env := []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + srv.URL, "DR_LOCK_WAIT=2"}
	out, err := bash(t, env, "dr_init --no-pq")
	if err != nil {
		t.Fatal(err)
	}
	s, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, out), srv.URL+protocol.LinkPath))
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic) // the script box sends here
	if err != nil {
		t.Fatal(err)
	}
	g, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic) // writes, then revokes itself
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Send(ctx, s, "sent before the revocation"); err != nil {
		t.Fatal(err)
	}
	rec, err := g.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Revoke(ctx, opt, rec); err != nil {
		t.Fatal(err)
	}
	sendErr := filepath.Join(t.TempDir(), "send.err")
	hook := `eval "orig_take() $(declare -f dr_take | tail -n +2)"
dr_take(){ bash -c '. ` + abs(t, "dromas.sh") + `; printf x | dr_send ` + c.Address().String() + `' > /dev/null 2>> ` + sendErr + `; orig_take "$@"; }
dr_recv`
	if out, _ := bash(t, env, hook); strings.Contains(out, g.Address().String()) {
		t.Error("mail from a revoked sender delivered")
	}
	if e, _ := os.ReadFile(sendErr); !strings.Contains(string(e), "waiting for this box's lock") {
		t.Errorf("the send beside the drain did not wait for the lock: %q", e)
	}
}

// The script's pass names the server as the Go client's does, as an origin is
// written: its host, lowercase, with no user before it, and its port as a
// number only when that is not the scheme's default (PROTOCOL.md §8;
// client's TestAPassNamesTheServerAsAnOrigin holds the Go client to the same).
func TestTheScriptsPassNamesTheServerAsAnOrigin(t *testing.T) {
	need(t, "bash")
	for base, want := range map[string]string{
		"https://dromas.dev":              "dromas.dev",
		"https://dromas.dev:443":          "dromas.dev",
		"https://Dromas.dev:0443/":        "dromas.dev",
		"https://someone@dromas.dev:8443": "dromas.dev:8443",
		"https://dromas.dev:80":           "dromas.dev:80",
		"http://dromas:8080":              "dromas:8080",
		"http://dromas:80":                "dromas",
		"http://dromas:":                  "dromas",
		"http://[::1]:8080":               "[::1]:8080",
		"https://[::1]:443":               "[::1]",
	} {
		if got, err := bash(t, nil, "dr_server '"+base+"'"); err != nil || got != want+"\n" {
			t.Errorf("%s: the pass names %q, %v; want %q", base, got, err, want)
		}
	}
}

// Both clients call a server over https, or over http only on this machine
// (PROTOCOL.md §11.1), so a pass never crosses a network in the clear. The
// script refuses another before any command runs.
func TestBothClientsCallTheSameServers(t *testing.T) {
	need(t, "bash", "jq")
	const refusal = "is not a server this client calls"
	for _, u := range []string{
		"https://dromas.dev", "HTTPS://dromas.dev", "https://10.0.0.1:8443", "https://someone@dromas.dev",
		"http://127.0.0.1:8080", "http://127.255.0.9", "http://[::1]:8080", "http://[::1]", "http://someone@127.0.0.1:1",
		"http://example.com", "http://dromas:8080", "http://10.0.0.1:8080", "http://127.0.0.256", "http://127.01.0.1",
		"http://127.0.0.1.example", "http://localhost.example", "http://localhost:1", "http://LOCALHOST", "http://[::2]:8080", "http://[::ffff:127.0.0.1]:8080",
		"ftp://dromas.dev", "dromas.dev", "https://", "http://",
	} {
		_, err := client.Open(t.TempDir(), client.Options{Base: u})
		goTakes := err == nil || !strings.Contains(err.Error(), refusal)
		_, shErr := bash(t, []string{"U=" + u}, `dr_tls "$U"`)
		if goTakes != (shErr == nil) {
			t.Errorf("%q as the box's server: the Go client %v, the script %v", u, err, shErr)
		}
		if !goTakes && (shErr == nil || !strings.Contains(shErr.Error(), refusal)) {
			t.Errorf("%q: the script's refusal: %v", u, shErr)
		}
	}
	// Each call is held to it too, as the Go client's are: dr_api calls no
	// curl for a server out of form, whoever named it.
	if _, err := bash(t, []string{"DR_HOME=" + t.TempDir()}, `curl(){ echo "curl was called" >&2; return 7; }; DR_BASE=http://example.com dr_api GET /v1/x`); err == nil || !strings.Contains(err.Error(), refusal) || strings.Contains(err.Error(), "curl was called") {
		t.Errorf("dr_api to a server over http elsewhere: %v", err)
	}
	cmd := exec.Command("bash", abs(t, "dromas.sh"), "addr")
	cmd.Env = append(os.Environ(), "DR_HOME="+t.TempDir(), "DR_BASE=http://example.com")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), refusal) {
		t.Errorf("dromas.sh addr with a server over http elsewhere: %v %q", err, out)
	}
}

// The script follows no redirect, and takes none as an answer: curl, with
// no -L, exits 0 on a 3xx, whose body is not the API's. The issue's repro,
// as the Go client's test has it: nothing reaches the other server, and
// the read fails with the redirect's status.
func TestTheScriptFollowsNoRedirect(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	var mu sync.Mutex
	var reached []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(other.Close)
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if strings.HasSuffix(r.URL.Path, "/messages") {
				// A body a list would take, so that only the status can refuse it.
				w.Header().Set("Location", other.URL+r.URL.RequestURI())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"messages":[]}`))
				return
			}
			next.ServeHTTP(w, r)
		})
		_, err := bash(t, env, "dr_recv")
		if err == nil || !strings.Contains(err.Error(), `"status":`+strconv.Itoa(status)) || !strings.Contains(err.Error(), "a redirect, which this client never follows") {
			t.Errorf("a drain answered %d: %v", status, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reached) != 0 {
		t.Fatalf("a redirect was followed: %q", reached)
	}
}

// Every other call the script makes is held to it too, for each status a
// redirect has (PROTOCOL.md §11.1): the read of a recipient before a send and
// the post itself, which post nothing anywhere and keep nothing.
func TestNoCallOfTheScriptFollowsARedirect(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	kt := protocol.PostQuantum
	var mu sync.Mutex
	var reached []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(other.Close)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	r, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, kt)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, r)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, call := range []struct {
			name string
			on   func(*http.Request) bool
		}{
			{"the read of the recipient", func(q *http.Request) bool {
				return q.Method == http.MethodGet && q.URL.Path == "/v1/"+r.Address().String()
			}},
			{"the post", func(q *http.Request) bool {
				return q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, "/messages")
			}},
		} {
			srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
				if call.on(q) {
					http.Redirect(w, q, other.URL+q.URL.RequestURI(), status)
					return
				}
				next.ServeHTTP(w, q)
			})
			_, err := bash(t, env, "printf 'never posted' | dr_send "+r.Link())
			if err == nil || !strings.Contains(err.Error(), `"status":`+strconv.Itoa(status)) || !strings.Contains(err.Error(), "a redirect, which this client never follows") {
				t.Errorf("%d on %s: %v", status, call.name, err)
			}
			if exists(filepath.Join(dir, "outbox")) || exists(filepath.Join(dir, "send.P")) {
				t.Errorf("%d on %s: something was kept to post again", status, call.name)
			}
		}
		srv.SetMiddle(nil)
		if n := srv.Count(r.Address()); n != 0 {
			t.Fatalf("%d: the recipient's server holds %d messages", status, n)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reached) != 0 {
		t.Fatalf("a redirect was followed: %q", reached)
	}
}

// stderr carries only the script's own JSON lines (AGENTS.md § What a box
// prints), whatever an error's answer holds, a body or none.
func TestAnAnswerWithNoBodyPutsOnlyJSONOnStderr(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	for _, status := range []int{http.StatusNotModified, http.StatusNotFound, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		t.Cleanup(srv.Close)
		cmd := exec.Command("bash", "-c", ". "+abs(t, "dromas.sh")+"\ndr_api GET /v1/x")
		cmd.Env = append(os.Environ(), "DR_HOME="+t.TempDir(), "DR_BASE="+srv.URL)
		var errs bytes.Buffer
		cmd.Stderr = &errs
		_ = cmd.Run()
		for l := range strings.Lines(errs.String()) {
			if !strings.HasPrefix(l, "{") {
				t.Errorf("%d: stderr has %q", status, l)
			}
		}
		if !strings.Contains(errs.String(), `"status":`+strconv.Itoa(status)+`,`) {
			t.Errorf("%d: no error line with its status: %q", status, errs.String())
		}
	}
}

// A server that is not there is no answer, with no status and none of curl's
// words, which can quote what a server sent (#289): curl's -w writes 000 for
// the status it never read.
func TestAServerThatIsNotThereIsNoAnswer(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + l.Addr().String()
	_ = l.Close()
	_, err = bash(t, []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + base}, "dr_api GET /v1/x")
	if err == nil || !strings.Contains(err.Error(), `{"type":"error","message":"no answer from `+base+`"}`) || strings.Contains(err.Error(), "curl") || strings.Contains(err.Error(), `"status":`) {
		t.Errorf("a server that is not there: %v", err)
	}
}

// A 3xx is no answer, whatever header or trailer line comes with it
// (PROTOCOL.md §11.1): its status is the final answer's own status line, as
// curl read it, never a line of its header block that looks like one.
func TestA3xxIsNoAnswerWhateverItsLines(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	env := []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + srv.URL}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatal(err)
	}
	list := `{"messages":[],"count":0}`
	for _, c := range []struct{ name, status, raw string }{
		{"a header line", "303", "HTTP/1.1 303 See Other\r\nLocation: /x\r\nRetry-After: 5\r\nHTTP/2 201: x\r\nContent-Length: " + strconv.Itoa(len(list)) + "\r\nConnection: close\r\n\r\n" + list},
		{"a trailer", "307", "HTTP/1.1 307 Temporary Redirect\r\nLocation: /x\r\nRetry-After: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + strconv.FormatInt(int64(len(list)), 16) + "\r\n" + list + "\r\n0\r\nHTTP/1.1 200 OK: x\r\n\r\n"},
	} {
		srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if !strings.HasSuffix(r.URL.Path, "/messages") {
				next.ServeHTTP(w, r)
				return
			}
			conn, bw, _ := w.(http.Hijacker).Hijack()
			_, _ = bw.WriteString(c.raw)
			_ = bw.Flush()
			_ = conn.Close()
		})
		if out, err := bash(t, env, "dr_recv"); err == nil || !strings.Contains(err.Error(), `"status":`+c.status+`,`) {
			t.Errorf("%s: a drain answered %s: %q, %v", c.name, c.status, out, err)
		}
	}
}

// The user's curl config changes nothing the script does (PROTOCOL.md §11.1):
// -q comes first, or curl reads .curlrc.
func TestTheScriptReadsNoCurlrc(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	curlrc := func(line string) string {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".curlrc"), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return "CURL_HOME=" + home
	}

	// location-trusted: the list's 307 is followed, and the pass goes with it.
	srv := fakeserver.New(t, time.Now)
	var mu sync.Mutex
	var got []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+strings.SplitN(r.Header.Get("Authorization"), ",", 2)[0])
		mu.Unlock()
		w.Header().Set("Retry-After", "60")
		_, _ = w.Write([]byte(`{"messages":[]}`))
	}))
	t.Cleanup(other.Close)
	env := []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + srv.URL, curlrc("location-trusted")}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatal(err)
	}
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.HasSuffix(r.URL.Path, "/messages") {
			http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err := bash(t, env, "dr_recv")
	mu.Lock()
	if err == nil || len(got) > 0 {
		t.Errorf("location-trusted: recv %v; the other server got %q", err, got)
	}
	mu.Unlock()

	// insecure: a server whose certificate nobody signed is called, with the pass.
	u, _ := url.Parse(fakeserver.New(t, time.Now).URL)
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	t.Cleanup(front.Close)
	env = []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + front.URL, curlrc("insecure")}
	if out, err := bash(t, env, "dr_init && dr_recv"); err == nil {
		t.Errorf("insecure: a server whose certificate nobody signed made a box and drained it: %q", out)
	}
}

// A server on this machine is called directly, never through a proxy the
// environment names, as the Go client calls it (PROTOCOL.md §11.1): over http,
// over https, and by the name localhost. A server elsewhere still goes
// through it, which shows the proxy is one curl uses.
func TestTheScriptCallsThisMachineDirectly(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	var mu sync.Mutex
	var got []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.RequestURI+" "+strings.SplitN(r.Header.Get("Authorization"), ",", 2)[0])
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	taken := func() []string {
		mu.Lock()
		defer mu.Unlock()
		g := got
		got = nil
		return g
	}
	srv := fakeserver.New(t, time.Now)
	u, _ := url.Parse(srv.URL)
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	t.Cleanup(front.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	register := func(base string) (string, error) {
		env := []string{"DR_HOME=" + t.TempDir(), "DR_BASE=" + base, "CURL_CA_BUNDLE=" + ca, "no_proxy=", "NO_PROXY="}
		for _, v := range []string{"http_proxy", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"} {
			env = append(env, v+"="+proxy.URL)
		}
		return bash(t, env, "dr_init")
	}
	for _, base := range []string{srv.URL, front.URL} {
		out, err := register(base)
		if g := taken(); err != nil || len(g) > 0 {
			t.Errorf("%s: init %q, %v; the proxy got %q", base, out, err, g)
		}
	}
	_, port, _ := strings.Cut(strings.TrimPrefix(front.URL, "https://"), ":")
	_, _ = register("https://localhost:" + port) // its certificate names no localhost: only where the call went is asked
	if g := taken(); len(g) > 0 {
		t.Errorf("localhost: the proxy got %q", g)
	}
	_, err := register("https://dromas.invalid")
	g := taken()
	if err == nil || len(g) == 0 {
		t.Errorf("a server elsewhere: %v; the proxy got %q", err, g)
	}
	for _, l := range g {
		if !strings.HasPrefix(l, "CONNECT dromas.invalid:443 ") {
			t.Errorf("a server elsewhere: the proxy got %q", l)
		}
	}
}

// A renewal the server did not take waits, signed for 33 days, and the owner
// then writes the shortest lifetime: the script's next renewal spends the one
// that waited and signs a new key for the lifetime now set, as the Go client
// does (PROTOCOL.md §12.4).
func TestTheScriptHoldsALowerLifetimeOverAWaitingRenewal(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}
	if _, err := bash(t, env, "dr_init"); err != nil {
		t.Fatalf("dr_init: %v", err)
	}
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := bash(t, env, "sleep 1; dr_rekey"); err == nil {
		t.Fatal("the renewal went through")
	}
	if err := os.WriteFile(filepath.Join(dir, "prekey-lifetime"), []byte("97200\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.SetMiddle(nil)
	if _, err := bash(t, env, "dr_rekey"); err != nil {
		t.Fatalf("dr_rekey: %v", err)
	}
	// Read from the script box's own files: its serial, and that prekey's
	// record of when it was signed and its statement.
	serial, err := os.ReadFile(filepath.Join(dir, "serial"))
	if err != nil {
		t.Fatal(err)
	}
	stem := filepath.Join(dir, "prekeys", strings.TrimSpace(string(serial)))
	rawMade, err := os.ReadFile(stem + ".made")
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile(stem + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	p, err := protocol.ParsePrekey(statement)
	if err != nil {
		t.Fatal(err)
	}
	made, err := protocol.ParseTime(strings.TrimSpace(string(rawMade)))
	if err != nil || p.NotAfter.Sub(made) > 27*time.Hour {
		t.Errorf("the script published a prekey made for %v after the lifetime was set to 1d3h: %v", p.NotAfter.Sub(made), err)
	}
}
