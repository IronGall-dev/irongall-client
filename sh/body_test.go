package sh_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// A send's body in the script: read once, from the file named or stdin, as
// the Go client reads it (os.ReadFile), and refused in the script's own
// words when it is not one it sends.

// sendBox is a box directory holding vector a's identity, enough for
// ig_send told it holds the lock, and the addresses of vectors a and b.
func sendBox(t *testing.T) (dir string, a, b protocol.Address) {
	t.Helper()
	dir = t.TempDir()
	for _, f := range []string{"identity.doc", "address"} {
		if err := os.WriteFile(filepath.Join(dir, f), mustRead(t, filepath.Join(vectors, "a", f)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range []struct {
		box  string
		addr *protocol.Address
	}{{"a", &a}, {"b", &b}} {
		ad, err := protocol.ParseAddress(strings.TrimSpace(string(mustRead(t, filepath.Join(vectors, x.box, "address")))))
		if err != nil {
			t.Fatal(err)
		}
		*x.addr = ad
	}
	return dir, a, b
}

// keepPost is ig_post replaced, for a test that runs ig_send: the envelope
// it would post, copied to $OUT, and nothing posted.
const keepPost = "IG_HELD=$IG; ig_post(){ cp \"$2.P\" \"$OUT\"; mv \"$2.P\" \"$2.sent\"; }\n"

// ig_send sends the body it checked, read once (#255): a body from a pipe
// is sent, not as "" and not refused; one named $IG/body.txt, the file a
// body on stdin is kept in, is not emptied first; and a file changed after
// ig_json read it is sent as it was checked.
func TestTheScriptReadsTheBodyOnce(t *testing.T) {
	need(t, scriptTools...)
	dir, a, b := sendBox(t)
	out := t.TempDir()
	sent := func(name, o, want string, err error) {
		t.Helper()
		p, rerr := os.ReadFile(o) //nolint:gosec // the test's own
		if rerr != nil {
			t.Errorf("%s: nothing sent: %v", name, err)
			return
		}
		env, perr := protocol.OpenEnvelopeRecord(p, a, b)
		if perr != nil || string(env.Body) != want {
			t.Errorf("%s: sent the body %s, want %s (%v)", name, env.Body, want, perr)
		}
	}
	for i, c := range []struct{ name, command, want string }{
		{"a pipe", `ig_send "$B" <(printf hello)`, `"hello"`},
		{"a pipe, --json", `ig_send --json "$B" <(printf '{"a":1}')`, `{"a":1}`},
		{"stdin", `printf hello | ig_send "$B"`, `"hello"`},
		{"the box's own body.txt", `printf kept > "$IG/body.txt"; ig_send "$B" "$IG/body.txt"`, `"kept"`},
	} {
		o := filepath.Join(out, fmt.Sprint(i))
		_, err := bash(t, []string{"IRONGALL_HOME=" + dir, "OUT=" + o, "B=" + b.String()}, keepPost+c.command)
		sent(c.name, o, c.want, err)
	}
	// The file changes once ig_json has read the body: the body sent is the
	// one it checked, never the file as it then is, which names a member twice.
	f := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(f, []byte(`{"action":"approve"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	o := filepath.Join(out, "changed")
	change := `eval "$(declare -f ig_json | sed '1s/^ig_json/ig_json_checked/')"
ig_json(){ ig_json_checked "$@" && { [ "$1" != "$IG/body.json" ] || printf '{"action":"approve","action":"reject"}' > "$F"; }; }
`
	_, err := bash(t, []string{"IRONGALL_HOME=" + dir, "OUT=" + o, "B=" + b.String(), "F=" + f}, keepPost+change+`ig_send --json "$B" "$F"`)
	sent("a file changed after its check", o, `{"action":"approve"}`, err)
}

// A body the script does not send is refused in its own words, one error
// line on stderr, with nothing kept and nothing left in the box: a --json
// body that would make a second member in the body's place (#254), and a
// body file it cannot read (#274).
func TestARefusedBodyIsOneErrorLine(t *testing.T) {
	need(t, scriptTools...)
	dir, _, b := sendBox(t)
	body := filepath.Join(t.TempDir(), "body")
	for _, c := range []struct{ name, body, args, words string }{
		{`1,"x":2`, `1,"x":2`, `--json "$B" "$F"`, "the body is not one JSON value its reader takes"},
		{`1,"v":2,"to":"x"`, `1,"v":2,"to":"x"`, `--json "$B" "$F"`, "the body is not one JSON value its reader takes"},
		{`{"body":{}},"x":1`, `{"body":{}},"x":1`, `--json "$B" "$F"`, "the body is not one JSON value its reader takes"},
		{"{}x, which ig_json refuses", `{}x`, `--json "$B" "$F"`, "the body is not one JSON value its reader takes"},
		{"a body file that is not there", "", `"$B" "$F.not-there"`, "the body file " + body + ".not-there could not be read: nothing is sent"},
		{"a body file that is a directory", "", `"$B" "$(dirname "$F")"`, "the body file " + filepath.Dir(body) + " could not be read: nothing is sent"},
	} {
		if err := os.WriteFile(body, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		o := filepath.Join(t.TempDir(), "sent")
		_, err := bash(t, []string{"IRONGALL_HOME=" + dir, "OUT=" + o, "B=" + b.String(), "F=" + body}, keepPost+"ig_send "+c.args)
		errs := ""
		if err != nil {
			_, errs, _ = strings.Cut(err.Error(), ": ")
		}
		var line struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err == nil || exists(o) || strings.Count(errs, "\n") != 0 || protocol.Unmarshal([]byte(errs), &line) != nil || line.Type != "error" || !strings.Contains(line.Message, c.words) {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, f := range []string{"send.P", "body.new"} {
			if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
				t.Errorf("%s: $IG/%s is left in the box", c.name, f)
			}
		}
		if left, _ := filepath.Glob(filepath.Join(dir, "outbox", "*")); len(left) != 0 {
			t.Errorf("%s: kept in the outbox: %v", c.name, left)
		}
	}
}

// A send whose envelope jq does not write, as a jq stopped midway leaves it,
// is one error line, with nothing kept and no send.P left in the box.
func TestASendWhoseEnvelopeIsNotBuiltLeavesNothing(t *testing.T) {
	need(t, scriptTools...)
	dir, _, b := sendBox(t)
	o := filepath.Join(t.TempDir(), "sent")
	_, err := bash(t, []string{"IRONGALL_HOME=" + dir, "OUT=" + o, "B=" + b.String(), "PATH=" + dyingJQ(t, "-cn", "--rawfile", "body") + ":" + os.Getenv("PATH")}, keepPost+`printf hi | ig_send "$B"`)
	if err == nil || exists(o) || !strings.HasSuffix(err.Error(), `: {"type":"error","message":"the envelope could not be built: nothing is sent"}`) {
		t.Errorf("a send whose envelope jq died: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "send.P")); err == nil {
		t.Error("$IG/send.P is left in the box")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "outbox", "*")); len(left) != 0 {
		t.Errorf("kept in the outbox: %v", left)
	}
}
