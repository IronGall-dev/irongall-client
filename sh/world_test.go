package sh_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The script's boxes against internal/fakeserver, one shell per command, as
// agents run it: each test stands up the server and the boxes it needs, and
// plays the hostile operator with a middleware (forge, SetMiddle) or the
// operator's powers over storage. What the server itself enforces is
// dromas-server's to test.

// world is a fake server, the script's boxes on it, and a directory for the
// files a test makes beside them.
type world struct {
	t    *testing.T
	srv  *fakeserver.Server
	work string

	opOnce sync.Once
	op     *operator
	home   string   // where the boxes are, removed after the checks below
	dirs   []string // every box's directory
}

func newWorld(t *testing.T) *world {
	t.Helper()
	need(t, append(scriptTools, "curl")...)
	t.Parallel() // each world is a server and directories of its own
	// The boxes' directory is made before the checks are registered, so that
	// it is removed after they run: cleanups run last first.
	w := &world{t: t, srv: fakeserver.New(t, time.Now), work: t.TempDir(), home: t.TempDir()}
	t.Cleanup(func() {
		// A read of a box carries no pass, of another box or its own
		// (PROTOCOL.md §11.8): asked of every call the test made.
		for _, r := range w.srv.Requests() {
			if isRead(r) && r.Pass {
				t.Errorf("a read of a box was sent a pass: %s %s", r.Method, r.Path)
			}
		}
		// Every file a box keeps is written beside it, synced and moved
		// into place: none is left half done (a pass.new waits for its
		// upload by design).
		for _, d := range w.dirs {
			_ = filepath.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
				if err == nil && strings.HasSuffix(path, ".new") && e.Name() != "pass.new" {
					t.Errorf("a .new left: %s", path)
				}
				return nil
			})
		}
	})
	return w
}

// sbox is one of the script's boxes, a directory of its own.
type sbox struct {
	w    *world
	dir  string
	addr protocol.Address
}

// empty is a box nothing has been made in yet.
func (w *world) empty() *sbox {
	d, err := os.MkdirTemp(w.home, "")
	if err != nil {
		w.t.Fatal(err)
	}
	b := &sbox{w: w, dir: filepath.Join(d, "box")}
	w.dirs = append(w.dirs, b.dir)
	return b
}

// box is a box made by dr_init, registered at the world's server.
func (w *world) box() *sbox {
	w.t.Helper()
	b := w.empty()
	b.must("dr_init")
	b.addr = mustAddress(w.t, b.dir)
	return b
}

// ran is what one command did.
type ran struct {
	out, err string
	rc       int
}

func (r ran) String() string { return fmt.Sprintf("exit %d, stdout %q, stderr %q", r.rc, r.out, r.err) }

// sh runs commands in a fresh shell that has sourced dromas.sh, as box b,
// in the world's work directory. $W is that directory and $SRV the server's
// URL.
func (b *sbox) sh(commands string) ran {
	b.w.t.Helper()
	cmd := exec.Command("bash", "-c", ". "+abs(b.w.t, "dromas.sh")+"\n"+commands)
	cmd.Dir = b.w.work
	cmd.Env = append(os.Environ(), "DR_HOME="+b.dir, "DR_SERVER_URL="+b.w.srv.URL, "W="+b.w.work, "SRV="+b.w.srv.URL)
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	r := ran{}
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			b.w.t.Fatal(err)
		}
		r.rc = ee.ExitCode()
	}
	r.out, r.err = out.String(), errs.String()
	return r
}

// must is sh, failing the test unless the shell exits 0. It returns stdout.
func (b *sbox) must(commands string) string {
	b.w.t.Helper()
	r := b.sh(commands)
	if r.rc != 0 {
		b.w.t.Fatalf("%s: %v", commands, r)
	}
	return r.out
}

// file is the box's file name, relative to its directory.
func (b *sbox) file(name string) string { return filepath.Join(b.dir, name) }

// read is the contents of the box's file, "" when there is none.
func (b *sbox) read(name string) string {
	s, _ := os.ReadFile(b.file(name))
	return string(s)
}

// has reports whether the box has the file and it is not empty.
func (b *sbox) has(name string) bool { return exists(b.file(name)) }

// num is the number of the prekey the box published last, which is its
// working key's and its certificate's too: a box takes each number from its
// clock, so a test reads the number and never assumes one.
func (b *sbox) num() uint64 {
	b.w.t.Helper()
	n, err := strconv.ParseUint(strings.TrimSpace(b.read("serial")), 10, 64)
	if err != nil {
		b.w.t.Fatalf("the box's serial: %v", err)
	}
	return n
}

// files are the names of the files in one of the box's directories.
func (b *sbox) files(dir string) []string {
	es, _ := os.ReadDir(b.file(dir))
	var ns []string
	for _, e := range es {
		ns = append(ns, e.Name())
	}
	return ns
}

// send sends body to the box at to, from a file, as an agent would.
func (b *sbox) send(to string, body string) ran {
	b.w.t.Helper()
	f, err := os.CreateTemp(b.w.work, "body")
	if err != nil {
		b.w.t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		b.w.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.w.t.Fatal(err)
	}
	return b.sh("dr_send " + to + " " + f.Name())
}

// mustSend is send, failing the test unless it is sent.
func (b *sbox) mustSend(to *sbox, body string) {
	b.w.t.Helper()
	if r := b.send(to.addr.String(), body); r.rc != 0 {
		b.w.t.Fatalf("a send to %s: %v", to.addr, r)
	}
}

// drain is one dr_recv: each mail line, and every other line, from stdout
// and stderr both, a refused line written "REFUSED <id>: <code>: <words>".
type drain struct {
	mail []string
	said string
	rc   int
}

func (d drain) String() string {
	return fmt.Sprintf("exit %d, mail %q, said %q", d.rc, d.mail, d.said)
}

// recv runs dr_recv, as cmd if one is given (a clock set before it).
func (b *sbox) recv(prefix ...string) drain {
	b.w.t.Helper()
	r := b.sh(strings.Join(prefix, "") + "dr_recv")
	d := drain{rc: r.rc}
	var said []string
	for l := range strings.Lines(r.out) {
		var j struct{ Type, ID, Code, Message string }
		switch {
		case strings.HasPrefix(l, `{"type":"mail",`):
			d.mail = append(d.mail, l)
		case json.Unmarshal([]byte(l), &j) != nil:
			said = append(said, "NOT A LINE OF JSON: "+l)
		case j.Type == "refused":
			said = append(said, fmt.Sprintf("REFUSED %s: %s: %s\n", j.ID, j.Code, j.Message))
		default:
			said = append(said, l)
		}
	}
	d.said = strings.Join(said, "") + r.err
	return d
}

// bodies are the bodies of the mail a drain delivered, in order.
func (d drain) bodies() []string {
	var bs []string
	for _, l := range d.mail {
		var m struct{ Envelope struct{ Body string } }
		_ = json.Unmarshal([]byte(l), &m)
		bs = append(bs, m.Envelope.Body)
	}
	return bs
}

// refused counts the drain's refusals with the code.
func (d drain) refused(code string) int {
	return strings.Count(d.said, ": "+code+": ")
}

// operator is the server's own keys, for the forgeries: an identity, a
// working key under its certificate, and an age key.
type operator struct {
	dir  string
	addr protocol.Address
}

// operator makes the world's operator once.
func (w *world) operator() *operator {
	w.opOnce.Do(func() {
		o := &operator{dir: filepath.Join(w.work, "op")}
		b := &sbox{w: w, dir: o.dir}
		b.must(`mkdir -p "$DR"; cd "$DR"
ssh-keygen -q -t ed25519 -N '' -C '' -f identity; printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 identity.pub)" > identity.doc; sha256sum < identity.doc | cut -c1-64 > address
ssh-keygen -q -t ed25519 -N '' -C '' -f work
ssh-keygen -q -s identity -I dromas-cert-v1 -n "$(cat address)" -z 1 -V "$(date -u -d '1 hour ago' +%Y%m%d%H%M%SZ):$(date -u -d '64 days' +%Y%m%d%H%M%SZ)" -O clear work.pub
age-keygen -o agekey 2> /dev/null; age-keygen -y agekey > recipient`)
		o.addr = mustAddress(w.t, o.dir)
		w.op = o
	})
	return w.op
}

// recipient is the operator's own age key, as a prekey line holds one.
func (o *operator) recipient() string {
	s, _ := os.ReadFile(filepath.Join(o.dir, "recipient"))
	return strings.TrimSpace(string(s))
}

// reading serves every read of box a through edit, and passes every other
// call to the server.
func (w *world) reading(a protocol.Address, edit func(*protocol.BoxResponse)) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == a {
			forge.Serve(w.t, w.srv, rw, r, next, edit)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// honest takes any middleware away.
func (w *world) honest() { w.srv.SetMiddle(nil) }

// posts is how many posts to box a the server has been sent.
func (w *world) posts(a protocol.Address) int {
	n := 0
	for _, r := range w.srv.Requests() {
		if r.Method == http.MethodPost && r.Path == "/v1/"+a.String()+"/messages" {
			n++
		}
	}
	return n
}

// isRead reports whether a logged call is a read of a box, GET /v1/<address>.
func isRead(r fakeserver.Request) bool {
	rest, ok := strings.CutPrefix(r.Path, "/v1/")
	return ok && r.Method == http.MethodGet && !strings.Contains(rest, "/")
}

// calls is every call the server has been sent since the n-th, one
// "METHOD path" each.
func (w *world) calls(n int) []string {
	var cs []string
	for _, r := range w.srv.Requests()[n:] {
		cs = append(cs, r.Method+" "+r.Path)
	}
	return cs
}
