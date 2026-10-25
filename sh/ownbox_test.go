package sh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The script's box is a directory of its own, by its own variables: its
// default is not the Go client's, nor is a directory the Go client's
// DROMAS_HOME names, and it refuses a directory holding the Go client's
// state file, at init and at every command that writes the box, writing
// nothing there (#331).
func TestTheScriptRunsABoxOfItsOwnOnly(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	home := t.TempDir()
	out, err := bash(t, []string{"HOME=" + home, "DR_HOME=", "DR_BOX=", "XDG_CONFIG_HOME=", "DROMAS_HOME=" + filepath.Join(home, "go-box")}, `printf '%s' "$DR"`)
	if err != nil || out != filepath.Join(home, ".config", "dromas-sh", "default") {
		t.Fatalf("the script's default box: %q, %v", out, err)
	}

	srv := fakeserver.New(t, time.Now)
	g, err := client.Init(context.Background(), t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	files := func() []string {
		var names []string
		_ = filepath.WalkDir(g.Dir(), func(p string, _ os.DirEntry, _ error) error { names = append(names, p); return nil })
		return names
	}
	before, calls := files(), len(srv.Requests())
	for _, cmd := range []string{"dr_init --no-pq", "dr_rekey", "dr_recv"} {
		if out, err := bash(t, []string{"DR_HOME=" + g.Dir(), "DR_BASE=" + srv.URL}, cmd); err == nil || !strings.Contains(err.Error(), "state file") {
			t.Errorf("%s in a Go box: %q, %v", cmd, out, err)
		}
	}
	if after := files(); !slicesEqual(before, after) || len(srv.Requests()) != calls {
		t.Errorf("the script wrote the Go box or asked its server: %d files were %d, %d calls were %d", len(after), len(before), len(srv.Requests()), calls)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// scriptRevocation is the record of the script box in dir's own revocation,
// as its identity signs it.
func scriptRevocation(t *testing.T, dir string) *protocol.Revocations {
	t.Helper()
	key, err := ssh.ParsePrivateKey(mustRead(t, filepath.Join(dir, "identity")))
	if err != nil {
		t.Fatal(err)
	}
	doc := mustRead(t, filepath.Join(dir, "identity.doc"))
	id, err := protocol.ParseIdentity(doc)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevocation(key, id.Address())
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: doc, Revocation: sig}
}

// putRevocation sends rec to the server behind a middleware, as another
// holder of the record would.
func putRevocation(t *testing.T, next http.Handler, rec *protocol.Revocations) {
	t.Helper()
	id, err := protocol.ParseIdentity(rec.Identity)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/"+id.Address().String()+"/revocations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, req)
	if rr.Code >= 300 {
		t.Fatalf("the revocation was answered %d", rr.Code)
	}
}

// A script box shown its own revocation by its server keeps it once it
// verifies, and signs nothing more, there or at a server it is pointed at
// after, which never saw it: at its renewal's read, answered 410 with the
// record; at a registration of its identity alone, refused 410; and at a
// renewal's upload, refused 410 after a clean read (#343).
func TestTheScriptKeepsItsOwnRevocationFromA410(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	for _, at := range []string{"its renewal's read", "a registration of its identity alone", "its renewal's upload"} {
		t.Run(at, func(t *testing.T) {
			srv := fakeserver.New(t, time.Now)
			dir := t.TempDir()
			env := []string{"DR_HOME=" + dir, "DR_BASE=" + srv.URL}
			if out, err := bash(t, env, "dr_init --no-pq"); err != nil {
				t.Fatalf("init: %q, %v", out, err)
			}
			rec := scriptRevocation(t, dir)
			var passes atomic.Int32
			var revoked atomic.Bool
			srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Header.Get("Authorization") != "" {
					passes.Add(1)
				}
				next.ServeHTTP(w, r)
				if at == "its renewal's upload" && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/messages") && revoked.CompareAndSwap(false, true) {
					putRevocation(t, next, rec)
				}
			})
			cmd := "dr_rekey"
			switch at {
			case "its renewal's read":
				if _, err := client.Publish(context.Background(), client.Options{Base: srv.URL}, rec); err != nil {
					t.Fatal(err)
				}
			case "a registration of its identity alone":
				if _, err := client.Publish(context.Background(), client.Options{Base: srv.URL}, rec); err != nil {
					t.Fatal(err)
				}
				restored := t.TempDir()
				if err := os.WriteFile(filepath.Join(restored, "identity"), mustRead(t, filepath.Join(dir, "identity")), 0o600); err != nil {
					t.Fatal(err)
				}
				dir, env, cmd = restored, []string{"DR_HOME=" + restored, "DR_BASE=" + srv.URL}, "dr_init --no-pq"
			}
			passes.Store(0)
			out, err := bash(t, env, cmd)
			if err == nil || !strings.Contains(err.Error(), "REVOKED") {
				t.Fatalf("%s: %q, %v", cmd, out, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "revoked.sig")); err != nil {
				t.Fatalf("the box keeps no revocation of itself: %v", err)
			}
			if at == "its renewal's read" && passes.Load() != 0 {
				t.Errorf("a pass went out after a read that showed the revocation: %d", passes.Load())
			}
			// Pointed at a server that never saw the revocation: nothing is
			// asked there and nothing signed.
			other := fakeserver.New(t, time.Now)
			if _, err := bash(t, []string{"DR_HOME=" + dir, "DR_BASE=" + other.URL}, "dr_rekey"); err == nil || len(other.Requests()) != 0 {
				t.Errorf("at another server: %v, %d calls", err, len(other.Requests()))
			}
		})
	}
}
