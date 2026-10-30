package sh_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// init on a mailbox that holds its own revocation and has published nothing, a
// mailbox restored from its identity alone beside its revocation: the script
// signs nothing more, no certificate and no prekey statement, and nothing
// reaches the server with a pass (PROTOCOL.md §12.5; #256). dr_prekey is the
// one path to its certificates and statements, so prekey renew is held the
// same way.
func TestScriptInitOfAMailboxThatHoldsItsOwnRevocationSignsNothing(t *testing.T) {
	t.Parallel()
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	a, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := a.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, f := range []string{"identity", "identity.pub", "identity.doc", "address"} {
		if err := os.WriteFile(filepath.Join(dir, f), mustRead(t, filepath.Join(a.Dir(), f)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "revoked.sig"), rec.Revocation, 0o600); err != nil {
		t.Fatal(err)
	}
	var passes atomic.Int32
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Header.Get("Authorization") != "" {
			passes.Add(1)
		}
		next.ServeHTTP(w, r)
	})
	env := []string{"DR_HOME=" + dir, "DR_SERVER_URL=" + srv.URL}
	for _, cmd := range []string{"dr_init --no-pq", "dr_renew"} {
		out, err := bash(t, env, cmd)
		made, _ := filepath.Glob(filepath.Join(dir, "work", "*"))
		stmts, _ := filepath.Glob(filepath.Join(dir, "prekeys", "*"))
		if err == nil || passes.Load() != 0 || len(made) != 0 || len(stmts) != 0 {
			t.Errorf("%s on a finished mailbox: %q, %v; %d requests with a pass; it made %v and %v", cmd, out, err, passes.Load(), made, stmts)
		}
	}
}
