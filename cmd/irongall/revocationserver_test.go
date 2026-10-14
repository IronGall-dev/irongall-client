package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/IronGall-dev/irongall-client/revocationserver"
)

// The commands, with a revocation server listed beside the box's own server
// in $IRONGALL_REVOCATION_SERVERS: a real one, which a test can take down.
func TestTheCommandsWithARevocationServer(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	x, err := revocationserver.Open(revocationserver.Options{Dir: t.TempDir(), WritesPerHour: -1})
	if err != nil {
		t.Fatal(err)
	}
	var down atomic.Bool
	h := x.Handler()
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { rs.Close(); _ = x.Close() })
	holds := func(a protocol.Address) int {
		t.Helper()
		resp, err := http.Get(rs.URL + "/v1/" + a.String() + "/revocations")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	t.Setenv("IRONGALL_BASE", srv.URL)
	t.Setenv("IRONGALL_REVOCATION_SERVERS", rs.URL)
	opt := client.Options{Base: srv.URL, RevocationServers: []string{rs.URL}}
	box := func() *client.Box {
		t.Helper()
		b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cmd := func(b *client.Box, args ...string) (string, string, error) {
		t.Helper()
		t.Setenv("IRONGALL_HOME", b.Dir())
		var out, errs bytes.Buffer
		err := run(ctx, args[0], args[1:], strings.NewReader("a body"), &out, &errs)
		return out.String(), errs.String(), err
	}
	a, b := box(), box()

	// status says who is asked.
	if out, _, err := cmd(a, "status"); err != nil || !strings.Contains(out, `"revocation_servers":["`+rs.URL+`"]`) {
		t.Fatalf("status: %v %q", err, out)
	}

	// A revocation server that gives no answer: the message goes, and the
	// owner is told on stderr.
	down.Store(true)
	out, warn, err := cmd(a, "send", b.Address().String())
	if err != nil || len(out) != 65 || !strings.Contains(warn, "the revocation server "+rs.URL+" gave no answer, which changes nothing here") {
		t.Fatalf("send with the revocation server down: %v %q %q", err, out, warn)
	}

	// rekey --revoke-earlier with it down: the revocation is at the box's own
	// server, the command fails and says where it is not, and how to send
	// it there.
	out, _, err = cmd(a, "rekey", "--revoke-earlier")
	var part *client.NotPublishedError
	kept := filepath.Join(a.Dir(), "revoked-certs.json")
	if !errors.As(err, &part) || !strings.Contains(err.Error(), "irongall revoked --publish "+kept) || strings.Contains(out, "revoked") {
		t.Fatalf("rekey --revoke-earlier with the revocation server down: %v %q", err, out)
	}
	if holds(a.Address()) != http.StatusServiceUnavailable {
		t.Fatal("the revocation server is not down")
	}
	down.Store(false)
	if holds(a.Address()) != http.StatusNotFound {
		t.Fatal("the revocation server holds a revocation of certificates it never took")
	}
	if out, _, err := cmd(a, "revoked", "--publish", kept); err != nil || !strings.HasPrefix(out, "published the revocation of the certificates of "+a.Address().String()+" through ") {
		t.Fatalf("revoked --publish: %v %q", err, out)
	}
	if holds(a.Address()) != http.StatusOK {
		t.Fatal("the revocation of certificates did not reach the revocation server")
	}
	// With every server up, one command does it.
	if out, _, err := cmd(a, "rekey", "--revoke-earlier"); err != nil || !strings.Contains(out, " revoked\n") || !strings.Contains(out, "certificates through ") {
		t.Fatalf("rekey --revoke-earlier: %v %q", err, out)
	}

	// revoke with it down: the address is revoked at the box's own server,
	// the box keeps its revocation, and the command fails saying where it is
	// not. The same command again, once the server is back, is the cure.
	down.Store(true)
	out, _, err = cmd(a, "revoke", a.Address().String())
	if !errors.As(err, &part) || out != "" || !strings.Contains(err.Error(), "was NOT taken by "+rs.URL) || !strings.Contains(err.Error(), "it was taken by "+srv.URL) {
		t.Fatalf("revoke with the revocation server down: %v %q", err, out)
	}
	if st, _, _ := cmd(a, "status"); !strings.Contains(st, `"revoked":true`) {
		t.Fatalf("a box whose revocation a server took does not hold it: %q", st)
	}
	down.Store(false)
	if out, _, err := cmd(a, "revoke", a.Address().String()); err != nil || out != "revoked "+a.Address().String()+"\n" {
		t.Fatalf("revoke again: %v %q", err, out)
	}
	if holds(a.Address()) != http.StatusOK {
		t.Fatal("the revocation did not reach the revocation server")
	}

	// What ends an address is never published without that address written
	// out: revoked --publish takes a revocation of certificates and nothing more.
	rec, _, err := cmd(b, "revocation")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(file, []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _, err := cmd(box(), "revoked", "--publish", file); err == nil || out != "" || !strings.Contains(err.Error(), "nothing was published") {
		t.Fatalf("revoked --publish of a revocation: %v %q", err, out)
	}
	if holds(b.Address()) != http.StatusNotFound {
		t.Fatal("revoked --publish published a revocation")
	}

	// A list that names no server is an error, said before anything is done.
	for _, v := range []string{"revocations.example", "https://one.example/path", "none,https://one.example"} {
		t.Setenv("IRONGALL_REVOCATION_SERVERS", v)
		if _, _, err := cmd(b, "addr"); err == nil || !strings.Contains(err.Error(), "$IRONGALL_REVOCATION_SERVERS") {
			t.Errorf("IRONGALL_REVOCATION_SERVERS=%q: %v", v, err)
		}
	}
	t.Setenv("IRONGALL_REVOCATION_SERVERS", "none")
	if out, _, err := cmd(b, "status"); err != nil || !strings.Contains(out, `"revocation_servers":[]`) {
		t.Fatalf("status of a box told to ask none: %v %q", err, out)
	}
}

// The help says where the list comes from, and names the default.
func TestHelpNamesTheRevocationServers(t *testing.T) {
	for _, want := range []string{"$IRONGALL_REVOCATION_SERVERS", "revocation-servers file", client.DefaultRevocationServer, "revoked --publish"} {
		if !strings.Contains(usage, want) {
			t.Errorf("the help does not name %s", want)
		}
	}
}
