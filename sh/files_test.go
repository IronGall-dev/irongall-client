package sh_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box's own files in the script, as the Go client keeps them: made from
// the identity, written beside and moved into place, and made again where a
// crash left one empty.

// addressIn is the address in the box line init prints.
func addressIn(t *testing.T, srv *fakeserver.Server, out string) protocol.Address {
	t.Helper()
	a, err := protocol.ParseAddress(strings.TrimPrefix(linkIn(t, out), srv.URL+protocol.LinkPath))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// stats is each file's os.FileInfo, by name.
func stats(t *testing.T, dir string, names ...string) map[string]os.FileInfo {
	t.Helper()
	m := map[string]os.FileInfo{}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		m[n] = fi
	}
	return m
}

// newestKey is the box's prekey key file of the highest serial.
func newestKey(t *testing.T, dir string) string {
	t.Helper()
	keys, _ := filepath.Glob(filepath.Join(dir, "prekeys", "*.agekey"))
	if len(keys) == 0 {
		t.Fatal("no prekey key file")
	}
	sort.Strings(keys)
	return keys[len(keys)-1]
}

// A box restored from its identity alone, in an empty directory, renews at a
// server that still holds it and at one that forgot it, as the README
// restores a box: the script makes its directories, identity.pub,
// identity.doc and the same address from the identity (#231, #243), mail
// sent to it is delivered, and init on it then rewrites none of them.
func TestTheScriptRestoresABoxFromItsIdentityAlone(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	ctx := context.Background()
	for _, forgotten := range []bool{false, true} {
		srv := fakeserver.New(t, time.Now)
		lost := t.TempDir()
		out, err := bash(t, []string{"IRONGALL_HOME=" + lost, "IG_BASE=" + srv.URL}, "ig_init --no-pq")
		if err != nil {
			t.Fatal(err)
		}
		a := addressIn(t, srv, out)
		if forgotten {
			srv.Forget(a)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "identity"), mustRead(t, filepath.Join(lost, "identity")), 0o600); err != nil {
			t.Fatal(err)
		}
		env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
		if out, err := bash(t, env, "ig_rekey --no-pq"); err != nil || !strings.HasPrefix(out, `{"type":"prekey",`) {
			t.Fatalf("forgotten %v: a renewal of the box restored from its identity alone: %v %q", forgotten, err, out)
		}
		for _, f := range []string{"identity.doc", "address"} {
			if string(mustRead(t, filepath.Join(dir, f))) != string(mustRead(t, filepath.Join(lost, f))) {
				t.Errorf("forgotten %v: the restored box's %s is not the lost machine's", forgotten, f)
			}
		}
		if !exists(filepath.Join(dir, "identity.pub")) {
			t.Errorf("forgotten %v: the restored box has no identity.pub", forgotten)
		}
		g, err := client.Init(ctx, t.TempDir(), client.Options{Base: srv.URL}, protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Send(ctx, a, "after the restore"); err != nil {
			t.Fatalf("forgotten %v: a send to the restored box: %v", forgotten, err)
		}
		if out, err := bash(t, env, "ig_recv"); err != nil || !strings.Contains(out, `"body":"after the restore"`) {
			t.Errorf("forgotten %v: the restored box's recv: %v %q", forgotten, err, out)
		}
		before := stats(t, dir, "identity.doc", "address")
		if out, err := bash(t, env, "ig_init --no-pq"); err != nil || addressIn(t, srv, out) != a {
			t.Errorf("forgotten %v: init on the restored box: %v %q", forgotten, err, out)
		}
		for n, fi := range stats(t, dir, "identity.doc", "address") {
			if !os.SameFile(before[n], fi) || !before[n].ModTime().Equal(fi.ModTime()) {
				t.Errorf("forgotten %v: init on the restored box rewrote %s", forgotten, n)
			}
		}
	}
}

// init run again on a registered box writes neither identity.doc nor
// address, which every other command of the box reads: each is written only
// where its bytes differ, beside and moved into place (#234). Held where it
// hashes the document, it leaves both whole for whoever reads them then.
// And it makes an address that is gone again.
func TestAnInitRunAgainRewritesNothing(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatal(err)
	}
	files := []string{"identity.doc", "address"}
	was := map[string]string{}
	for _, f := range files {
		was[f] = string(mustRead(t, filepath.Join(dir, f)))
	}
	before := stats(t, dir, files...)
	done := make(chan error, 1)
	go func() {
		_, err := bash(t, env, `sha256sum(){ sleep 2; command sha256sum "$@"; }; ig_init --no-pq`)
		done <- err
	}()
	time.Sleep(time.Second)
	mid := map[string]string{}
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(dir, f)) //nolint:gosec // a file the test's box keeps
		mid[f] = string(b)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for n, fi := range stats(t, dir, files...) {
		if mid[n] != was[n] {
			t.Errorf("while a second init ran, %s read %q", n, mid[n])
		}
		if !os.SameFile(before[n], fi) || !before[n].ModTime().Equal(fi.ModTime()) {
			t.Errorf("a second init rewrote %s", n)
		}
	}
	if err := os.Remove(filepath.Join(dir, "address")); err != nil {
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil || string(mustRead(t, filepath.Join(dir, "address"))) != was["address"] {
		t.Errorf("init did not make the box's address again: %v", err)
	}
}

// init makes identity.doc and address under the box's lock, as every
// command that writes the box makes them, so that it never writes them
// beside a command that reads them: while another command holds the lock,
// init waits, and writes neither.
func TestInitMakesTheIdentityFilesUnderTheLock(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL, "IG_LOCK_WAIT=1"}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(dir, "identity.doc")
	was := string(mustRead(t, doc))
	if err := os.Remove(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "lock"), 0o700); err != nil { // another command of the box holds its lock
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_init --no-pq"); err == nil || !strings.Contains(err.Error(), "held its lock") {
		t.Errorf("init while another command held the lock: %v", err)
	}
	if _, err := os.Stat(doc); err == nil {
		t.Error("init wrote identity.doc while another command held the lock")
	}
	if err := os.Remove(filepath.Join(dir, "lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil || string(mustRead(t, doc)) != was {
		t.Errorf("init once the lock was free: %v", err)
	}
}

// The document the box's files are made from is checked before it is
// written: an identity.pub out of form, where identity.doc is to be made
// again, is refused, and the box keeps its address, where it would
// otherwise take the hash of what that file holds.
func TestAnIdentityPubOutOfFormIsRefused(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatal(err)
	}
	was := string(mustRead(t, filepath.Join(dir, "address")))
	if err := os.Remove(filepath.Join(dir, "identity.doc")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.pub"), []byte("ssh-ed25519 not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_rekey --no-pq"); err == nil || !strings.Contains(err.Error(), "identity.pub is not a key an identity document holds") {
		t.Errorf("a renewal with identity.pub out of form: %v", err)
	}
	if got := string(mustRead(t, filepath.Join(dir, "address"))); got != was {
		t.Errorf("the box's address became %q", got)
	}
}

// A prekey's key file that a crash left empty, before the sync after
// age-keygen, is no key: init and a renewal make it again, as the Go client
// does, where the script once signed a statement with no key in it, which
// the server refused at every try (#238). A key file age cannot read and
// that is not empty is refused, and nothing is signed with it.
func TestAPrekeyKeyACrashLeftEmptyIsMadeAgain(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if _, err := bash(t, env, "ig_work(){ return 1; }; ig_init --no-pq"); err == nil { // cut short once the key is made
		t.Fatal("init went through")
	}
	if err := os.Truncate(newestKey(t, dir), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatalf("init after a crash that emptied the first prekey's key: %v", err)
	}
	if _, err := bash(t, env, "sleep 1; ig_work(){ return 1; }; ig_rekey --no-pq"); err == nil {
		t.Fatal("the renewal went through")
	}
	if err := os.Truncate(newestKey(t, dir), 0); err != nil {
		t.Fatal(err)
	}
	for _, try := range []string{"first", "second"} {
		if _, err := bash(t, env, "ig_rekey --no-pq"); err != nil {
			t.Errorf("a renewal after a crash that emptied the new prekey's key, %s try: %v", try, err)
		}
	}
	if _, err := bash(t, env, "sleep 1; ig_work(){ return 1; }; ig_rekey --no-pq"); err == nil {
		t.Fatal("the renewal went through")
	}
	key := newestKey(t, dir)
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bash(t, env, "ig_rekey --no-pq"); err == nil || !strings.Contains(err.Error(), "age-keygen cannot read") {
		t.Errorf("a renewal with a key file age cannot read: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(key, ".agekey") + ".txt.sig"); err == nil {
		t.Error("a statement was signed for a key file age cannot read")
	}
}

// An identity a crash left empty, with its identity.pub, before init's sync
// is no key: nothing was registered with it, and init makes it again, as the
// Go client does (#238).
func TestAnInitCrashedBeforeItsIdentityIsSyncedRegisters(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", filepath.Join(dir, "identity")).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	for _, f := range []string{"identity", "identity.pub"} {
		if err := os.Truncate(filepath.Join(dir, f), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Errorf("init after a crash that emptied the identity: %v", err)
	}
}

// .gitignore and aliases are written beside and moved into place, as every
// file a box keeps is, so a crash leaves the old file or the new one (#239):
// each write is a new file, never one written in place, and aliases keeps
// every line it had, each ending in a line feed, as the Go client writes it.
func TestGitignoreAndAliasesAreMovedIntoPlace(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	dir := t.TempDir()
	env := []string{"IRONGALL_HOME=" + dir, "IG_BASE=" + srv.URL}
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatal(err)
	}
	gi := stats(t, dir, ".gitignore")[".gitignore"]
	if _, err := bash(t, env, "ig_init --no-pq"); err != nil {
		t.Fatal(err)
	}
	if os.SameFile(gi, stats(t, dir, ".gitignore")[".gitignore"]) || string(mustRead(t, filepath.Join(dir, ".gitignore"))) != "*\n" {
		t.Errorf("init wrote .gitignore in place, or not as *: %q", mustRead(t, filepath.Join(dir, ".gitignore")))
	}
	first := "first " + strings.Repeat("1", 64)
	if err := os.WriteFile(filepath.Join(dir, "aliases"), []byte(first), 0o600); err != nil { // as a person writes it, with no line feed after the last line
		t.Fatal(err)
	}
	al := stats(t, dir, "aliases")["aliases"]
	if _, err := bash(t, env, "ig_alias second "+strings.Repeat("2", 64)); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, filepath.Join(dir, "aliases"))); os.SameFile(al, stats(t, dir, "aliases")["aliases"]) || got != first+"\nsecond "+strings.Repeat("2", 64)+"\n" {
		t.Errorf("alias add wrote aliases in place, or as %q", got)
	}
}

// A box its server has forgotten renews as a registration, once it has read
// what the server holds of its revocations (PROTOCOL.md §6.4, §7). A 2xx
// there that is no record stops the renewal with a refusal that says so, as
// an answer for the box's own read does (#230): the script once exited 1
// with no line. A record that holds nothing lets the renewal go on.
func TestAForgottenBoxsRenewalRefusesARevocationsAnswerThatIsNoRecord(t *testing.T) {
	need(t, append(scriptTools, "curl")...)
	srv := fakeserver.New(t, time.Now)
	env := []string{"IRONGALL_HOME=" + t.TempDir(), "IG_BASE=" + srv.URL}
	out, err := bash(t, env, "ig_init --no-pq")
	if err != nil {
		t.Fatal(err)
	}
	a := addressIn(t, srv, out)
	srv.Forget(a)
	var mu sync.Mutex
	answer := ""
	srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/"+a.String()+"/revocations" {
			mu.Lock()
			body := answer
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return
		}
		next.ServeHTTP(w, r)
	})
	set := func(body string) {
		mu.Lock()
		answer = body
		mu.Unlock()
	}
	for _, body := range []string{`{"type":"other"}`, "not json"} {
		set(body)
		if _, err := bash(t, env, "ig_rekey --no-pq"); err == nil || !strings.Contains(err.Error(), `"REFUSED: the server's answer for this box's revocations is not one this client reads`) {
			t.Errorf("%s: %v", body, err)
		}
	}
	set("{}") // control: a record that holds nothing
	if out, err := bash(t, env, "ig_rekey --no-pq"); err != nil || !strings.HasPrefix(out, `{"type":"prekey",`) {
		t.Errorf("a record that holds nothing: %v %q", err, out)
	}
}
