package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

var update = flag.Bool("update", false, "write testdata/statetable.golden from this run")

// TestStateTable runs each command of a box in each state its server and its
// directory can be in, with the server answering or refusing, and holds what each cell did to testdata/statetable.golden: what the command
// returned, every call it made, and what changed in the box's directory. The
// file is the behaviour's spec (the redesign's (4)): a change to what a
// command does in some state is a change to it, read line by line before it
// is committed. go test ./client -run TestStateTable -update writes it anew.
//
// A row is the box's directory (all of it, or the identity alone, as a
// restore from its backup), what its server holds (never registered, an
// active box, one the server forgot), and what the
// server holds of a revocation of its certificates (none, through the one
// in use, or through a serial a day ahead of the clock), each revocation
// published by another holder of the identity and not kept by the box; then
// three rows more: the address revoked at the server, the box finished (it
// holds its own revocation), and no box at all.
//
// Two kinds of cell are not run, since each is the same as another (#426
// item 3): a server that is silent leaves the box as one that refuses does
// in all 220 pairs of row and command, and only its words differ, which
// TestACallWithNoAnswerSaysWhatKind holds; and the identity alone at a
// server that forgot the box does in all 90 cells what it does at one that
// never registered it, which holds nothing of it either.
func TestStateTable(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	type cell struct{ key, line string }
	var (
		mu    sync.Mutex
		cells []cell
	)
	t.Run("cells", func(t *testing.T) {
		for _, r := range stateRows() {
			for _, c := range stateCommands() {
				for _, m := range []string{"answers", "refuses"} {
					key := r.name + " | " + c.name + " | " + m
					t.Run(strings.NewReplacer(" ", "_", "|", "").Replace(key), func(t *testing.T) {
						t.Parallel()
						line := runCell(t, r, c, m)
						mu.Lock()
						cells = append(cells, cell{key, key + " | " + line})
						mu.Unlock()
					})
				}
			}
		}
	})
	if t.Failed() {
		return
	}
	slices.SortFunc(cells, func(a, b cell) int { return strings.Compare(a.key, b.key) })
	var out strings.Builder
	out.WriteString("# row | command | server | result | calls | box: +added ~changed -removed\n")
	out.WriteString("# Written by go test ./client -run TestStateTable -update (statetable_test.go); read each changed line before committing it.\n")
	for _, c := range cells {
		out.WriteString(c.line + "\n")
	}
	golden := filepath.Join("testdata", "statetable.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(out.String()), 0o644); err != nil { //nolint:gosec // a test's golden file
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden) //nolint:gosec // the test's own golden file
	if err != nil {
		t.Fatalf("%v: run go test ./client -run TestStateTable -update", err)
	}
	if got := out.String(); got != string(want) {
		wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
		for _, l := range gl {
			if !slices.Contains(wl, l) {
				t.Errorf("now:  %s", l)
			}
		}
		for _, l := range wl {
			if !slices.Contains(gl, l) {
				t.Errorf("was:  %s", l)
			}
		}
		t.Error("the state table changed: read each line above, then go test ./client -run TestStateTable -update")
	}
}

// A stateRow puts a box in its state: in dir, against e, with peer an active
// box of the same server.
type stateRow struct {
	name string
	make func(t *testing.T, e *env, dir string, peer *client.Box)
}

func stateRows() []stateRow {
	var rows []stateRow
	for _, view := range []string{"full", "identity alone"} {
		for _, server := range []string{"never registered", "active", "forgotten"} {
			for _, rev := range []string{"no revocation", "revoked through the one in use", "revoked a day ahead"} {
				if view == "identity alone" && server == "forgotten" {
					continue // the same in every cell as never registered (TestStateTable)
				}
				rows = append(rows, stateRow{view + ", " + server + ", " + rev, func(t *testing.T, e *env, dir string, peer *client.Box) {
					makeBox(t, e, dir, peer, server == "never registered")
					a := openBox(t, e, dir)
					if server == "forgotten" {
						e.srv.Forget(a.Address())
					}
					switch rev {
					case "revoked through the one in use":
						publish(t, e, certsRecord(t, dir, begunAt(t, a)))
					case "revoked a day ahead":
						publish(t, e, certsRecord(t, dir, protocol.SerialAt(e.clock.Now(), 0)+86400))
					}
					if view == "identity alone" {
						identityAlone(t, dir)
					}
				}})
			}
		}
	}
	return append(rows,
		stateRow{"full, address revoked at the server", func(t *testing.T, e *env, dir string, peer *client.Box) {
			makeBox(t, e, dir, peer, false)
			rec, err := openBox(t, e, dir).Revocation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			publish(t, e, rec)
		}},
		stateRow{"identity alone, address revoked at the server", func(t *testing.T, e *env, dir string, peer *client.Box) {
			makeBox(t, e, dir, peer, false)
			rec, err := openBox(t, e, dir).Revocation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			publish(t, e, rec)
			identityAlone(t, dir)
		}},
		stateRow{"full, finished: it holds its own revocation", func(t *testing.T, e *env, dir string, peer *client.Box) {
			makeBox(t, e, dir, peer, false)
			a := openBox(t, e, dir)
			rec, err := a.Revocation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			publish(t, e, rec)
			if _, _, err := a.KeepRevocation(t.Context(), rec); err != nil {
				t.Fatal(err)
			}
		}},
		stateRow{"no box", func(*testing.T, *env, string, *client.Box) {}},
	)
}

// makeBox makes a box in dir, registered, with a message from peer waiting
// for it; or, unregistered, one whose registration its server refused. Beside
// the box it leaves the record its owner hands over (handedOver).
func makeBox(t *testing.T, e *env, dir string, peer *client.Box, unregistered bool) {
	t.Helper()
	defer func() {
		raw, err := json.Marshal(certsRecord(t, dir, begunAt(t, openBox(t, e, dir))))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(handedOverFile(dir), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}()
	if unregistered {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPut && strings.Count(r.URL.Path, "/") == 2 {
				forge.Refuse(w, protocol.CodeUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := client.Init(context.Background(), dir, e.opts(), protocol.Classic); err == nil {
			t.Fatal("the registration was taken")
		}
		e.srv.SetMiddle(nil)
		return
	}
	a, err := client.Init(context.Background(), dir, e.opts(), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, a)
	send(t, peer, a, "waiting")
}

func openBox(t *testing.T, e *env, dir string) *client.Box {
	t.Helper()
	b, err := client.Open(dir, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// certsRecord is a record of the revocation of the certificates of the box
// in dir through serial, signed by its identity: what another holder of it
// publishes, or hands over.
func certsRecord(t *testing.T, dir string, through uint64) *protocol.Revocations {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(dir, "identity")) //nolint:gosec // a test box's own file
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.IdentityOf(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	certs, err := protocol.NewRevokedCertificates(id.Address(), through)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(signer, certs)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: id.Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
}

// publish puts rec to e's server as anyone may, with no box.
func publish(t *testing.T, e *env, rec *protocol.Revocations) {
	t.Helper()
	if _, err := client.Publish(context.Background(), e.opts(), rec); err != nil {
		t.Fatal(err)
	}
}

// identityAlone leaves the box in dir as a restore from its backup does: its
// identity alone.
func identityAlone(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		if f.Name() != "identity" {
			if err := os.RemoveAll(filepath.Join(dir, f.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A stateCommand is a command as the CLI runs it, on the box in dir, as a
// process of its own: it returns what to write for it.
type stateCommand struct {
	name string
	run  func(ctx context.Context, e *env, dir string, peer *client.Box) (string, error)
}

func stateCommands() []stateCommand {
	open := func(e *env, dir string) (*client.Box, error) { return client.Open(dir, e.opts()) }
	return []stateCommand{
		{"init", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			_, err := client.Init(ctx, dir, e.opts(), protocol.PostQuantum) // the command's default
			return "", err
		}},
		{"recv", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			res, err := b.Receive(ctx)
			if res == nil {
				return "", err
			}
			s := fmt.Sprintf("delivered %d, held %d, refused %d", len(res.Delivered), len(res.Held), len(res.Refused))
			if res.Renewed != nil {
				s += fmt.Sprintf(", renewed to %d", res.Renewed.Serial)
			}
			if res.RenewErr != nil {
				s += ", not renewed: " + res.RenewErr.Error()
			}
			return s, err
		}},
		{"send", func(ctx context.Context, e *env, dir string, peer *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			_, err = b.Send(ctx, peer.Address(), "a reply")
			return "", err
		}},
		{"prekey renew", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			p, err := b.Rekey(ctx, "")
			if p == nil {
				return "", err
			}
			return fmt.Sprintf("prekey %d", p.Serial), err
		}},
		{"cert revoke-earlier", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			r, err := b.RenewAndRevoke(ctx, "")
			if r == nil {
				return "", err
			}
			s := fmt.Sprintf("below %d", r.Below)
			if r.Revoked != nil {
				s += fmt.Sprintf(", revoked through %d", r.Revoked.Through)
			}
			if r.NotRevoked != nil {
				s += ", not revoked: " + r.NotRevoked.Error()
			}
			if r.Prekey != nil {
				s += fmt.Sprintf(", prekey %d", r.Prekey.Serial)
			}
			if r.NotRenewed != nil {
				s += ", not renewed: " + r.NotRenewed.Error()
			}
			if r.Unread != nil {
				s += ", unread: " + r.Unread.Error()
			}
			return s, err
		}},
		{"cert publish-revoked", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			// The record of its certificates through the one in use, handed
			// over: kept, then published, as the command does with a file.
			rec := handedOver(dir)
			if rec == nil {
				return "", fmt.Errorf("no record to hand over")
			}
			if _, _, err := b.KeepRevocation(ctx, rec); err != nil {
				return "", err
			}
			_, err = b.Publish(ctx, rec)
			return "", err
		}},
		{"revocation make", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			_, err = b.Revocation(ctx)
			return "", err
		}},
		{"revocation keep", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			rec := handedOver(dir)
			if rec == nil {
				return "", fmt.Errorf("no record to hand over")
			}
			_, h, err := b.KeepRevocation(ctx, rec)
			return heldWords(h), err
		}},
		{"revocation publish", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			rec, err := b.Revocation(ctx)
			if err != nil {
				return "", err
			}
			if _, err := b.Revoke(ctx, rec); err != nil {
				return "", err
			}
			_, h, err := b.KeepRevocation(ctx, rec)
			return heldWords(h), err
		}},
		{"revocation ask", func(ctx context.Context, e *env, dir string, _ *client.Box) (string, error) {
			b, err := open(e, dir)
			if err != nil {
				return "", err
			}
			h, err := b.Ask(ctx, b.Address())
			return heldWords(h), err
		}},
	}
}

// handedOver is the record cert publish-revoked and revocation keep are
// given: the identity's revocation of the box's certificates through the one
// in use when its row was made, as its owner signs one on another machine.
// It is nil where no box was made.
func handedOver(dir string) *protocol.Revocations {
	raw, err := os.ReadFile(handedOverFile(dir))
	if err != nil {
		return nil
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil {
		return nil
	}
	return &rec
}

// handedOverFile is where the record handed over is kept, beside the box and
// not in it.
func handedOverFile(dir string) string { return filepath.Join(filepath.Dir(dir), "handed-over.json") }

func heldWords(h *client.Held) string {
	if h == nil {
		return ""
	}
	s := "holds"
	if h.Revoked {
		s += " the address revoked"
	}
	if h.Certificates != nil {
		s += fmt.Sprintf(" certificates through %d", h.Certificates.Through)
	}
	if s == "holds" {
		s = "holds nothing"
	}
	return s
}

// runCell runs command c on a box put in row r's state, against a server in
// mode m, and returns what the cell writes, every address and serial in it
// written as a role and an offset from the clock.
func runCell(t *testing.T, r stateRow, c stateCommand, m string) string {
	e := newEnv(t)
	peer := e.box(protocol.Classic)
	dir := filepath.Join(t.TempDir(), "box")
	r.make(t, e, dir, peer)
	// Two hours on: the box's certificate began well before the command, and
	// a revocation through it is below the clock.
	e.clock.Add(2 * time.Hour)
	before := snapshot(dir)
	calls := len(e.srv.Requests())
	switch m {
	case "refuses":
		e.srv.SetMiddle(func(w http.ResponseWriter, _ *http.Request, _ http.Handler) {
			w.Header().Set("Retry-After", "3600")
			forge.Refuse(w, protocol.CodeRateLimited)
		})
	}
	words, err := c.run(context.Background(), e, dir, peer)
	result := "ok"
	if words != "" {
		result += ": " + words
	}
	if err != nil {
		result = "error: " + err.Error()
		if words != "" {
			result += " (" + words + ")"
		}
	}
	var made []string
	for _, q := range e.srv.Requests()[calls:] {
		s := q.Method + " " + q.Path
		if q.Pass {
			s += " +pass"
		}
		made = append(made, s)
	}
	line := result + " | " + strings.Join(made, ", ") + " | " + changes(before, snapshot(dir))
	return normalize(line, e, dir, peer)
}

// snapshot is every file under dir but the state file, and every record the
// state file keeps, by its path or a record's name (client.RecordsAt), with a
// hash of what it holds.
func snapshot(dir string) map[string][32]byte {
	files := map[string][32]byte{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a box with no directory has no files
		}
		raw, err := os.ReadFile(p) //nolint:gosec // a test box's own file
		if err != nil {
			return nil //nolint:nilerr // a file gone as it was read is not one
		}
		rel, _ := filepath.Rel(dir, p)
		// The state file is read as its records, and the gate holds
		// nothing: it is Windows' lock (gate_windows.go).
		if rel = filepath.ToSlash(rel); rel != "state" && rel != "gate" {
			files[rel] = sha256.Sum256(raw)
		}
		return nil
	})
	records, _ := client.RecordsAt(dir)
	for name, v := range records {
		files[name] = sha256.Sum256(v)
	}
	return files
}

// changes says which files were added, changed and removed.
func changes(before, after map[string][32]byte) string {
	var add, chg, rm []string
	for p, h := range after {
		switch g, ok := before[p]; {
		case !ok:
			add = append(add, "+"+p)
		case g != h:
			chg = append(chg, "~"+p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			rm = append(rm, "-"+p)
		}
	}
	slices.Sort(add)
	slices.Sort(chg)
	slices.Sort(rm)
	all := slices.Concat(add, chg, rm)
	if len(all) == 0 {
		return "nothing"
	}
	return strings.Join(all, " ")
}

var (
	hex64  = regexp.MustCompile(`[0-9a-f]{64}`)
	uuid   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	serial = regexp.MustCompile(`\b1[0-9]{9}\b`)
	temp   = regexp.MustCompile(`\.tmp-[0-9]+`)
	inBox  = regexp.MustCompile(`<box>[^ :,]*`)
)

// notFound is the system's words for a file, and for a directory, that is
// not there, each to be written as Unix writes them, so that the table reads
// the same on every system.
var notFound = func() []string {
	missing := filepath.Join(os.TempDir(), "statetable-missing-"+strconv.Itoa(os.Getpid()))
	var words []string
	for _, p := range []string{missing, filepath.Join(missing, "file")} {
		var pe *fs.PathError
		if _, err := os.Stat(p); errors.As(err, &pe) {
			words = append(words, pe.Err.Error())
		}
	}
	return words
}()

// normalize writes the box's address as own, the peer's as peer, any other
// hash as #, a message id as <msg_id>, the box's directory as <box>, and
// each serial, a time in seconds, as T+k, k from the clock at the cell's
// start.
func normalize(s string, e *env, dir string, peer *client.Box) string {
	s = strings.ReplaceAll(s, dir, "<box>")
	s = inBox.ReplaceAllStringFunc(s, filepath.ToSlash)
	for _, w := range notFound {
		s = strings.ReplaceAll(s, w, "no such file or directory")
	}
	s = strings.ReplaceAll(s, peer.Address().String(), "peer")
	if id, err := os.ReadFile(filepath.Join(dir, "identity")); err == nil { //nolint:gosec // a test box's own file
		if signer, err := ssh.ParsePrivateKey(id); err == nil {
			if pid, err := protocol.IdentityOf(signer.PublicKey()); err == nil {
				s = strings.ReplaceAll(s, pid.Address().String(), "own")
			}
		}
	}
	s = hex64.ReplaceAllString(s, "#")
	s = uuid.ReplaceAllString(s, "<msg_id>")
	s = temp.ReplaceAllString(s, ".tmp-*")
	start := e.clock.Now().Add(-2 * time.Hour).Unix()
	return serial.ReplaceAllStringFunc(s, func(v string) string {
		n, _ := strconv.ParseInt(v, 10, 64)
		if d := n - start; d < 0 {
			return fmt.Sprintf("T%d", d)
		}
		return fmt.Sprintf("T+%d", n-start)
	})
}
