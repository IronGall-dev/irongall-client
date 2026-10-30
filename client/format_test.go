package client_test

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
)

// A mailbox is stamped with this client's format at the first command that
// writes it, and status says it, with where the mailbox keeps each of its
// files. A mailbox with no state file, restored from its identity alone, reads
// as format 1, and is stamped at its first command.
func TestAMailboxRecordsItsFormatAtItsFirstWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox()
	if got, ok := b.Record(t, "format"); !ok || string(got) != "1" {
		t.Fatalf("a mailbox made here records format %q (%v), want 1", got, ok)
	}
	st, err := b.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs(b.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if st.Format != 1 || st.Paths["mailbox"] != dir || st.Paths["state"] != filepath.Join(dir, "state") || st.Paths["prekey_lifetime"] != filepath.Join(dir, "prekey-lifetime") {
		t.Fatalf("status: format %d, paths %v", st.Format, st.Paths)
	}

	restored := t.TempDir()
	for _, f := range []string{"identity", "identity.pub"} {
		raw, err := os.ReadFile(filepath.Join(b.Dir(), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(restored, f), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x, err := client.Open(restored, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if st, err := x.Status(t.Context()); err != nil || st.Format != 1 {
		t.Fatalf("status of a mailbox with no state file: %+v, %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(restored, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a reading made the state file: %v", err)
	}
	if err := x.SetPolicy(t.Context(), client.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if got, ok := x.Record(t, "format"); !ok || string(got) != "1" {
		t.Fatalf("a restored mailbox's first command records format %q (%v), want 1", got, ok)
	}
}

// A mailbox in a newer format than this client's is refused by every entry
// that reads or writes it, at the mailbox's state, with nothing written, its
// directories among it: waits is every such entry, built from the code
// (TestEveryEntryThatWaitsIsTriedWithItsContext).
func TestANewerFormatIsRefusedByEveryEntryWritingNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b, c := e.mailbox(), e.mailbox()
	rec, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	newer := client.ClientFormat() + 1
	client.SetFormat(t, b.Dir(), []byte(strconv.Itoa(newer)))
	if err := os.Remove(filepath.Join(b.Dir(), "sent")); err != nil {
		t.Fatal(err)
	}
	before := snapshot(b.Dir())
	for _, name := range slices.Sorted(maps.Keys(waits(nil, nil, nil, client.Options{}))) {
		err := waits(opened(t, e, b), c, rec, e.opts())[name](t.Context())
		var fe *client.FormatError
		if !errors.As(err, &fe) || fe.Format != newer || fe.Client != client.ClientFormat() || fe.Code() != "mailbox_format_newer" {
			t.Errorf("%s on a newer format: %v", name, err)
		}
		if got := changes(before, snapshot(b.Dir())); got != "nothing" {
			t.Fatalf("%s on a newer format changed %s", name, got)
		}
		if _, err := os.Stat(filepath.Join(b.Dir(), "sent")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s on a newer format made sent/: %v", name, err)
		}
	}
}

// A mailbox in an older format is refused by every reading, which writes
// nothing, and brought forward by every command that writes it, each step
// run once and the format recorded after; a step that fails leaves the format
// as it was, and the next command runs it again. The readings and the
// commands are waits', told apart by the code.
func TestAnOlderFormatIsBroughtForwardByACommandAndRefusedByAReading(t *testing.T) {
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	e := newEnv(t)
	b, c := e.mailbox(), e.mailbox()
	rec, err := c.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	var fail error
	client.SetFormatSteps(t, func(*client.Mailbox) error { ran++; return fail })
	readings := entriesCalling(t, "reading")
	for _, name := range slices.Sorted(maps.Keys(waits(nil, nil, nil, client.Options{}))) {
		client.SetFormat(t, b.Dir(), []byte("1"))
		ran = 0
		before := snapshot(b.Dir())
		f := waits(opened(t, e, b), c, rec, e.opts())[name]
		err := f(t.Context())
		if readings[name] {
			var fe *client.FormatError
			if !errors.As(err, &fe) || fe.Format != 1 || fe.Client != 2 || fe.Code() != "mailbox_format_older" {
				t.Errorf("%s, a reading, on an older format: %v", name, err)
			}
			if got := changes(before, snapshot(b.Dir())); got != "nothing" || ran != 0 {
				t.Errorf("%s, a reading, on an older format changed %s and ran %d steps", name, got, ran)
			}
			continue
		}
		if got, _ := b.Record(t, "format"); string(got) != "2" || ran != 1 {
			t.Errorf("%s, a command, on an older format: format %q, %d steps run (%v)", name, got, ran, err)
		}
		if _ = f(t.Context()); ran != 1 {
			t.Errorf("%s ran a step again on a mailbox brought forward", name)
		}
	}

	client.SetFormat(t, b.Dir(), []byte("1"))
	fail, ran = errors.New("a fault"), 0
	if err := b.SetPolicy(t.Context(), client.DefaultPolicy()); err == nil || !strings.Contains(err.Error(), "from format 1 to 2") {
		t.Fatalf("a step that fails: %v", err)
	}
	if got, _ := b.Record(t, "format"); string(got) != "1" {
		t.Fatalf("a step that failed left format %q", got)
	}
	fail = nil
	if err := b.SetPolicy(t.Context(), client.DefaultPolicy()); err != nil || ran != 2 {
		t.Fatalf("the command after a step failed: %v, %d steps run", err, ran)
	}
	if got, _ := b.Record(t, "format"); string(got) != "2" {
		t.Fatalf("after the step ran again, format %q", got)
	}
	if st, err := b.Status(t.Context()); err != nil || st.Format != 2 {
		t.Fatalf("status once brought forward: %+v, %v", st, err)
	}
}

// A mailbox with no state file is format 1, whatever its other files: so a
// client of a later format brings it forward from the oldest, never takes it
// as its own (client/format.go).
func TestAMailboxWithNoStateFileIsFormat1(t *testing.T) {
	e := newEnv(t)
	b := e.mailbox()
	ran := 0
	client.SetFormatSteps(t, func(*client.Mailbox) error { ran++; return nil })
	if err := os.Remove(filepath.Join(b.Dir(), "state")); err != nil {
		t.Fatal(err)
	}
	var fe *client.FormatError
	if _, err := b.Status(t.Context()); !errors.As(err, &fe) || fe.Format != 1 || fe.Client != 2 {
		t.Fatalf("status of a mailbox with no state file, at format 2: %v", err)
	}
	if err := b.SetPolicy(t.Context(), client.DefaultPolicy()); err != nil || ran != 1 {
		t.Fatalf("its first command: %v, %d steps run", err, ran)
	}
	if got, _ := b.Record(t, "format"); string(got) != "2" {
		t.Fatalf("its first command records format %q", got)
	}
}

// A format record no client writes is refused by a reading and a command
// alike, and left as it is.
func TestAFormatRecordNoClientWritesIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox()
	for _, raw := range []string{"", "0", "01", "-1", "+1", "1 ", " 1", "1.0", "x", "99999999999999999999"} {
		client.SetFormat(t, b.Dir(), []byte(raw))
		if _, err := b.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "no decimal number") {
			t.Errorf("status of format %q: %v", raw, err)
		}
		if err := b.SetPolicy(t.Context(), client.DefaultPolicy()); err == nil || !strings.Contains(err.Error(), "no decimal number") {
			t.Errorf("a command on format %q: %v", raw, err)
		}
		if got, _ := b.Record(t, "format"); string(got) != raw {
			t.Errorf("format %q left as %q", raw, got)
		}
	}
}

// client/doc.go names each format, 1 through this client's, in order.
func TestDocNamesEveryFormat(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	_, list, ok := strings.Cut(string(raw), "each format and what it changed:\n//\n")
	if !ok {
		t.Fatal("doc.go has no list of formats")
	}
	var named []int
	for l := range strings.Lines(list) {
		m := regexp.MustCompile(`^//\t(\d+) {2,}\S`).FindStringSubmatch(l)
		if m == nil {
			break
		}
		n, _ := strconv.Atoi(m[1])
		named = append(named, n)
	}
	want := make([]int, client.ClientFormat())
	for i := range want {
		want[i] = i + 1
	}
	if !slices.Equal(named, want) {
		t.Fatalf("doc.go names formats %v, want %v", named, want)
	}
}

// opened is b's mailbox opened again, a Mailbox of its own: each entry of waits
// then has its own turn to hold (Hold, Await).
func opened(t *testing.T, e *env, b *client.Mailbox) *client.Mailbox {
	t.Helper()
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	return x
}
