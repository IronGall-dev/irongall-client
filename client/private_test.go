package client_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Every file and directory a mailbox holds is its owner's alone: its directory
// and each of its own by private, mode 0700 on Unix and an access list on
// Windows, which what is made in them inherits, and each file written 0600.
// Each mailbox is made in a directory open to others, where nothing but private
// makes it its owner's: one by Init, with an inbox/ someone made before it,
// and one restored from its identity alone and opened. The set is read from
// the mailboxes' own directories once each has sent and received, so a file
// added later is held to it too.
func TestEveryFileOfABoxIsItsOwnersAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	made := filepath.Join(t.TempDir(), "made")
	openToOthers(t, made)
	openToOthers(t, filepath.Join(made, "inbox"))
	a, err := client.Init(t.Context(), made, e.opts(), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}

	id, err := os.ReadFile(filepath.Join(e.mailbox(protocol.Classic).Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	openToOthers(t, restored)
	if err := os.WriteFile(filepath.Join(restored, "identity"), id, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := client.Open(restored, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Rekey(t.Context(), protocol.Classic); err != nil {
		t.Fatal(err)
	}

	for _, x := range [][2]*client.Mailbox{{a, b}, {b, a}} {
		landAll(t, x[1])
		if _, err := x[0].Send(t.Context(), x[1].Address(), "kept where only its owner reads it"); err != nil {
			t.Fatal(err)
		}
		if _, err := x[1].Receive(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, mailbox := range []*client.Mailbox{a, b} {
		err := filepath.WalkDir(mailbox.Dir(), func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			n++
			if err := ownerOnly(p); err != nil {
				rel, _ := filepath.Rel(mailbox.Dir(), p)
				t.Errorf("%s: %v", filepath.ToSlash(rel), err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 20 {
		t.Errorf("the mailboxes held %d files and directories: too few for a mailbox that sent and received", n)
	}
}

// openToOthers makes dir as someone else might before a mailbox is made in it,
// open to others (widen), and fails the test where ownerOnly still passes
// it: a mailbox made there would then pass whatever private did.
func openToOthers(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	widen(t, dir)
	if ownerOnly(dir) == nil {
		t.Fatalf("%s is its owner's alone, opened to others: no mailbox made in it could fail this test", dir)
	}
}
