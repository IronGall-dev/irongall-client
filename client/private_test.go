package client_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Every file and directory a box holds is its owner's alone: its directory by
// private, mode 0700 on Unix and an access list on Windows, which what is made
// in it inherits, and each file written 0600. The set is read from the boxes'
// own directories, once one has sent and the other received, so a file added
// later is held to it too.
func TestEveryFileOfABoxIsItsOwnersAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	if _, err := a.Send(t.Context(), b.Address(), "kept where only its owner reads it"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Receive(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, box := range []*client.Box{a, b} {
		err := filepath.WalkDir(box.Dir(), func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			n++
			if err := ownerOnly(p); err != nil {
				rel, _ := filepath.Rel(box.Dir(), p)
				t.Errorf("%s: %v", filepath.ToSlash(rel), err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 20 {
		t.Errorf("the boxes held %d files and directories: too few for a box that sent and received", n)
	}
}
