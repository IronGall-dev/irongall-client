//go:build unix

package client_test

import (
	"fmt"
	"os"
)

// ownerOnly is whether the file or directory at path is its owner's alone:
// mode 0600 for a file, 0700 for a directory.
func ownerOnly(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	want := os.FileMode(0o600)
	if fi.IsDir() {
		want = 0o700
	}
	if m := fi.Mode().Perm(); m != want {
		return fmt.Errorf("mode %v, want %v", m, want)
	}
	return nil
}
