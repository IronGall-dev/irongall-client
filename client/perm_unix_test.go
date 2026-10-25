//go:build unix

package client_test

import (
	"fmt"
	"os"
)

// ownerOnly is whether the file at path is its owner's alone: mode 0600.
func ownerOnly(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if m := fi.Mode().Perm(); m != 0o600 {
		return fmt.Errorf("mode %v, want 0600", m)
	}
	return nil
}
