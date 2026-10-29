//go:build !unix && !windows

package client_test

import (
	"os"
	"testing"
)

// ownerOnly checks only that path is there, where the system has neither
// Unix modes nor Windows' access lists (private).
func ownerOnly(path string) error {
	_, err := os.Stat(path)
	return err
}

// widen skips the test, where ownerOnly cannot tell a directory open to
// others from one that is not.
func widen(t *testing.T, _ string) {
	t.Helper()
	t.Skip("this system has neither Unix modes nor Windows' access lists")
}
