//go:build !unix && !windows

package client_test

import "os"

// ownerOnly checks only that path is there, where the system has neither
// Unix modes nor Windows' access lists (private).
func ownerOnly(path string) error {
	_, err := os.Stat(path)
	return err
}
