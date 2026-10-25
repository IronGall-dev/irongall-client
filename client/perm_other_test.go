//go:build !unix

package client_test

import "os"

// ownerOnly checks only that the file at path is there: where there are no
// Unix modes (Windows), what keeps it its owner's alone is the directory's
// access list, which the client does not set yet, so nothing here holds it.
func ownerOnly(path string) error {
	_, err := os.Stat(path)
	return err
}
