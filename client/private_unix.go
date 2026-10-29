//go:build unix

package client

import "os"

// private makes a directory of the box its owner's alone: mode 0700, where
// MkdirAll leaves an existing directory's mode as it was. Every file in it is
// written 0600 (writeFile).
func private(dir string) error {
	return os.Chmod(dir, 0o700) //nolint:gosec // a directory: 0700 is owner-only
}
