//go:build unix

package client

import (
	"os"
	"syscall"
)

// staleDetect reports whether a lock left by a crashed client can be told
// from a live one.
const staleDetect = true

func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits an int
}
