//go:build unix

package revocationserver

import (
	"os"
	"syscall"
)

// flock takes f for this process alone, or fails at once if another holds
// it. The lock goes when the process does.
func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits an int
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // a directory inside the server's own
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close() //nolint:errcheck,gosec // the sync error wins
		return err
	}
	return d.Close()
}
