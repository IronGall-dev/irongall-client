//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

// The systems with flock, as cmd/go's own file lock lists them
// (cmd/go/internal/lockedfile/internal/filelock, filelock_unix.go): solaris
// and aix have none, and get no gate (gate_other.go).

package client

import (
	"errors"
	"os"
	"syscall"
)

// tryGate takes the mailbox's gate, an exclusive flock on its directory, if no
// one holds it: it reports false, with no error, when another does
// ([Mailbox.openState]).
func tryGate(dir string) (*os.File, bool, error) {
	f, err := os.Open(dir) //nolint:gosec // the mailbox's own directory
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // a descriptor fits an int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}
