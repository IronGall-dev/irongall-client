//go:build unix

package client

import (
	"errors"
	"os"
	"syscall"
)

// tryGate takes the box's gate, an exclusive flock on its directory, if no
// one holds it: it reports false, with no error, when another does
// ([Box.openState]).
func tryGate(dir string) (*os.File, bool, error) {
	f, err := os.Open(dir) //nolint:gosec // the box's own directory
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
