//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// tryGate takes the box's gate if no one holds it, as gate_unix.go's flock on
// the directory does, which Windows cannot lock: an exclusive lock on the
// box's file gate, made empty where there is none, taken as bbolt takes its
// own on the state file (LockFileEx on the last byte a file can have, failing
// at once). It reports false, with no error, when another holds it
// ([Box.openState]); closing the file lets go of it.
func tryGate(dir string) (*os.File, bool, error) {
	f, err := os.OpenFile(filepath.Join(dir, "gate"), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the box's own gate
	if err != nil {
		return nil, false, err
	}
	const last = ^uint32(0)
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{Offset: last, OffsetHigh: last})
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}
