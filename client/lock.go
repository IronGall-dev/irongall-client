package client

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
)

// The consumer lock is the directory "lock", as the stock recipe takes it with
// mkdir, so the two clients exclude each other on a shared box. This client
// also holds a flock on lock/pid while it runs, so a lock left by a crashed Go
// client is recognised and taken over. A lock directory without a pid file
// belongs to the recipe; it is never taken over.

// errLocked is returned when another consumer holds the box.
var errLocked = refuse("another consumer holds the lock: one consumer per box (remove lock/ if it is stale)")

// errLockGone is a lock/pid deleted between this client's open and its flock.
var errLockGone = errors.New("the lock file was deleted under us")

// lockOpened, in tests, runs between opening lock/pid and taking its flock:
// the window in which a releasing holder can delete it.
var lockOpened = func() {}

type lock struct {
	dir string
	pid *os.File
}

func (b *Box) lock() (*lock, error) {
	for range 3 {
		l, err := b.lockOnce()
		if !errors.Is(err, errLockGone) {
			return l, err
		}
	}
	return nil, errLocked
}

func (b *Box) lockOnce() (*lock, error) {
	l := &lock{dir: b.path("lock")}
	err := os.Mkdir(l.dir, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	created := err == nil
	if !created && !staleDetect {
		return nil, errLocked
	}
	// Into an existing lock, open the pid file only if it is there: a lock
	// without one is the recipe's, and gets no file of ours.
	flags := os.O_RDWR
	if created {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(l.dir+"/pid", flags, 0o600) //nolint:gosec // a path inside the box's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errLocked
	}
	if err != nil {
		return nil, err
	}
	lockOpened()
	if err := flock(f); err != nil {
		f.Close() //nolint:errcheck,gosec // held by another process
		return nil, errLocked
	}
	// A holder releasing deletes lock/pid and lock/, then closes the file,
	// which drops its flock. A file opened before that delete and flocked
	// after that close is locked, but it is no longer the lock: a third
	// consumer can make a new one. Only the file lock/pid still names counts.
	if !stillNamed(f, l.dir+"/pid") {
		f.Close() //nolint:errcheck,gosec // not the lock any more
		return nil, errLockGone
	}
	if err := f.Truncate(0); err != nil {
		f.Close() //nolint:errcheck,gosec
		return nil, err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		f.Close() //nolint:errcheck,gosec
		return nil, err
	}
	l.pid = f
	return l, nil
}

// stillNamed reports whether name is the file f has open.
func stillNamed(f *os.File, name string) bool {
	held, err := f.Stat()
	if err != nil {
		return false
	}
	named, err := os.Stat(name)
	return err == nil && os.SameFile(held, named)
}

func (l *lock) release() error {
	err := os.Remove(l.dir + "/pid")
	if e := os.Remove(l.dir); err == nil {
		err = e
	}
	if e := l.pid.Close(); err == nil {
		err = e
	}
	return err
}
