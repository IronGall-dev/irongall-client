package client

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"time"
)

// The box's lock is the directory "lock", as the stock recipe takes it with
// mkdir, so the two clients exclude each other on a shared box. Every command
// that writes the box's files holds it from its start to its end ([Box.hold]),
// so one runs at a time and none reads what another is half way through
// writing. This client also holds a flock on lock/pid while it runs, so a
// lock left by a crashed Go client is recognised and taken over. A lock
// directory without a pid file belongs to the recipe; it is never taken over.

// errLocked is returned when another command still holds the box's lock once
// a command has waited for it as long as it waits.
var errLocked = refuse("another command of this box held its lock, lock/, for as long as a command waits for it: a box's commands write its files one at a time. If none is running, one that crashed left lock/ behind: remove it")

// lockPatience is how long a command waits for the box's lock while another
// command holds it: what apt waits for its own lock when no one is at a
// terminal.
var lockPatience = 2 * time.Minute

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

// hold takes the box's lock for a command, waiting up to lockPatience while
// another command holds it. The first time it finds the lock held it tells
// Options.Waiting, if set, so that a wait is not read as a hang.
func (b *Box) hold(ctx context.Context) (*lock, error) {
	deadline := time.Now().Add(lockPatience)
	told := false
	for {
		l, err := b.lock()
		if !errors.Is(err, errLocked) || !time.Now().Before(deadline) {
			return l, err
		}
		if !told && b.waiting != nil {
			b.waiting()
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// locked runs f with the box's lock held ([Box.hold]), and lets go of it
// after, on every way out of f, a panic among them.
func locked[T any](ctx context.Context, b *Box, f func() (T, error)) (v T, err error) {
	l, err := b.hold(ctx)
	if err != nil {
		return v, err
	}
	defer func() {
		if e := l.release(); err == nil {
			err = e
		}
	}()
	return f()
}

// lockedDo is locked, for an f that returns only an error.
func (b *Box) lockedDo(ctx context.Context, f func() error) error {
	_, err := locked(ctx, b, func() (struct{}, error) { return struct{}{}, f() })
	return err
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
	// command can make a new one. Only the file lock/pid still names counts.
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
