package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// The box's lock is its state file, the bbolt database "state", held open by
// a command from its start to its end ([Box.hold]). bbolt takes an exclusive
// flock on it, so one command of a box runs at a time and none reads what
// another is half way through writing, and the kernel lets go of it however
// the process that held it ended (#235). signal-cli does the same with one
// lock on an account's file, held for a whole command and waited for by the
// next. A lock-free layout, Maildir's name per message renamed into place,
// fits a file written once, and not what a box reads, compares and writes
// again, such as its revocations and a peer's serials (decided on #62, #83 and
// #96). A box directory on NFS, where a flock is not one to rely on, is not
// supported (#188).

// errLocked is returned when another command still holds the box's lock once
// a command has waited for it as long as it waits.
var errLocked = refuse("another command of this box held its lock, its state file, for as long as a command waits for it: a box's commands write its files one at a time")

// lockPatience is how long a command waits for the box's lock while another
// command holds it: what apt waits for its own lock when no one is at a
// terminal.
var lockPatience = 2 * time.Minute

// lockTry is how long one attempt to take the lock waits for it: between
// attempts, a command that waits checks its context and its patience.
const lockTry = 100 * time.Millisecond

// lock is the box's state file, open: the lock, until it is closed.
type lock struct{ db *bolt.DB }

// hold takes the box's lock for a command, waiting up to lockPatience while
// another command holds it. The first time it finds the lock held it tells
// Options.Waiting, if set, so that a wait is not read as a hang.
func (b *Box) hold(ctx context.Context) (*lock, error) {
	if err := b.makeState(); err != nil {
		return nil, fmt.Errorf("the box's state file: %w", err)
	}
	deadline := time.Now().Add(lockPatience)
	told := false
	for {
		db, err := bolt.Open(b.path("state"), 0o600, &bolt.Options{Timeout: lockTry})
		if err == nil {
			return &lock{db: db}, nil
		}
		if !errors.Is(err, berrors.ErrTimeout) {
			return nil, fmt.Errorf("the box's state file: %w", err)
		}
		if !time.Now().Before(deadline) {
			return nil, errLocked
		}
		if !told && b.waiting != nil {
			b.waiting()
			told = true
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

// makeState makes the box's state file where it has none, as writeFile makes
// every file a box keeps: bbolt makes the database beside it and syncs it,
// and only then is it linked into place, where a link replaces nothing
// another command made first. bbolt writes a new database where it is
// opened, and one that a crash or a full disk cut off there can fault every
// process that opens it after (bbolt's README, of a database's first
// initialization; etcd-io/etcd#16596).
func (b *Box) makeState() error {
	if _, err := os.Lstat(b.path("state")); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(b.dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone once linked
	if err := tmp.Close(); err != nil {
		return err
	}
	db, err := bolt.Open(tmp.Name(), 0o600, nil)
	if err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), b.path("state")); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return syncDir(b.dir)
}

func (l *lock) release() error { return l.db.Close() }

// locked runs f with the box's lock held ([Box.hold]), and lets go of it
// after, on every way out of f, a panic among them. It is the one entry of
// every command that writes the box, so a box that holds its own revocation
// is refused here, before anything is asked or written (PROTOCOL.md §6.3):
// only what §6.3 lets it still do runs on one, through lockedFinished.
func locked[T any](ctx context.Context, b *Box, f func() (T, error)) (v T, err error) {
	return lockedFinished(ctx, b, func() (T, error) {
		if err := b.finished(); err != nil {
			return v, err
		}
		return f()
	})
}

// lockedFinished is locked for a command a box that holds its own
// revocation still runs, since it neither carries a pass nor asks for
// anything §6.3 refuses: asking about a revocation and keeping one, a flush,
// which moves what waits to outbox/failed/, and a change to the box's own
// files alone. Each signs nothing (sign).
func lockedFinished[T any](ctx context.Context, b *Box, f func() (T, error)) (v T, err error) {
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

// lockedFinishedDo is lockedFinished, for an f that returns only an error.
func (b *Box) lockedFinishedDo(ctx context.Context, f func() error) error {
	_, err := lockedFinished(ctx, b, func() (struct{}, error) { return struct{}{}, f() })
	return err
}
