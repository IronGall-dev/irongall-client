package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The mailbox's lock is its state file, the bbolt database "state", held open by
// a command from its start to its end ([Mailbox.hold]). bbolt takes an exclusive
// flock on it, so one command of a mailbox runs at a time and none reads what
// another is half way through writing, and the kernel lets go of it however
// the process that held it ended (#235). signal-cli does the same with one
// lock on an account's file, held for a whole command and waited for by the
// next. A lock-free layout, Maildir's name per message renamed into place,
// fits a file written once, and not what a mailbox reads, compares and writes
// again, such as its revocations and a peer's serials (decided on #62, #83 and
// #96). A mailbox directory on NFS, where a flock is not one to rely on, is not
// supported (#188).
//
// In one process, goroutines that share a Mailbox take turns in its slot first
// (claim), at each exported entry that reads or writes the state file, so a
// command of one waits for another's as a command of another process does
// (#329).

// errLocked is returned when another command still holds the mailbox's lock once
// a command has waited for it as long as it waits.
var errLocked = refuse("another command of this mailbox held its lock, its state file, for as long as a command waits for it: a mailbox's commands write its files one at a time")

// lockPatience is how long a command waits for the mailbox's lock while another
// command holds it: what apt waits for its own lock when no one is at a
// terminal.
var lockPatience = 2 * time.Minute

// lockTry is how long one attempt to take the lock waits for it: between
// attempts, a command that waits checks its context and its patience.
const lockTry = 100 * time.Millisecond

// hold takes the mailbox's lock for a command, waiting up to lockPatience while
// another command holds it (openState), and keeps the state file it opened on
// the mailbox for the command's transactions until release.
func (b *Mailbox) hold(ctx context.Context) (func() error, error) {
	if err := b.makeState(); err != nil {
		return nil, fmt.Errorf("the mailbox's state file: %w", err)
	}
	db, err := b.openState(ctx, false)
	// Removed between makeState and the open: made again beside its place,
	// never in place (openWhole).
	if errors.Is(err, fs.ErrNotExist) {
		if err = b.makeState(); err == nil {
			db, err = b.openState(ctx, false)
		}
	}
	if err != nil {
		if errors.Is(err, errLocked) || ctx.Err() != nil {
			return nil, err
		}
		return nil, fmt.Errorf("the mailbox's state file: %w", err)
	}
	b.db = db
	release := func() error {
		b.db = nil
		return db.Close()
	}
	// The mailbox's format comes before anything else of it is read or
	// written, its directories among them, which a newer format may lay out
	// otherwise.
	if err := b.bringForward(); err != nil {
		_ = release() // the error is the format's
		return nil, err
	}
	if err := b.makeDirs(); err != nil {
		_ = release() // the error is the directories'
		return nil, err
	}
	return release, nil
}

// makeState makes the mailbox's state file where it has none, as writeFile makes
// every file a mailbox keeps: bbolt makes the database beside it and syncs it,
// and only then is it linked into place, where a link replaces nothing
// another command made first. bbolt writes a new database where it is
// opened, and one that a crash or a full disk cut off there can fault every
// process that opens it after (bbolt's README, of a database's first
// initialization; etcd-io/etcd#16596).
func (b *Mailbox) makeState() error {
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
	db, err := bolt.Open(tmp.Name(), 0o600, &bolt.Options{NoSync: !fsync})
	if err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), b.path("state")); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	// The name it was made under goes before the directory is synced, so a
	// cut after leaves no second link to the live file.
	if err := os.Remove(tmp.Name()); err != nil {
		return err
	}
	return syncDir(b.dir)
}

// claim takes the Mailbox's slot for one command or reading, waiting while
// another goroutine's holds it as hold waits for the state file: up to
// lockPatience, while ctx lasts, telling Options.Waiting once (#329).
func (b *Mailbox) claim(ctx context.Context) (func(), error) {
	select {
	case b.slot <- struct{}{}:
		return func() { <-b.slot }, nil
	default:
	}
	if b.waiting != nil {
		b.waiting()
	}
	wait := time.NewTimer(lockPatience)
	defer wait.Stop()
	select {
	case b.slot <- struct{}{}:
		return func() { <-b.slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-wait.C:
		return nil, errLocked
	}
}

// reading runs f, a reading of the mailbox that writes nothing and refuses a
// format other than this client's (formatIn), in the Mailbox's
// slot (claim) and with its state file open read-only throughout, which
// waits while a command writes the mailbox: what f's views read is one state,
// never a command's half done (#329), and the wait ends with ctx (#330).
// Where the open finds no state file, every view of f reads none, and opens
// none that a command makes in the meantime, which would read a second state
// and wait for that command with no context (#382).
func reading[T any](ctx context.Context, b *Mailbox, f func() (T, error)) (v T, err error) {
	release, err := b.claim(ctx)
	if err != nil {
		return v, err
	}
	defer release()
	db, err := b.openState(ctx, true)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		b.none = true
		defer func() { b.none = false }()
	case err != nil:
		return v, err
	default:
		b.db = db
		defer func() {
			b.db = nil
			_ = db.Close() // read only
		}()
	}
	// A reading refuses a format other than this client's, before f reads
	// anything: it writes nothing, so an older one waits for a command to
	// bring it forward.
	if err := b.view(func(s store) error {
		n, _, err := formatIn(s, true)
		b.format = n
		return err
	}); err != nil {
		return v, err
	}
	return f()
}

// locked runs f with the mailbox's lock held ([Mailbox.hold]), and lets go of it
// after, on every way out of f, a panic among them. It is the one entry of
// every command that writes the mailbox, so a mailbox that holds its own revocation
// is refused here, before anything is asked or written (PROTOCOL.md §12.5):
// only what §12.5 lets it still do runs on one, through lockedFinished. A
// command that learns it part way returns it at its exit (outcome).
func locked[T any](ctx context.Context, b *Mailbox, f func() (T, error)) (v T, err error) {
	return lockedFinished(ctx, b, func() (T, error) {
		if err := b.finished(); err != nil {
			return v, err
		}
		v, err := f()
		return outcome(b, v, err)
	})
}

// outcome is what a command that began with its mailbox unfinished returns:
// what it returned, or once it kept the mailbox's own revocation on the way
// (keepRevocation), that revocation alone as its error, beside what it did
// before (#332), whatever else it met after, a call refused among them.
func outcome[T any](b *Mailbox, v T, err error) (T, error) {
	if b.ended != nil {
		return v, b.ended
	}
	return v, err
}

// lockedFinished is locked for a command a mailbox that holds its own
// revocation still runs, since it neither carries a pass nor asks for
// anything §12.5 refuses: asking about a revocation and keeping one, a flush,
// which moves what waits to outbox/failed/, and a change to the mailbox's own
// files alone. Each signs nothing (sign). Each begins having kept no
// revocation of its own, and asks nothing once it has (call); finishing the
// mailbox is what some of them are for, so none is held to locked's outcome.
func lockedFinished[T any](ctx context.Context, b *Mailbox, f func() (T, error)) (v T, err error) {
	unclaim, err := b.claim(ctx)
	if err != nil {
		return v, err
	}
	defer unclaim()
	release, err := b.hold(ctx)
	if err != nil {
		return v, err
	}
	b.ended = nil
	defer func() {
		b.ended = nil
		if e := release(); err == nil {
			err = e
		}
	}()
	v, err = f()
	// Under the lock, and after everything the command did: what its answers
	// said of this client's version, which fails nothing.
	b.recordVersions(ctx)
	return v, err
}

// lockedDo is locked, for an f that returns only an error.
func (b *Mailbox) lockedDo(ctx context.Context, f func() error) error {
	_, err := locked(ctx, b, func() (struct{}, error) { return struct{}{}, f() })
	return err
}

// lockedFinishedDo is lockedFinished, for an f that returns only an error.
func (b *Mailbox) lockedFinishedDo(ctx context.Context, f func() error) error {
	_, err := lockedFinished(ctx, b, func() (struct{}, error) { return struct{}{}, f() })
	return err
}
