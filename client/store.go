package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// The mailbox's state file, the bbolt database "state", holds what this client
// writes about the mailbox itself, each change made in one transaction: so no
// two records that go together are ever left one new and one old, and no
// file's existence stands for a step having finished. Keys, messages and the
// owner's own files stay files (client/doc.go): a key deleted inside a
// database stays in its free pages and in every copy of it, and messages and the
// owner's files are for a person to read, move and delete. A command that
// writes the mailbox holds the state file open from its start to its end, which
// is the mailbox's lock ([Mailbox.hold]); a reading with no command under way opens
// it read-only ([Mailbox.view]).
//
// Its buckets:
//
//	mailbox          the mailbox's own records, each by its name: serial, pass, etag, seen-floor, acl, acl-another-writer, acl-replaced, revoked, revoked-certs, renew-failed, not-made, partial, deprecation, sunset, document-read, latest (version.go)
//	prekeys      each prekey statement this mailbox signed, by its serial: the statement, its signature and when it was signed, in one value
//	made         the SHA-256 of every prekey statement this mailbox signed, in hex, never pruned: its serial
//	intent       the renewal under way, under "renewal": the number it took; under "adopt-acl", a restore's adoption of its server's ACL, until it is done; and under "acl-read", the read of its server's ACL a renewal recv began owes, with the serial the mailbox had published then, until it is made
//	peers        what this mailbox pinned of each peer, by its address, in one value
//	seen         the replay set, by ciphertext hash; seen-sender by sender and msg_id, and seen-time by sent_at, its two indexes
//	refused      what this client's checks found of each message it refused, by its id: refused/ keeps the message as served
//	meta         the mailbox's format, under "format" (format.go)
const (
	bucketMailbox    = "box" // the name stored in every state file, kept as it was
	bucketPrekeys    = "prekeys"
	bucketMade       = "made"
	bucketIntent     = "intent"
	bucketPeers      = "peers"
	bucketSeen       = "seen"
	bucketSeenSender = "seen-sender"
	bucketSeenTime   = "seen-time"
	bucketRefused    = "refused"
)

// store is one transaction of the mailbox's state. A store with no transaction
// is the state of a mailbox that has none yet, and holds nothing.
type store struct{ tx *bolt.Tx }

// get returns a copy of what bucket holds under key, or nil.
func (s store) get(bucket, key string) []byte {
	if s.tx == nil {
		return nil
	}
	bk := s.tx.Bucket([]byte(bucket))
	if bk == nil {
		return nil
	}
	return bytes.Clone(bk.Get([]byte(key)))
}

// put keeps value under key in bucket.
func (s store) put(bucket, key string, value []byte) error {
	bk, err := s.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	return bk.Put([]byte(key), value)
}

// del deletes what bucket holds under key; a key it does not hold is not an
// error.
func (s store) del(bucket, key string) error {
	if bk := s.tx.Bucket([]byte(bucket)); bk != nil {
		return bk.Delete([]byte(key))
	}
	return nil
}

// each calls f with every key and value bucket holds, in the keys' byte
// order, each a copy, until f returns an error.
func (s store) each(bucket string, f func(key, value []byte) error) error {
	if s.tx == nil {
		return nil
	}
	bk := s.tx.Bucket([]byte(bucket))
	if bk == nil {
		return nil
	}
	var keys, values [][]byte
	_ = bk.ForEach(func(k, v []byte) error { //nolint:errcheck // the function returns none
		keys, values = append(keys, bytes.Clone(k)), append(values, bytes.Clone(v))
		return nil
	})
	for i := range keys {
		if err := f(keys[i], values[i]); err != nil {
			return err
		}
	}
	return nil
}

// serialKey is a prekey's serial as the prekeys bucket keys it: eight bytes,
// big-endian, so the keys' order is the serials'.
func serialKey(n uint64) string { return string(binary.BigEndian.AppendUint64(nil, n)) }

// keySerial is the serial a prekeys key names.
func keySerial(k []byte) (uint64, error) {
	if len(k) != 8 {
		return 0, fmt.Errorf("the mailbox's state file holds a prekey under a key that is no serial")
	}
	return binary.BigEndian.Uint64(k), nil
}

// errNotHeld is a write to the mailbox's state by code that does not hold its
// lock: a bug in this client, never a state of the mailbox.
var errNotHeld = errors.New("this client wrote the mailbox's state without its lock")

// view runs f with the mailbox's state to read: the transaction under way, if f
// runs inside one; the state the command or reading holds, if one does;
// nothing, in a reading that found no state file ([reading]); otherwise the
// state file opened read-only for f alone, waiting as [Mailbox.hold] waits while
// another command of the mailbox holds it. A mailbox with no state file yet holds
// nothing.
func (b *Mailbox) view(f func(store) error) error {
	if b.tx != nil {
		return f(store{b.tx})
	}
	if b.none {
		return f(store{})
	}
	db := b.db
	if db == nil {
		ro, err := b.openState(context.Background(), true)
		if errors.Is(err, fs.ErrNotExist) {
			return f(store{})
		}
		if err != nil {
			return err
		}
		defer ro.Close() //nolint:errcheck // read only
		db = ro
	}
	return db.View(func(tx *bolt.Tx) error {
		b.tx = tx
		defer func() { b.tx = nil }()
		return f(store{tx})
	})
}

// update runs f in one transaction of the mailbox's state, the command's, which
// holds the lock: what f writes is kept only if it returns nil, and all of
// it together. Inside a transaction already under way, f is part of it, so
// what goes together is written together. No server call is made inside
// one.
func (b *Mailbox) update(f func(store) error) error {
	if failWrite != nil {
		if err := failWrite(); err != nil {
			return err
		}
	}
	if b.tx != nil {
		if !b.tx.Writable() {
			return errNotHeld
		}
		return f(store{b.tx})
	}
	if b.db == nil {
		return errNotHeld
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		b.tx = tx
		defer func() { b.tx = nil }()
		return f(store{tx})
	})
}

// failWrite is asked before each write of the mailbox's state, and a write it
// gives an error fails with it, as a full disk or EIO fails one: nil but in
// a test.
var failWrite func() error

// openState opens the mailbox's state file, waiting up to lockPatience while
// another command holds it: for writing, which only one command at a time
// may, or read-only, which any number of readings may at once, while no
// command writes. The first time it finds the file held it tells
// Options.Waiting, if set, so that a wait is not read as a hang.
//
// A flock gives a writer that waits no preference over readings, which
// overlap and leave it no moment the file is free, so it holds the mailbox's gate
// while it waits, a flock on the mailbox's directory, and every reading takes the
// gate and lets go of it around its own lock: readings wait behind a waiting
// writer, and those under way finish, as SQLite's PENDING lock has them
// (#344). The file is opened as bbolt opens it, never made (openWhole).
func (b *Mailbox) openState(ctx context.Context, readOnly bool) (*bolt.DB, error) {
	deadline := time.Now().Add(lockPatience)
	told := false
	waited := func() error {
		if !time.Now().Before(deadline) {
			return errLocked
		}
		if !told && b.waiting != nil {
			b.waiting()
			told = true
		}
		return ctx.Err()
	}
	// gated is the gate taken: held as gate, or none where the system has
	// none to hold (noGate), which a reading never waits for.
	var gate *os.File
	gated := false
	defer func() {
		if gate != nil {
			_ = gate.Close() // lets go of its flock
		}
	}()
	takeGate := func() error {
		g, ok, err := gateOf(b.dir)
		if ok {
			gate, gated = g, true
		}
		return err
	}
	if readOnly {
		for {
			if err := takeGate(); err != nil {
				return nil, err
			}
			if gated {
				break
			}
			if err := waited(); err != nil {
				return nil, err
			}
			time.Sleep(lockTry)
		}
	}
	for {
		db, err := bolt.Open(b.path("state"), 0o600, &bolt.Options{Timeout: lockTry, ReadOnly: readOnly, OpenFile: openWhole, NoSync: !fsync})
		if err == nil {
			return db, nil
		}
		if !errors.Is(err, berrors.ErrTimeout) {
			return nil, err
		}
		if !gated {
			if err := takeGate(); err != nil {
				return nil, err
			}
		}
		if err := waited(); err != nil {
			return nil, err
		}
	}
}

// gateOf takes the mailbox's gate: tryGate, the system's, or noGate in a test of
// a system that has none.
var gateOf = tryGate

// noGate is the gate where a directory cannot be flocked (gate_other.go): none
// to hold, so it is always taken, and a waiting writer has no preference over
// readings there.
func noGate(string) (*os.File, bool, error) { return nil, true, nil }

// openWhole opens the state file as bbolt asks, but never makes it, which
// makeState alone does, and refuses one of no bytes: bbolt would make a
// database in either, in place, where a cut can leave a file that faults
// every process that opens it after (#323).
func openWhole(name string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(name, flag&^os.O_CREATE, perm) //nolint:gosec // the mailbox's own state file
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || info.Size() == 0 {
		_ = f.Close()
		if err == nil {
			err = errEmptyState
		}
		return nil, err
	}
	return f, nil
}

// errEmptyState is a state file of no bytes, which this client never leaves.
var errEmptyState = refuse("the mailbox's state file is empty, which this client never leaves: something else made it, and it holds none of the mailbox's records; delete it, and the next command makes it again")
