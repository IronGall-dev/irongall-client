package client

import (
	"fmt"
	"strconv"
)

// The mailbox's format is one number for how its files are laid out and what
// each holds, the state file's records among them: client/doc.go lists each
// format and what it changed. The state file keeps it in its meta bucket
// under "format", a decimal integer, as etcd keeps its storage version and git
// its repository format version. A state file that records none, and a
// mailbox with no state file at all (one restored from its identity alone, or
// from a backup without it, or whose state file was deleted), are format 1:
// the oldest, so that bringing it forward reads every older layout right. So
// each step that changes the layout recognises the old form from the files
// themselves, and does nothing where it finds none. The identity, the address
// and identity document Open derives from it, and the directory's .gitignore
// are outside every format: Open reads and writes them before the format is
// read, so no format moves them.
const (
	bucketMeta = "meta"
	keyFormat  = "format"
)

// formatSteps bring a mailbox forward, one format at a time: formatSteps[n-1]
// takes a mailbox of format n to n+1. Each runs under the mailbox's lock and is
// safe to run again, since a step a crash cut short runs again from its start
// at the next command, and the format is recorded only once every step is
// done (bringForward).
var formatSteps []func(*Mailbox) error

// clientFormat is the format this client reads and writes.
func clientFormat() int { return len(formatSteps) + 1 }

// FormatError is a mailbox in a format other than this client's, which a
// command meets once it has the mailbox's state file open, before it reads or
// writes anything else of the mailbox but its identity. A newer one is refused
// by every command, with nothing written: a newer client wrote it. An older
// one is refused by every reading, and brought forward by any command that
// writes the mailbox ([Mailbox.Receive] among them), which an older client
// then refuses.
type FormatError struct {
	// Format is the mailbox's, and Client this client's.
	Format, Client int
}

func (e *FormatError) Error() string {
	if e.Format > e.Client {
		return fmt.Sprintf("REFUSED: the mailbox is in format %d, which a newer client wrote; this client reads format %d: run a newer dromas", e.Format, e.Client)
	}
	return fmt.Sprintf("REFUSED: the mailbox is in format %d, older than this client's %d: dromas recv, or any command that writes the mailbox, brings it forward", e.Format, e.Client)
}

// Code is the refusal's code: "mailbox_format_newer" or "mailbox_format_older".
func (e *FormatError) Code() string {
	if e.Format > e.Client {
		return "mailbox_format_newer"
	}
	return "mailbox_format_older"
}

// formatOf is the format s records, and whether it records one: 1 where it
// records none, or s is the state of a mailbox with no state file.
func formatOf(s store) (n int, recorded bool, err error) {
	raw := s.get(bucketMeta, keyFormat)
	if raw == nil {
		return 1, false, nil
	}
	n, err = strconv.Atoi(string(raw))
	if err != nil || n < 1 || strconv.Itoa(n) != string(raw) {
		return 0, true, errFormatUnread
	}
	return n, true, nil
}

// errFormatUnread is a format record that is not one: no client writes it.
var errFormatUnread = refuse("the mailbox's state file records a format that is no decimal number this client writes: something else wrote it, and nothing of the mailbox is read")

// formatIn is the format s records, refused where it is not this client's:
// newer always, older where older is set too, as a reading refuses it.
func formatIn(s store, older bool) (int, bool, error) {
	n, recorded, err := formatOf(s)
	if err != nil {
		return 0, recorded, err
	}
	if n > clientFormat() || older && n < clientFormat() {
		return n, recorded, &FormatError{Format: n, Client: clientFormat()}
	}
	return n, recorded, nil
}

// bringForward takes the mailbox to this client's format, under the lock and
// before the command reads anything else of it: a newer format is refused,
// and an older one runs each step from it in turn. The format is recorded
// last, alone, also where a state file recorded none: so a mailbox is stamped
// at the first command that writes it.
func (b *Mailbox) bringForward() error {
	var n int
	var recorded bool
	if err := b.view(func(s store) error {
		var err error
		n, recorded, err = formatIn(s, false)
		return err
	}); err != nil {
		return err
	}
	for ; n < clientFormat(); n++ {
		recorded = false
		if err := formatSteps[n-1](b); err != nil {
			return fmt.Errorf("bringing the mailbox from format %d to %d: %w", n, n+1, err)
		}
	}
	if !recorded {
		if err := b.update(func(s store) error {
			return s.put(bucketMeta, keyFormat, []byte(strconv.Itoa(n)))
		}); err != nil {
			return err
		}
	}
	b.format = n
	return nil
}
