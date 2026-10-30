package client

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A fetch that is cut keeps what it read, and the next fetch of that message
// asks for the rest (PROTOCOL.md §12.3; #381): the bytes go to the mailbox's
// partial file as they are read, the file is synced at the end of an
// attempt that did not read them all, and only then does the mailbox's state
// record which message they are of and how many are synced, under
// "partial", as "<id> <length>". A fetch trusts the file only up to the
// length state records: whatever a crash left past it was never synced. The
// whole, those bytes and the range, is then held to the list's size and
// judged as a body read whole is, its id held to its SHA-256 (§12.3 check 8),
// so bytes a server splices in are refused as any wrong ciphertext is. One
// message's partial is kept at a time: a fetch of another starts the file
// afresh. It goes once its message is judged or gone (drop), and a drain
// that emptied the mailbox drops whatever is left (dropPartials).

// partialError is a fault of this mailbox writing its partial file, never a
// server's: it is an error, and nothing is judged.
type partialError struct{ err error }

func (e *partialError) Error() string { return "the mailbox's partial file: " + e.err.Error() }
func (e *partialError) Unwrap() error { return e.err }

// partial is one fetch's ciphertext of message id, listed at size bytes, as
// far as it is read: what earlier attempts kept (kept, synced, and asked
// after), then what this attempt reads.
type partial struct {
	b    *Mailbox
	id   string
	size int64
	kept int64
	have []byte
	f    *os.File // the partial file, while this attempt writes it
	err  error    // a write of it that failed
}

// resume is the fetch of message id, listed at size bytes, with the bytes
// an earlier attempt kept of it, when the mailbox's state records some of it
// below its size and the partial file still holds them.
func (b *Mailbox) resume(id string, size int64) (*partial, error) {
	p := &partial{b: b, id: id, size: size}
	rid, n, err := b.partialRecord()
	if err != nil || rid != id || n <= 0 || n >= size {
		return p, err
	}
	f, err := os.Open(b.path("partial"))
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, &partialError{err}
	}
	defer f.Close() //nolint:errcheck // read only
	have := make([]byte, n, size)
	if _, err := io.ReadFull(f, have); errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return p, nil // fewer bytes than state records: none is taken
	} else if err != nil {
		return nil, &partialError{err}
	}
	p.kept, p.have = n, have
	return p, nil
}

// partialRecord is what the mailbox's state records of its partial: which
// message, and how many of its bytes are synced; none is "" and 0, and so is
// a record of another form, which only saves a fetch, and goes at the next
// one (begin).
func (b *Mailbox) partialRecord() (id string, n int64, err error) {
	err = b.view(func(s store) error {
		rid, rn, ok := strings.Cut(string(s.get(bucketMailbox, "partial")), " ")
		v, perr := decimal([]byte(rn), "partial")
		if ok && hexID.MatchString(rid) && perr == nil && v <= protocol.MaxCiphertext {
			id, n = rid, int64(v) //nolint:gosec // at most protocol.MaxCiphertext
		}
		return nil
	})
	return id, n, err
}

// clearPartial deletes state's record of the mailbox's partial, of whatever
// message, where it keeps one.
func (b *Mailbox) clearPartial() error {
	held := false
	if err := b.view(func(s store) error { held = s.get(bucketMailbox, "partial") != nil; return nil }); err != nil || !held {
		return err
	}
	return b.update(func(s store) error { return s.del(bucketMailbox, "partial") })
}

// ask is the header a fetch sends: a Range for the bytes after those kept,
// or none to ask for the whole.
func (p *partial) ask() http.Header {
	if p.kept == 0 {
		return nil
	}
	return http.Header{"Range": {protocol.RangeAsk(p.kept)}}
}

// begin readies the partial file for an answer whose bytes begin at from:
// the bytes kept, which a 206 goes on from, or 0, the whole, which drops
// them and any other message's. State's record goes before the file is cut
// short, so it never names bytes the file no longer holds; past the bytes
// kept the file is cut to them, since what a crash left there was never
// synced.
func (p *partial) begin(from int64) error {
	if from == 0 {
		p.kept, p.have = 0, make([]byte, 0, p.size)
		if err := p.b.clearPartial(); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(p.b.path("partial"), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return &partialError{err}
	}
	if err := f.Truncate(from); err != nil {
		_ = f.Close() // the truncate's error wins
		return &partialError{err}
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		_ = f.Close() // the seek's error wins
		return &partialError{err}
	}
	p.f = f
	return nil
}

// Write keeps b, read of the answer, in memory and in the partial file.
func (p *partial) Write(b []byte) (int, error) {
	if _, err := p.f.Write(b); err != nil {
		p.err = &partialError{err}
		return 0, p.err
	}
	p.have = append(p.have, b...)
	return len(b), nil
}

// whole reports whether every byte of the message is read.
func (p *partial) whole() bool { return int64(len(p.have)) == p.size }

// end ends an attempt. One that read the whole leaves the file for drop,
// unsynced: nothing reads it again. One that did not syncs what it read,
// and the directory that holds the file, and then records it in state, so
// the next fetch of the message asks for the rest; a write that failed
// drops it instead.
func (p *partial) end() error {
	if p.f == nil {
		return nil
	}
	f := p.f
	p.f = nil
	if p.whole() {
		return f.Close()
	}
	if p.err == nil {
		if err := syncFile(f); err != nil {
			p.err = &partialError{err}
		}
	}
	if err := f.Close(); err != nil && p.err == nil {
		p.err = &partialError{err}
	}
	if p.err != nil || len(p.have) == 0 {
		return errors.Join(p.err, p.drop())
	}
	if err := syncDir(p.b.dir); err != nil {
		return errors.Join(&partialError{err}, p.drop())
	}
	if err := p.b.update(func(s store) error {
		return s.put(bucketMailbox, "partial", fmt.Appendf(nil, "%s %d", p.id, len(p.have)))
	}); err != nil {
		return err
	}
	step("partial kept")
	return nil
}

// drop deletes this message's partial: state's record, then the file. A
// partial of another message stays: this fetch never began, so the file
// holds that message's bytes still.
func (p *partial) drop() error {
	id, _, err := p.b.partialRecord()
	if err != nil || id != "" && id != p.id {
		return err
	}
	if p.f != nil {
		_ = p.f.Close() // it goes
		p.f = nil
	}
	if err := p.b.dropPartials(); err != nil {
		return err
	}
	step("partial dropped")
	return nil
}

// dropPartials deletes the mailbox's partial, whatever message it is of:
// state's record, then the file. A drain that emptied the mailbox left none of
// its messages on the server.
func (b *Mailbox) dropPartials() error {
	if err := b.clearPartial(); err != nil {
		return err
	}
	if err := removeIfExists(b.path("partial")); err != nil {
		return &partialError{err}
	}
	return nil
}

// read reads a fetch's answer, a 2xx, into ct through its partial: a 206
// that goes on from the bytes kept, its Content-Range the range asked of the
// listed size, or any other 2xx as the whole body, which starts the partial
// afresh. It reads no more than the listed size, and a byte past it to see
// that the body ends there (PROTOCOL.md §12.3). An answer that breaks that
// form is no answer, and drops the partial (notListed); one whose body could
// not be read is returned as readErr, the bytes read so far kept for end.
func (ct *ciphertext) read(name string, resp *http.Response) (readErr, err error) {
	p := ct.keep
	from := int64(0)
	if resp.StatusCode == http.StatusPartialContent {
		if v := resp.Header.Values("Content-Range"); p.kept == 0 || len(v) != 1 || v[0] != protocol.ContentRange(p.kept, ct.size) {
			return nil, errors.Join(notListed(name, ct.size), p.drop())
		}
		from = p.kept
	}
	// The listed size is at most the protocol's largest ciphertext, which
	// the list's form holds (protocol.MessageList), and is read whatever its
	// size (§11.10).
	if resp.ContentLength >= 0 && resp.ContentLength != ct.size-from {
		return nil, errors.Join(notListed(name, ct.size), p.drop())
	}
	if err := p.begin(from); err != nil {
		return nil, err
	}
	if _, err := io.Copy(p, io.LimitReader(resp.Body, ct.size-from+1)); err != nil {
		if p.err != nil {
			return nil, p.err
		}
		return err, nil
	}
	if !p.whole() {
		return nil, errors.Join(notListed(name, ct.size), p.drop())
	}
	ct.bytes = p.have
	return nil, nil
}

// got is how many bytes of the message this fetch read: the drain's bound
// on bytes counts them, and not those an earlier drain kept.
func (p *partial) got() int { return len(p.have) - int(p.kept) }
