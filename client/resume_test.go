package client_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A fetch that is cut keeps what it read in the box's partial file, and the
// next fetch of that message asks for the rest by range (PROTOCOL.md §12.3;
// #381). The fake answers ranges as irongall-server does, so these tests
// meet a 206 from an honest server; a middleware plays the link that cuts
// and the server that lies.

// fetches watches the fetches of box b's mail: what Range each asked, and
// how many bytes of body the server wrote to them.
type fetches struct {
	b      *client.Box
	mu     sync.Mutex
	ranges []string
	served atomic.Int64
}

// is reports whether r is a fetch of b's mail, and keeps its Range.
func (f *fetches) is(r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, boxPath(f.b)+"/messages/") {
		return false
	}
	f.mu.Lock()
	f.ranges = append(f.ranges, r.Header.Get("Range"))
	f.mu.Unlock()
	return true
}

// asked is the Range of each fetch so far, "" for none.
func (f *fetches) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ranges)
}

// counted is w, each byte of body written to it counted as served.
func (f *fetches) counted(w http.ResponseWriter) http.ResponseWriter { return &counting{w, &f.served} }

type counting struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (c *counting) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *counting) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// honest is the server's own answer to r, kept: what the fake would write.
func honest(next http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	return rec
}

// cutAfter answers a fetch with the head of the whole ciphertext ct and its
// first n bytes, then drops the connection, as a link that fails does.
func cutAfter(f *fetches, w http.ResponseWriter, ct []byte, n int) {
	w.Header().Set("Content-Type", protocol.CiphertextContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(ct)))
	w.WriteHeader(http.StatusOK)
	m, _ := w.Write(ct[:n])
	f.served.Add(int64(m))
	w.(http.Flusher).Flush()
	panic(http.ErrAbortHandler)
}

// partialOf is what box b keeps of a message a fetch was cut in: the message
// its state names, how many bytes it records, and how many the partial file
// holds, -1 for none.
func partialOf(t *testing.T, b *client.Box) (string, int64, int64) {
	t.Helper()
	id, n, err := b.Partial()
	if err != nil {
		t.Fatal(err)
	}
	size := int64(-1)
	if fi, err := os.Stat(filepath.Join(b.Dir(), "partial")); err == nil {
		size = fi.Size()
	}
	return id, n, size
}

// noPartial fails the test unless box b keeps no partial, in state or as a
// file.
func noPartial(t *testing.T, b *client.Box) {
	t.Helper()
	if id, n, size := partialOf(t, b); id != "" || n != 0 || size != -1 {
		t.Fatalf("the box keeps a partial of %q, %d bytes recorded, a file of %d", id, n, size)
	}
}

// cutOnce sends a message to b, and has its first fetch cut half way: it
// returns the message's id and its ciphertext, as the server holds it.
func cutOnce(t *testing.T, e *env, a, b *client.Box, f *fetches) (string, []byte) {
	t.Helper()
	id := send(t, a, b, strings.Repeat("a message cut in the middle of its fetch. ", 1500)).ID
	var held atomic.Pointer[[]byte]
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !f.is(r) {
			next.ServeHTTP(w, r)
			return
		}
		ct := honest(next, r).Body.Bytes()
		held.Store(&ct)
		cutAfter(f, w, ct, len(ct)/2)
	})
	if _, err := b.Receive(context.Background()); err == nil || !strings.Contains(err.Error(), "an answer whose body could not be read") {
		t.Fatalf("a fetch cut half way: %v", err)
	}
	e.srv.SetMiddle(nil)
	ct := *held.Load()
	if got, n, size := partialOf(t, b); got != id || n != int64(len(ct)/2) || size != n {
		t.Fatalf("after a fetch cut at %d of %d bytes the box keeps %d of %q, a file of %d", len(ct)/2, len(ct), n, got, size)
	}
	return id, ct
}

// A fetch the link cuts keeps what it read, synced and recorded, and the
// next asks for the rest alone: the message is delivered once, the server
// serves each byte of it once, and nothing of it is kept after.
func TestACutFetchGoesOnFromWhatItKept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := &fetches{b: b}
	id, ct := cutOnce(t, e, a, b, f)
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if f.is(r) {
			w = f.counted(w)
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Delivered) != 1 || res.Delivered[0].ID != id || len(res.Refused) != 0 || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("the drain after the cut: %+v; the server holds %d", res, e.srv.Count(b.Address()))
	}
	if got, want := f.asked(), []string{"", protocol.RangeAsk(int64(len(ct) / 2))}; !slices.Equal(got, want) {
		t.Errorf("the fetches asked %q, want %q", got, want)
	}
	if n := f.served.Load(); n != int64(len(ct)) {
		t.Errorf("the server served %d bytes of a ciphertext of %d", n, len(ct))
	}
	noPartial(t, b)
}

// Bytes a server splices into the range it answers make a whole that is not
// the ciphertext the id names: it is refused as a wrong body read whole is,
// with the same code, kept in quarantine/ and acked, and the partial goes.
func TestBytesSplicedIntoARangeAreRefusedAsAWrongCiphertext(t *testing.T) {
	t.Parallel()
	flip := func(ct []byte, at int) []byte {
		out := slices.Clone(ct)
		out[at] ^= 0x01
		return out
	}
	var codes []string
	for _, spliced := range []bool{false, true} {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		f := &fetches{b: b}
		var id string
		if spliced {
			id, _ = cutOnce(t, e, a, b, f)
		} else {
			id = send(t, a, b, strings.Repeat("a message served with one byte changed. ", 1500)).ID
		}
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if !f.is(r) {
				next.ServeHTTP(w, r)
				return
			}
			rec := honest(next, r)
			body := rec.Body.Bytes()
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(flip(body, len(body)*3/4))
		})
		res := receive(t, b)
		if len(res.Refused) != 1 || len(res.Delivered) != 0 || res.Refused[0].ID == id || e.srv.Count(b.Address()) != 0 {
			t.Fatalf("spliced %v: %+v; the server holds %d", spliced, res, e.srv.Count(b.Address()))
		}
		if qs, err := b.Quarantined(t.Context()); err != nil || len(qs) != 1 {
			t.Fatalf("spliced %v: quarantine/ holds %+v, %v", spliced, qs, err)
		}
		noPartial(t, b)
		codes = append(codes, res.Refused[0].Code)
	}
	if codes[0] != codes[1] || codes[0] != client.RefusedDecrypt {
		t.Errorf("a whole body with a byte changed is refused %s, and one spliced into a range %s", codes[0], codes[1])
	}
}

// A 206 whose Content-Range is not the range asked, or not of the size the
// list gives, or a 206 to a fetch that asked no range, breaks the answer's
// form: the drain stops, nothing is judged or acked, and the partial goes,
// so the next fetch asks for the whole.
func TestA206ThatIsNotTheRangeAskedBreaksItsForm(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, c := range []struct {
		name string
		// answer writes the 206 to a fetch of ct whose Range asked from n.
		answer func(w http.ResponseWriter, ct []byte, n int)
		cut    bool
	}{
		{"from a byte before the one asked", func(w http.ResponseWriter, ct []byte, n int) {
			fakeserver.WritePartial(w, ct, int64(n-1))
		}, true},
		{"from a byte after the one asked", func(w http.ResponseWriter, ct []byte, n int) {
			fakeserver.WritePartial(w, ct, int64(n+1))
		}, true},
		{"to a byte before the last", func(w http.ResponseWriter, ct []byte, n int) {
			partial(w, ct[n:len(ct)-1], "bytes "+strconv.Itoa(n)+"-"+strconv.Itoa(len(ct)-2)+"/"+strconv.Itoa(len(ct)))
		}, true},
		{"of another length", func(w http.ResponseWriter, ct []byte, n int) {
			partial(w, ct[n:], "bytes "+strconv.Itoa(n)+"-"+strconv.Itoa(len(ct)-1)+"/"+strconv.Itoa(len(ct)+1))
		}, true},
		{"with no Content-Range", func(w http.ResponseWriter, ct []byte, n int) { partial(w, ct[n:]) }, true},
		{"with two", func(w http.ResponseWriter, ct []byte, n int) {
			cr := protocol.ContentRange(int64(n), int64(len(ct)))
			partial(w, ct[n:], cr, cr)
		}, true},
		{"to a fetch that asked none", func(w http.ResponseWriter, ct []byte, _ int) { fakeserver.WritePartial(w, ct, 0) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			f := &fetches{b: b}
			id := ""
			n := 0
			if c.cut {
				var ct []byte
				id, ct = cutOnce(t, e, a, b, f)
				n = len(ct) / 2
			} else {
				id = send(t, a, b, "answered 206 to a fetch of it whole").ID
			}
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if !f.is(r) {
					next.ServeHTTP(w, r)
					return
				}
				r.Header.Del("Range")
				c.answer(w, honest(next, r).Body.Bytes(), n)
			})
			res, err := b.Receive(context.Background())
			if err == nil || !strings.Contains(err.Error(), "bytes of ciphertext the list gives") || len(res.Delivered)+len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1 {
				t.Fatalf("%+v, %v; the server holds %d", res, err, e.srv.Count(b.Address()))
			}
			noPartial(t, b)
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				f.is(r)
				next.ServeHTTP(w, r)
			})
			if res := receive(t, b); len(res.Delivered) != 1 || res.Delivered[0].ID != id {
				t.Fatalf("the drain after: %+v", res)
			}
			if got := f.asked(); got[len(got)-1] != "" {
				t.Errorf("the fetch after asked %q", got[len(got)-1])
			}
		})
	}
}

// partial writes a 206 of body with each Content-Range given.
func partial(w http.ResponseWriter, body []byte, contentRange ...string) {
	w.Header().Set("Content-Type", protocol.CiphertextContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	for _, cr := range contentRange {
		w.Header().Add("Content-Range", cr)
	}
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(body)
}

// A 200 to a fetch that asked for a range is the whole body, as RFC 9110
// §14.2 lets a server ignore a Range: the partial starts afresh, and the
// message is delivered from the whole.
func TestA200ToARangedFetchStartsAfresh(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := &fetches{b: b}
	id, ct := cutOnce(t, e, a, b, f)
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if f.is(r) {
			r.Header.Del("Range")
			w = f.counted(w)
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Delivered) != 1 || res.Delivered[0].ID != id || e.srv.Count(b.Address()) != 0 {
		t.Fatalf("a 200 to the ranged fetch: %+v", res)
	}
	if got, want := f.served.Load(), int64(len(ct)+len(ct)/2); got != want {
		t.Errorf("the server served %d bytes, want %d: the half, then the whole", got, want)
	}
	noPartial(t, b)
}

// What a box kept of a message goes when the message leaves the list: a
// drain that empties the box drops it, and a fetch answered no_such_message
// drops it too.
func TestAPartialGoesWhenItsMessageLeavesTheList(t *testing.T) {
	t.Run("a drain that empties the box", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		cutOnce(t, e, a, b, &fetches{b: b})
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages" {
				fakeserver.WriteList(w, protocol.MessageList{Messages: []protocol.MessageInfo{}})
				return
			}
			next.ServeHTTP(w, r)
		})
		receive(t, b)
		noPartial(t, b)
	})
	t.Run("a fetch answered no_such_message", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		f := &fetches{b: b}
		id, _ := cutOnce(t, e, a, b, f)
		send(t, a, b, "behind it, where the drain stops")
		client.SetDrainLimits(t, 1, 64<<20, 100) // so the drain stops before it could drop what is left
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if f.is(r) && strings.HasSuffix(r.URL.Path, id) {
				fakeserver.WriteJSON(w, http.StatusNotFound, protocol.Problem{Type: protocol.CodeNoSuchMessage.TypeURI(), Title: protocol.CodeNoSuchMessage.Title(), Status: http.StatusNotFound, Code: protocol.CodeNoSuchMessage})
				return
			}
			next.ServeHTTP(w, r)
		})
		if res := receive(t, b); !res.More {
			t.Fatalf("a drain past its limit of one: %+v", res)
		}
		noPartial(t, b)
	})
	t.Run("a drain that stops at its limit keeps it", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		f := &fetches{b: b}
		id, ct := cutOnce(t, e, a, b, f)
		client.SetDrainLimits(t, 0, 64<<20, 100)
		if res := receive(t, b); !res.More {
			t.Fatalf("a drain of no messages: %+v", res)
		}
		if got, n, _ := partialOf(t, b); got != id || n != int64(len(ct)/2) {
			t.Fatalf("a drain that stopped at its limit kept %d of %q", n, got)
		}
	})
}

// The default client cuts a fetch once requestTimeout passes with no byte of
// it moving, and keeps what it read; one whose bytes keep moving runs for as
// long as they do, many times that.
func TestAFetchIsCutWhenItStallsAndNotWhileItMoves(t *testing.T) {
	const bound = 300 * time.Millisecond
	client.SetRequestTimeout(t, bound)
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	id := send(t, a, b, strings.Repeat("a message sent at the speed of a slow link. ", 1500)).ID
	f := &fetches{b: b}
	stalled := make(chan struct{})
	defer close(stalled)
	var stall atomic.Bool
	stall.Store(true)
	var size atomic.Int64
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !f.is(r) {
			next.ServeHTTP(w, r)
			return
		}
		rec := honest(next, r)
		body := rec.Body.Bytes()
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		if stall.Load() {
			size.Store(int64(len(body)))
			_, _ = w.Write(body[:len(body)/2])
			w.(http.Flusher).Flush()
			<-stalled
			return
		}
		// A link that moves 2 KiB each 50 ms: far longer than the bound in
		// all, and never that long without a byte.
		for i := 0; i < len(body); i += 2 << 10 {
			_, _ = w.Write(body[i:min(i+2<<10, len(body))])
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})
	start := time.Now()
	_, err := b.Receive(context.Background())
	if took := time.Since(start); err == nil || !strings.Contains(err.Error(), "no answer within the wait") || took > 5*bound {
		t.Fatalf("a fetch that stopped half way: %v after %s", err, took)
	}
	if got, n, _ := partialOf(t, b); got != id || n != size.Load()/2 {
		t.Fatalf("a fetch cut by its stall kept %d of %q", n, got)
	}
	stall.Store(false)
	start = time.Now()
	res := receive(t, b)
	if took := time.Since(start); len(res.Delivered) != 1 || took < 3*bound {
		t.Fatalf("a fetch whose bytes kept moving: %+v after %s", res, took)
	}
}

// The partial file is taken only as far as the box's state records it
// synced: bytes past that, which a crash can leave unsynced, are cut off,
// and the next fetch asks from the recorded length.
func TestAPartialIsTakenOnlyAsFarAsStateRecordsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := &fetches{b: b}
	id, ct := cutOnce(t, e, a, b, f)
	file, err := os.OpenFile(filepath.Join(b.Dir(), "partial"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("bytes no sync covered")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		f.is(r)
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Delivered) != 1 || res.Delivered[0].ID != id {
		t.Fatalf("after bytes past the record: %+v", res)
	}
	if got := f.asked(); got[len(got)-1] != protocol.RangeAsk(int64(len(ct)/2)) {
		t.Fatalf("the fetch asked %q, want from the %d bytes recorded", got[len(got)-1], len(ct)/2)
	}
}

// A partial goes once its message is judged, though the drain then stops at
// its limit and never empties the box.
func TestAPartialGoesOnceItsMessageIsJudged(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := &fetches{b: b}
	id, _ := cutOnce(t, e, a, b, f)
	send(t, a, b, "behind it, where the drain stops")
	client.SetDrainLimits(t, 1, 64<<20, 100)
	res := receive(t, b)
	if len(res.Delivered) != 1 || res.Delivered[0].ID != id || !res.More {
		t.Fatalf("a drain of one: %+v", res)
	}
	noPartial(t, b)
}

// A fetch of another message, which a server may list first, drops what was
// kept of the one before it, in state before the file takes its bytes: the
// message cut is fetched whole after, and delivered, never judged on the
// other's bytes.
func TestAFetchOfAnotherMessageDropsWhatWasKept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := &fetches{b: b}
	id, _ := cutOnce(t, e, a, b, f)
	other := send(t, a, b, strings.Repeat("listed first by its server, fetched whole. ", 1500)).ID
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages" {
			var list protocol.MessageList
			if err := protocol.Unmarshal(honest(next, r).Body.Bytes(), &list); err != nil || len(list.Messages) != 2 {
				t.Errorf("the list: %v", err)
				return
			}
			slices.Reverse(list.Messages)
			fakeserver.WriteList(w, list)
			return
		}
		f.is(r)
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Refused) != 0 || len(res.Delivered) != 2 || res.Delivered[0].ID != other || res.Delivered[1].ID != id {
		t.Fatalf("a drain that fetched another message first: %+v", res)
	}
	if got := f.asked(); !slices.Equal(got[len(got)-2:], []string{"", ""}) {
		t.Errorf("the fetches asked %q: both whole", got)
	}
	noPartial(t, b)
}

// No size a server gives is taken past the protocol's largest ciphertext
// (PROTOCOL.md §11.10, §11.11, §11.12), whether the box keeps part of the message
// or none: a list that gives one is no answer, and a fetch's Content-Length
// or Content-Range that is not the listed size breaks its answer's form.
// Either way the drain stops with nothing judged or acked, the message still
// on the server, nothing fetched on a list that is no answer, and nothing
// made by the size: a resume once made its buffer from the listed size
// before any bound held it, and 2^53 − 1 panicked the drain (#404). 🛑 No
// case asks for more than a ciphertext's bytes where a regression would
// allocate them: a size like 1 << 40 there has the host find a TiB.
func TestNoSizeAServerGivesIsTakenPastTheLargestCiphertext(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	type answer func(w http.ResponseWriter, honest *httptest.ResponseRecorder, size int64)
	header := func(name string, value func(kept, size int64) string) answer {
		return func(w http.ResponseWriter, h *httptest.ResponseRecorder, size int64) {
			kept := int64(0)
			if h.Code == http.StatusPartialContent {
				var last, length int64
				if _, err := fmt.Sscanf(h.Header().Get("Content-Range"), "bytes %d-%d/%d", &kept, &last, &length); err != nil {
					panic(err)
				}
			}
			maps.Copy(w.Header(), h.Header())
			w.Header().Set(name, value(kept, size))
			w.WriteHeader(h.Code)
			_, _ = w.Write(h.Body.Bytes())
		}
	}
	for _, c := range []struct {
		name  string
		sizes []int64
		// fetch answers the fetch, given the honest answer, with the size
		// it gives; nil leaves it honest and gives the size in the list.
		fetch answer
		cut   bool
	}{
		{"in the list", []int64{-1, protocol.MaxCiphertext + 1, protocol.MaxInteger}, nil, false},
		{"in the list, part of it kept", []int64{-1, protocol.MaxCiphertext + 1, protocol.MaxInteger}, nil, true},
		// net/http's server sends no Content-Length of -1, and its client
		// takes none: the two larger are the ones a server can give.
		{"as the Content-Length", []int64{protocol.MaxCiphertext + 1, protocol.MaxInteger}, header("Content-Length", func(_, size int64) string { return strconv.FormatInt(size, 10) }), false},
		{"as the Content-Length, part of it kept", []int64{protocol.MaxCiphertext + 1, protocol.MaxInteger}, header("Content-Length", func(kept, size int64) string { return strconv.FormatInt(size-kept, 10) }), true},
		{"as the Content-Range's length", []int64{-1, protocol.MaxCiphertext + 1, protocol.MaxInteger}, header("Content-Range", func(kept, size int64) string { return fmt.Sprintf("bytes %d-%d/%d", kept, size-1, size) }), true},
	} {
		for _, size := range c.sizes {
			t.Run(c.name+"/"+strconv.FormatInt(size, 10), func(t *testing.T) {
				e := newEnv(t)
				a, b := e.box(protocol.Classic), e.box(protocol.Classic)
				f := &fetches{b: b}
				var id string
				if c.cut {
					id, _ = cutOnce(t, e, a, b, f)
				} else {
					id = send(t, a, b, strings.Repeat("a message listed or served at a size past any. ", 1500)).ID
				}
				before := len(f.asked())
				e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					switch {
					case f.is(r) && c.fetch != nil:
						c.fetch(w, honest(next, r), size)
					case r.Method == http.MethodGet && r.URL.Path == boxPath(b)+"/messages" && c.fetch == nil:
						var list protocol.MessageList
						if err := protocol.Unmarshal(honest(next, r).Body.Bytes(), &list); err != nil || len(list.Messages) != 1 {
							t.Errorf("the list: %v", err)
							return
						}
						list.Messages[0].Size = size
						fakeserver.WriteList(w, list)
					default:
						next.ServeHTTP(w, r)
					}
				})
				res, err := func() (res *client.Result, err error) {
					defer func() {
						if p := recover(); p != nil {
							res, err = &client.Result{}, fmt.Errorf("the drain panicked: %v", p)
						}
					}()
					return b.Receive(context.Background())
				}()
				switch {
				case err == nil || len(res.Delivered)+len(res.Refused) != 0 || e.srv.Count(b.Address()) != 1:
					t.Fatalf("%+v, %v; the server holds %d", res, err, e.srv.Count(b.Address()))
				case c.fetch == nil && (!errors.Is(err, protocol.ErrMemberValue) || len(f.asked()) != before):
					t.Fatalf("a list that is no answer: %v, and %d fetches", err, len(f.asked())-before)
				case c.fetch != nil && !strings.Contains(err.Error(), "bytes of ciphertext the list gives"):
					t.Fatalf("a fetch of another size: %v", err)
				}
				e.srv.SetMiddle(nil)
				if res := receive(t, b); len(res.Delivered) != 1 || res.Delivered[0].ID != id {
					t.Fatalf("the drain after: %+v", res)
				}
			})
		}
	}
}
