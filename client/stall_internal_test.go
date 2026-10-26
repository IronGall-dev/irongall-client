package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// stallBound is the requestTimeout these tests set: short, so they run in
// seconds.
const stallBound = 200 * time.Millisecond

// shortBound sets requestTimeout to stallBound for one test.
func shortBound(t *testing.T) {
	old := requestTimeout
	requestTimeout = stallBound
	t.Cleanup(func() { requestTimeout = old })
}

// slowBox is a box whose default client reaches a server that the given
// transport plays, bounded as the default client is (stall).
func slowBox(t *testing.T, rt roundTripper) *Box {
	t.Helper()
	b, err := newBox(t.TempDir(), Options{Base: "https://dromas.dev", HTTPClient: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	b.stall = true
	return b
}

// readsEvery reads a request's body a chunk at a time, each after pause,
// until it ends or the request's context does; it returns how much it read.
func readsEvery(r *http.Request, chunk int, pause time.Duration) (int, error) {
	buf := make([]byte, chunk)
	n := 0
	for {
		select {
		case <-r.Context().Done():
			return n, r.Context().Err()
		case <-time.After(pause):
		}
		k, err := r.Body.Read(buf)
		n += k
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// cutOrGiveUp waits for r's context to end, as a server that sends nothing
// more waits, and gives up after many times stallBound with an error of its
// own: a call no bound cut.
func cutOrGiveUp(r *http.Request) error {
	select {
	case <-r.Context().Done():
		return r.Context().Err()
	case <-time.After(10 * stallBound):
		return errors.New("the call was never cut")
	}
}

// timeline records when each read of a body returned, and what it got, so
// a test of a timed bound can say which wait ran long when it fails.
type timeline struct {
	start time.Time
	mu    sync.Mutex
	b     strings.Builder
}

// of is body, each read of it recorded.
func (l *timeline) of(body io.ReadCloser) io.ReadCloser { return timedBody{body, l} }

func (l *timeline) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() == 0 {
		return "none"
	}
	return l.b.String()
}

type timedBody struct {
	io.ReadCloser
	l *timeline
}

func (b timedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.l.mu.Lock()
	fmt.Fprintf(&b.l.b, "%s %d %v; ", time.Since(b.l.start).Round(time.Millisecond), n, err)
	b.l.mu.Unlock()
	return n, err
}

func created() *http.Response {
	return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}
}

// A post of a ciphertext runs while its bytes move, for many times
// requestTimeout in all, and is cut once requestTimeout passes with none
// moving; the server's transport plays a slow link, read a chunk at a time.
func TestAPostRunsWhileItsBytesMove(t *testing.T) {
	shortBound(t)
	body := bytes.Repeat([]byte{1}, 64<<10)
	var reads timeline
	moving := slowBox(t, func(r *http.Request) (*http.Response, error) {
		r.Body = reads.of(r.Body)
		if _, err := readsEvery(r, 4<<10, stallBound/4); err != nil {
			return nil, err
		}
		return created(), nil
	})
	start := time.Now()
	reads.start = start
	if _, err := moving.exchange(context.Background(), http.MethodPost, "/v1/x/messages", &ciphertext{bytes: body}, nil, nil); err != nil {
		t.Fatalf("a post whose bytes kept moving, after %s: %v; the server's reads, from the start: %s", time.Since(start), err, reads.String())
	}
	if took := time.Since(start); took < 3*stallBound {
		t.Fatalf("the slow link took %s, too little to show the bound is not on the whole", took)
	}
	stalled := slowBox(t, func(r *http.Request) (*http.Response, error) {
		if _, err := r.Body.Read(make([]byte, 4<<10)); err != nil {
			return nil, err
		}
		return nil, cutOrGiveUp(r) // and reads nothing more
	})
	start = time.Now()
	_, err := stalled.exchange(context.Background(), http.MethodPost, "/v1/x/messages", &ciphertext{bytes: body}, nil, nil)
	var te *transportError
	if took := time.Since(start); !errors.As(err, &te) || te.kind != "no answer within the wait" || took > 5*stallBound {
		t.Fatalf("a post whose bytes stopped: %v after %s", err, took)
	}
}

// The wait for an answer's head is bounded by requestTimeout, from the last
// byte the call sent: a fetch, which sends none, from its start.
func TestTheWaitForTheHeadIsBounded(t *testing.T) {
	shortBound(t)
	b := slowBox(t, func(r *http.Request) (*http.Response, error) {
		return nil, cutOrGiveUp(r)
	})
	start := time.Now()
	_, err := b.exchange(context.Background(), http.MethodGet, "/v1/x/messages/y", nil, nil, &ciphertext{size: 10})
	var te *transportError
	if took := time.Since(start); !errors.As(err, &te) || te.kind != "no answer within the wait" || took > 5*stallBound {
		t.Fatalf("a fetch with no answer: %v after %s", err, took)
	}
}

// trickle is a body that gives one byte each pause, of n in all, and ends
// with ctx.
type trickle struct {
	ctx   context.Context
	n     int
	pause time.Duration
}

func (tr *trickle) Read(p []byte) (int, error) {
	if tr.n == 0 {
		return 0, io.EOF
	}
	select {
	case <-tr.ctx.Done():
		return 0, tr.ctx.Err()
	case <-time.After(tr.pause):
	}
	tr.n--
	p[0] = ' '
	return 1, nil
}

func (tr *trickle) Close() error { return nil }

// Any call but a ciphertext's send or fetch is bounded whole: an answer
// whose body comes a byte at a time, never as long as requestTimeout without
// one, is cut at requestTimeout all the same, so a server that trickles a
// list or a read of a box cannot hold the box's lock (#381's trickle).
func TestAnyOtherCallIsBoundedWhole(t *testing.T) {
	shortBound(t)
	b := slowBox(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: &trickle{r.Context(), 40, stallBound / 4}}, nil
	})
	start := time.Now()
	var out struct{}
	_, err := b.exchange(context.Background(), http.MethodGet, "/v1/x", nil, nil, &out)
	var te *transportError
	if took := time.Since(start); !errors.As(err, &te) || te.kind != "no answer within the wait" || took > 5*stallBound {
		t.Fatalf("a read whose answer trickles: %v after %s", err, took)
	}
}

// A post's answer, once its ciphertext is sent, is bounded whole: a receipt
// that comes a byte at a time, never as long as requestTimeout without one,
// is cut at requestTimeout all the same, so a server cannot hold a send, and
// the box's lock, by trickling what it answers (#403 item 3).
func TestAPostsAnswerIsBoundedWholeOnceItsBodyIsSent(t *testing.T) {
	shortBound(t)
	body := bytes.Repeat([]byte{1}, 1<<10)
	b := slowBox(t, func(r *http.Request) (*http.Response, error) {
		if _, err := io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: &trickle{r.Context(), 40, stallBound / 4}}, nil
	})
	start := time.Now()
	var out struct{}
	_, err := b.exchange(context.Background(), http.MethodPost, "/v1/x/messages", &ciphertext{bytes: body}, nil, &out)
	var te *transportError
	if took := time.Since(start); !errors.As(err, &te) || te.kind != "no answer within the wait" || took > 3*stallBound {
		t.Fatalf("a post whose answer trickles: %v after %s (the bound is %s)", err, took, stallBound)
	}
}

// counted is a body that counts the bytes read of it.
type counted struct {
	io.Reader
	n *int
}

func (c counted) Read(p []byte) (int, error) {
	k, err := c.Reader.Read(p)
	*c.n += k
	return k, err
}

func (counted) Close() error { return nil }

// A post's answer once the server took it, a receipt, is read no further
// than a receipt's size: one longer is an answer that breaks its form, and
// what is past it is never read (#403 item 3).
func TestAPostsAnswerIsReadNoFurtherThanAReceipt(t *testing.T) {
	t.Parallel()
	read := 0
	b := slowBox(t, func(r *http.Request) (*http.Response, error) {
		if _, err := io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		long := io.MultiReader(strings.NewReader(`{"id":"`), strings.NewReader(strings.Repeat("0", 1<<20)), strings.NewReader(`"}`))
		return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Body: counted{long, &read}}, nil
	})
	var out struct {
		ID string `json:"id"`
	}
	_, err := b.exchange(context.Background(), http.MethodPost, "/v1/x/messages", &ciphertext{bytes: []byte{1}}, nil, &out)
	if err == nil || read > maxReceipt {
		t.Fatalf("a receipt of a MiB: %v, %d bytes of it read (a receipt is at most %d)", err, read, maxReceipt)
	}
}

// A fetch's answer that is not its ciphertext, a problem, is bounded whole
// from its head: only a ciphertext's bytes hold a call open by moving
// (#403 item 3).
func TestAFetchsProblemIsBoundedWhole(t *testing.T) {
	shortBound(t)
	b := slowBox(t, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: &trickle{r.Context(), 40, stallBound / 4}}, nil
	})
	start := time.Now()
	_, err := b.exchange(context.Background(), http.MethodGet, "/v1/x/messages/y", nil, nil, &ciphertext{size: 10})
	var te *transportError
	if took := time.Since(start); !errors.As(err, &te) || te.kind != "no answer within the wait" || took > 3*stallBound {
		t.Fatalf("a fetch whose problem trickles: %v after %s (the bound is %s)", err, took, stallBound)
	}
}

// The stall keeps when a byte last moved as an offset from its start, read
// on the monotonic clock, so a step of the wall clock while a call is in
// flight neither holds a call with no byte moving past requestTimeout nor
// cuts one whose bytes move (#403 item 4).
func TestTheStallCountsOnTheMonotonicClock(t *testing.T) {
	t.Parallel()
	_, s := newStall(context.Background())
	defer s.stop()
	if s.base == s.base.Round(0) {
		t.Fatal("the stall's start carries no monotonic reading")
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := s.reading(io.NopCloser(strings.NewReader("x"))).Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	since := time.Since(s.base)
	if last := time.Duration(s.last.Load()); last < 10*time.Millisecond || last > since {
		t.Fatalf("a byte that moved 10ms or more after the stall began is kept as %d, not an offset from its start up to %s", s.last.Load(), since)
	}
}
