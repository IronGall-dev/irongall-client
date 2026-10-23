package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
	b, err := newBox(t.TempDir(), Options{Base: "https://irongall.dev", HTTPClient: &http.Client{Transport: rt}})
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

func created() *http.Response {
	return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}
}

// A post of a ciphertext runs while its bytes move, for many times
// requestTimeout in all, and is cut once requestTimeout passes with none
// moving; the server's transport plays a slow link, read a chunk at a time.
func TestAPostRunsWhileItsBytesMove(t *testing.T) {
	shortBound(t)
	body := bytes.Repeat([]byte{1}, 64<<10)
	moving := slowBox(t, func(r *http.Request) (*http.Response, error) {
		if _, err := readsEvery(r, 4<<10, stallBound/4); err != nil {
			return nil, err
		}
		return created(), nil
	})
	start := time.Now()
	if _, err := moving.exchange(context.Background(), http.MethodPost, "/v1/x/messages", &ciphertext{bytes: body}, nil, nil); err != nil {
		t.Fatalf("a post whose bytes kept moving, after %s: %v", time.Since(start), err)
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
