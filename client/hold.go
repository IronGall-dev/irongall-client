package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/time/rate"
)

// A box that waits for mail holds its list (PROTOCOL.md §11.11), one held
// request after another, down one TLS connection that it keeps. Two layers
// fail and recover apart:
//
//   - The connection. The default client keeps one, resumes TLS when it
//     makes another (a session cache), and sends no keep-alive on it:
//     every probe across many held connections is traffic, and the answer
//     that ends each hold is traffic enough for most networks. A connection
//     that drops before its hold ends is a network that forgets a silent
//     connection sooner; the next is made with TCP keep-alive below the
//     hold that dropped, so the connection lives and the wait stays long.
//   - The request. Each asks the server to hold it for the box's wait,
//     DefaultHold at first, and ends at that wait and a margin whether
//     answered or not: a dead path is found there, never by a probe. Only a
//     connection that drops with keep-alive on shortens the wait, never
//     below MinHold. Holds start at most about once a minute (holdEvery),
//     so a connection that fails at once is a minute's poll, within the
//     poll budget (PROTOCOL.md §11.5).

// DefaultHold is how long a box asks the server to hold its list at first:
// under the 5 minutes at which common networks drop a silent connection.
const DefaultHold = 4*time.Minute + 45*time.Second

// MinHold is the shortest wait a box asks for, however its connections
// drop: the poll budget covers a list a minute.
const MinHold = time.Minute

// holdMargin is how long after its wait a held request may go unanswered
// before the box takes its connection for dead: the server answers at the
// wait at the latest.
const holdMargin = 15 * time.Second

// holdEvery and holdBurst pace the holds a box starts: one a minute on
// average, two at once.
const (
	holdEvery = time.Minute
	holdBurst = 2
)

// dialTimeout bounds a connection's making, and the default transport's
// TLS handshake has its own (net/http's TLSHandshakeTimeout).
const dialTimeout = 10 * time.Second

// holding is what a box has learned of its network while it holds its
// list: the wait it asks for, and the keep-alive its connections need.
type holding struct {
	mu        sync.Mutex
	wait      time.Duration // the wait it asks for; DefaultHold when zero
	keepAlive time.Duration // the keep-alive a new connection gets; none when zero
	starts    *rate.Limiter
}

func (h *holding) current() (wait, keepAlive time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wait == 0 {
		h.wait = DefaultHold
	}
	return h.wait, h.keepAlive
}

// dropped records a connection that dropped after held, before its hold
// ended: the next connection gets keep-alive below that, and only one that
// drops with keep-alive on shortens the wait, to under held. It returns what
// the box asks for and sets from now on.
func (h *holding) dropped(held time.Duration) (wait, keepAlive time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	below := max(held-holdMargin, MinHold/2)
	if h.keepAlive == 0 || h.keepAlive > below {
		h.keepAlive = below
	} else {
		h.wait = max(min(h.wait, held)-holdMargin, MinHold)
	}
	return h.wait, h.keepAlive
}

func (h *holding) limiter() *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.starts == nil {
		h.starts = rate.NewLimiter(rate.Every(holdEvery), holdBurst)
	}
	return h.starts
}

// keepAliveOf is the keep-alive a connection of the default client gets:
// none, or what a drop taught the box (holding.dropped).
func (h *holding) keepAliveOf() net.KeepAliveConfig {
	_, ka := h.current()
	if ka == 0 {
		return net.KeepAliveConfig{Enable: false}
	}
	return net.KeepAliveConfig{Enable: true, Idle: ka, Interval: ka, Count: 3}
}

// defaultTransport is the default client's: net/http's own, a TLS session
// cache so that a new connection resumes (RFC 8446 §2.2; no early data),
// and a dialer that sends keep-alive only as h says.
func defaultTransport(h *holding) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(0)}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout, KeepAliveConfig: h.keepAliveOf()}
		if !d.KeepAliveConfig.Enable {
			d.KeepAlive = -1
		}
		return d.DialContext(ctx, network, addr)
	}
	return t
}

// HoldResult is what one held list came to.
type HoldResult struct {
	// Changed reports that the box's list changed, or that the box must
	// receive to find out (its pass refused): a Receive follows.
	Changed bool
	// Dropped reports that the connection dropped before the hold ended;
	// Wait and KeepAlive are then what the box asks for from now on.
	Dropped         bool
	After           time.Duration // how long the request was held
	Wait, KeepAlive time.Duration
}

// heldFor is the context key of the bound on a held list's call, in place
// of requestTimeout (exchange).
type heldFor struct{}

// Hold holds the box's list for up to wait, or the box's own wait if that
// is shorter (DefaultHold, or what its drops taught it): the server answers
// once the box's first page changes, or at the wait with nothing new. It
// first waits its turn (one a minute on average), then holds the box's lock
// only to read its tag and its pass, never through the hold, so the box's
// other commands go on meanwhile.
//
// A box with no tag kept, one whose last list found mail, or whose pass the
// server refused, is Changed at once, for a Receive to settle. An error is a
// call that failed and that holding again may get past: a refusal no wait
// mends (a revocation, an answer out of its form) is one too, which a caller
// tells by its kind ([APIError], [RevokedError]).
func (b *Box) Hold(ctx context.Context, wait time.Duration) (*HoldResult, error) {
	if err := b.holding.limiter().Wait(ctx); err != nil {
		return nil, err
	}
	type kept struct{ pass, tag string }
	k, err := locked(ctx, b, func() (kept, error) {
		hdr, err := b.ifNoneMatch()
		if err != nil || hdr == nil {
			return kept{}, err
		}
		pass, err := b.pass()
		return kept{pass, hdr.Get("If-None-Match")}, err
	})
	if err != nil {
		return nil, err
	}
	if k.tag == "" {
		return &HoldResult{Changed: true}, nil
	}
	own, _ := b.holding.current()
	wait = min(wait, own)
	hdr := http.Header{"If-None-Match": {k.tag}, "Authorization": {k.pass}}
	path := b.boxPath("/messages") + "?wait=" + strconv.FormatInt(int64(wait/time.Second), 10)
	// How long the request was held is timed from the connection it got
	// last: net/http sends a GET again, once, on a new connection when a
	// reused one drops before its answer, and a drop is the connection's.
	var mu sync.Mutex
	start := time.Now()
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		start = time.Now()
	}}
	held := httptrace.WithClientTrace(context.WithValue(ctx, heldFor{}, wait+holdMargin), trace)
	var list protocol.MessageList
	resp, err := b.call(held, http.MethodGet, path, nil, hdr, &list)
	mu.Lock()
	after := time.Since(start)
	mu.Unlock()
	var te *transportError
	switch {
	case err == nil && resp.StatusCode == http.StatusNotModified && sameTag(resp.Header.Get("ETag"), k.tag):
		return &HoldResult{After: after}, nil
	case err == nil:
		return &HoldResult{Changed: true, After: after}, nil
	case passRefused(code(err)):
		return &HoldResult{Changed: true, After: after}, nil
	case ctx.Err() == nil && errors.As(err, &te) && after >= MinHold/2:
		// The connection dropped part way through a hold, or its answer
		// never came: a network that forgets a silent connection.
		b.http.CloseIdleConnections()
		w, ka := b.holding.dropped(after)
		return &HoldResult{Dropped: true, After: after, Wait: w, KeepAlive: ka}, nil
	case errors.As(err, &te):
		// No answer at all: the next connection is a new one.
		b.http.CloseIdleConnections()
	}
	return nil, err
}
