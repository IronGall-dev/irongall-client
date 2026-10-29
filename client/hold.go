package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
//     drop, so the connection lives and the wait stays long. A drop the
//     box sees as it comes (a reset) names when the network forgot the
//     connection. One it sees only at its own deadline (a network that
//     drops silently) names only a bound above that, so keep-alive halves
//     at each such drop: a search for a bound no answer names, as path MTU
//     discovery's binary search halves its range at each failed probe
//     (RFC 4821 §7.3).
//   - The request. Each asks the server to hold it for the box's wait,
//     DefaultHold at first, and ends at that wait and a margin from the
//     connection it got last, whether answered or not: a dead path is found
//     there, never by a probe. Only a connection that drops with keep-alive
//     at its floor shortens the wait, never below MinHold: a path whose
//     probes keep nothing alive (an HTTP proxy's timeout, which TCP's
//     keep-alive does not reach). Holds start at most about once a minute
//     (holdEvery), so a connection that fails at once is a minute's poll,
//     within the poll budget (PROTOCOL.md §11.5).

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

// minKeepAlive is the shortest keep-alive a box's connections get, however
// they drop.
const minKeepAlive = MinHold / 2

// dropped records a connection that dropped after held. One seen as it
// dropped gives the next connection keep-alive below held; one seen only at
// the hold's own deadline (silent) dropped at some time within the wait, so
// keep-alive halves, from the wait at first. Once keep-alive is at its
// floor, a drop shortens the wait instead: below held, or for a silent one
// to half of it. It returns what the box asks for and sets from now on.
func (h *holding) dropped(held time.Duration, silent bool) (wait, keepAlive time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wait == 0 {
		h.wait = DefaultHold
	}
	below := held - holdMargin
	if silent {
		below = h.keepAlive
		if below == 0 {
			below = min(h.wait, held)
		}
		below = (below / 2).Truncate(time.Second)
	}
	below = max(below, minKeepAlive)
	switch {
	case h.keepAlive == 0 || h.keepAlive > below:
		h.keepAlive = below
	case silent:
		h.wait = max((h.wait / 2).Truncate(time.Second), MinHold)
	default:
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
// none, or what the box's drops taught it (holding.dropped).
func (h *holding) keepAliveOf() net.KeepAliveConfig {
	_, ka := h.current()
	if ka == 0 {
		return net.KeepAliveConfig{Enable: false}
	}
	return net.KeepAliveConfig{Enable: true, Idle: ka, Interval: ka, Count: 3}
}

// dialer is what makes a connection of the default client: keep-alive as
// keepAliveOf says, and otherwise none, where net's default sends it.
func (h *holding) dialer() *net.Dialer {
	d := &net.Dialer{Timeout: dialTimeout, KeepAliveConfig: h.keepAliveOf()}
	if !d.KeepAliveConfig.Enable {
		d.KeepAlive = -1
	}
	return d
}

// defaultTransport is the default client's: net/http's own, a TLS session
// cache so that a new connection resumes (RFC 8446 §2.2; no early data),
// and a dialer that sends keep-alive only as h says.
func defaultTransport(h *holding) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(0)}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return h.dialer().DialContext(ctx, network, addr)
	}
	return t
}

// HoldResult is what one held list came to.
type HoldResult struct {
	// Changed reports that the box's list changed, or that the box must
	// receive to find out (its pass refused): a Receive follows.
	Changed bool
	// Dropped reports that a connection of the hold dropped: before the
	// hold's answer, seen as it dropped or only at the hold's deadline, or
	// on a reused connection that net/http sent the request again past,
	// which the hold's answer then follows. Wait and KeepAlive are then what
	// the box asks for from now on.
	Dropped bool
	// After is how long the request was held on the connection it got
	// last.
	After           time.Duration
	Wait, KeepAlive time.Duration
}

// heldFor is the context key of the bound on a held list's call, in place
// of requestTimeout (exchange, heldBound).
type heldFor struct{}

// errHeldOut is a held list's call cut at its bound, unanswered.
var errHeldOut = fmt.Errorf("no answer within the wait: %w", context.DeadlineExceeded)

// heldBound is ctx, cut with errHeldOut once d passes from the connection
// its request got last: net/http sends a GET again, once, on a new
// connection when a reused one drops before its answer, and that request's
// bound is its own.
func heldBound(ctx context.Context, d time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	t := time.AfterFunc(d, func() { cancel(errHeldOut) })
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { t.Reset(d) }})
	return ctx, func() {
		t.Stop()
		cancel(nil)
	}
}

// timedOut reports whether err is a call cut by a bound on its time, with
// no answer: a drop the box did not see as it came.
func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

// Transient reports whether err is a call that failed and that making it
// again may get past: no answer, a server error, a rate limit or a request
// timeout. A refusal no wait mends, a revocation or an answer out of its
// form, is not.
func Transient(err error) bool {
	var ae *APIError
	var re *RevokedError
	switch {
	case err == nil, errors.As(err, &re):
		return false
	case errors.As(err, &ae):
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests || ae.Status == http.StatusRequestTimeout
	}
	var te *transportError
	return errors.As(err, &te)
}

// turn waits for the box's turn to start a hold, one a minute on average,
// for up to wait: false is a turn later than that, whose wait it has waited
// out instead.
func (h *holding) turn(ctx context.Context, wait time.Duration) (bool, error) {
	r := h.limiter().Reserve()
	d := r.Delay()
	if d >= wait {
		r.Cancel()
		d = max(wait, 0)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		r.Cancel()
		return false, ctx.Err()
	case <-t.C:
	}
	return d < wait, nil
}

// Hold holds the box's list for up to wait, or the box's own wait if that
// is shorter (DefaultHold, or what its drops taught it): the server answers
// once the box's first page changes, or at the wait with nothing new. It
// first waits its turn (one a minute on average), and where the turn comes
// past the wait, it waits the wait out and holds nothing. It then holds the
// box's lock only to read its tag and its pass, never through the hold, so
// the box's other commands go on meanwhile. The held request reads nothing
// of the box's state: an answer about a revocation is proved under the lock
// once it comes (provedLocked).
//
// A box with no tag kept, one whose last list found mail, or whose pass the
// server refused, is Changed at once, for a Receive to settle. An error is a
// call that failed and that holding again may get past ([Transient]): a
// refusal no wait mends (a revocation, an answer out of its form) is one
// too, which a caller tells by its kind ([APIError], [RevokedError]).
func (b *Box) Hold(ctx context.Context, wait time.Duration) (*HoldResult, error) {
	own, _ := b.holding.current()
	wait = min(wait, own)
	if ok, err := b.holding.turn(ctx, wait); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return &HoldResult{}, nil
	}
	type kept struct{ pass, tag, path string }
	k, err := locked(ctx, b, func() (kept, error) {
		hdr, err := b.ifNoneMatch()
		if err != nil || hdr == nil {
			return kept{}, err
		}
		pass, err := b.pass()
		return kept{pass, hdr.Get("If-None-Match"), b.boxPath("/messages")}, err
	})
	if err != nil {
		return nil, err
	}
	if k.tag == "" {
		return &HoldResult{Changed: true}, nil
	}
	hdr := http.Header{"If-None-Match": {k.tag}, "Authorization": {k.pass}}
	path := k.path + "?wait=" + strconv.FormatInt(int64(wait/time.Second), 10)
	// How long the request was held is timed from the connection it got
	// last: net/http sends a GET again, once, on a new connection when a
	// reused one drops before its answer, and a drop is the connection's.
	// A connection asked for after one was got is asked for past a drop,
	// seen as it came; it is learned then, before the next is dialled.
	h := &HoldResult{}
	var mu sync.Mutex
	var got bool
	start := time.Now()
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			mu.Lock()
			defer mu.Unlock()
			if lived := time.Since(start); got && lived >= MinHold/2 {
				h.Dropped = true
				h.Wait, h.KeepAlive = b.holding.dropped(lived, false)
			}
		},
		GotConn: func(httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			got, start = true, time.Now()
		},
	}
	held := httptrace.WithClientTrace(context.WithValue(ctx, heldFor{}, wait+holdMargin), trace)
	var list protocol.MessageList
	resp, err := b.exchange(held, http.MethodGet, path, nil, hdr, &list)
	mu.Lock()
	after := time.Since(start)
	h.After = after
	mu.Unlock()
	err = b.provedLocked(ctx, http.MethodGet, path, err)
	var te *transportError
	switch {
	case err == nil && resp.StatusCode == http.StatusNotModified && sameTag(resp.Header.Get("ETag"), k.tag):
	case err == nil, passRefused(code(err)):
		h.Changed = true
	case ctx.Err() == nil && errors.As(err, &te) && after >= MinHold/2:
		// The connection dropped part way through a hold, or its answer
		// never came: a network that forgets a silent connection.
		b.http.CloseIdleConnections()
		h.Dropped = true
		h.Wait, h.KeepAlive = b.holding.dropped(after, timedOut(err))
	case errors.As(err, &te):
		// No answer at all: the next connection is a new one.
		b.http.CloseIdleConnections()
		return nil, err
	default:
		return nil, err
	}
	return h, nil
}

// ReceiveEvery is the longest Await holds before it returns for a Receive,
// which renews the prekey when it is due.
const ReceiveEvery = time.Hour

// Await holds the box's list, one held request after another (Hold), until
// it changes, until passes or ReceiveEvery has, and returns for a Receive;
// a zero until is no deadline, as for a box that waits for mail for as long
// as it runs. A call that holding again may get past (no answer, a server
// error, a rate limit) is held again, after its Retry-After where it gives
// one; a refusal no wait mends ends it, as its error. say, when not nil, is
// told of each: a held request that failed, with its error, and a
// connection that dropped, with its HoldResult. Await returns by until, its
// waits for a turn to hold included (Hold).
//
// With under a second left Await waits it out, so the Receive after is the
// caller's last, never one of a burst of polls until the deadline passes.
func (b *Box) Await(ctx context.Context, until time.Time, say func(*HoldResult, error)) error {
	if say == nil {
		say = func(*HoldResult, error) {}
	}
	if every := time.Now().Add(ReceiveEvery); until.IsZero() || every.Before(until) {
		until = every
	}
	for time.Until(until) >= time.Second {
		h, err := b.Hold(ctx, time.Until(until))
		var ae *APIError
		var re *RevokedError
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.As(err, &re), errors.As(err, &ae) && !Transient(err):
			return err
		case err != nil:
			say(nil, err)
			if ae != nil && ae.RetryAfter > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(min(ae.RetryAfter, time.Until(until))):
				}
			}
			continue
		}
		if h.Dropped {
			say(h, nil)
		}
		if h.Changed {
			return nil
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Until(until)):
	}
	return nil
}
