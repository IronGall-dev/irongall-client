package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tk "github.com/dromas-dev/dromas-client/client/internal/taken"
	"github.com/dromas-dev/dromas-client/protocol"
)

// maxResponse bounds what is read of any answer but a fetch's: a list, the
// read of a box, a problem. It is this client's own, which the protocol does
// not fix, and only stops a server from filling memory. A fetch is bounded by
// the protocol's largest ciphertext instead (protocol.MaxCiphertext), which
// every reader takes, so that this bound moves without changing which mail a
// box reads.
const maxResponse = 16 << 20

// maxReceipt bounds what is read of a post's answer once the server took it,
// a receipt: its three members are some 130 bytes, and this leaves room for
// members a later version adds (PROTOCOL.md §14). It is this client's own,
// as maxResponse is. A refusal is read as any answer is.
const maxReceipt = 4 << 10

// maxWaitSeconds bounds a wait a server asks for, the Retry-After of a refusal
// or of a list: a day, longer than any limit a server counts. A server may ask
// for less; a larger number is read as a day, and never overflows the pause
// it becomes.
const maxWaitSeconds = 24 * 60 * 60

// ciphertext is a message's ciphertext as the whole body of a send or of a
// fetch: the age file's exact bytes, never JSON (PROTOCOL.md §11.10, §11.12). As
// what a fetch reads into, size is the length its list gives, and a body of
// any other length is no answer; keep is the partial it reads through, which
// holds what an earlier attempt kept and keeps what this one reads
// (partial.go).
type ciphertext struct {
	bytes []byte
	size  int64
	keep  *partial
}

// call makes one API request of this box's server. A request body is sent as
// JSON, or as it is when it is a message's ciphertext; a 2xx response body is
// read into out when out is not nil: as JSON, or as the ciphertext's bytes.
// A 304 to a request that carried If-None-Match is answered, with nothing
// read into out; one to a request that did not breaks its form. Any other
// status outside 2xx is an *APIError, a redirect among them, which no box
// follows ([followNone]). A call that got no answer it could read is a
// [transportError], in this client's words. A server whose URL
// [checkServerURL] refuses is called not at all. It returns the response,
// whose body is consumed.
//
// Every answer passes here, so what one says of a revocation is proved here
// and nowhere else (proved): a caller meets a [RevokedError] that verified,
// or the call's error. A command that has kept its box's own revocation asks
// nothing more: each call of it after that returns the revocation before any
// request is made.
func (b *Box) call(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	if b.ended != nil {
		return nil, b.ended
	}
	resp, err := b.exchange(ctx, method, path, in, hdr, out)
	return resp, b.proved(ctx, method, path, err)
}

// exchange is call's request and its answer, as the server gave it.
func (b *Box) exchange(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	if err := checkServerURL(b.base); err != nil {
		return nil, err
	}
	var body io.Reader
	contentType := ""
	switch v := in.(type) {
	case nil:
	case *ciphertext:
		body, contentType = bytes.NewReader(v.bytes), protocol.CiphertextContentType
	default:
		j, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body, contentType = bytes.NewReader(j), "application/json"
	}
	_, rawIn := in.(*ciphertext)
	ct, raw := out.(*ciphertext)
	// The default client bounds a call by requestTimeout: a ciphertext's
	// bytes, sent or fetched, by their stalls alone, so one of any size moves
	// on a slow link that keeps moving, and the rest of that call, and any
	// other call, whole (stall).
	var cut *stall
	if b.stall {
		if rawIn || raw {
			ctx, cut = newStall(ctx)
			defer cut.stop()
		} else {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, requestTimeout)
			defer cancel()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, body)
	if err != nil {
		return nil, err
	}
	cut.sending(req)
	for k, v := range hdr {
		req.Header[k] = v
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// An error names the call by its method and its path, never its query,
	// which can carry the server's own text: a list's cursor (PROTOCOL.md
	// §11.3).
	name, _, _ := strings.Cut(path, "?")
	name = method + " " + name
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, noAnswer(name, "no answer that is HTTP", cut.why(err))
	}
	answered := resp.StatusCode >= 200 && resp.StatusCode <= 299
	if raw && answered {
		resp.Body = cut.reading(resp.Body)
	} else {
		// Any answer but a fetched ciphertext, a post's among them.
		cut.answering()
	}
	defer resp.Body.Close() //nolint:errcheck // read fully below
	if resp.StatusCode == http.StatusNotModified {
		// A 304 has no content (RFC 9110 §15.4.5), and answers only the
		// condition asked: one asked none is no answer.
		if req.Header.Get("If-None-Match") == "" {
			return resp, fmt.Errorf("%s: a 304 to a request that asked no condition", name)
		}
		return resp, nil
	}
	if raw && answered {
		readErr, err := ct.read(name, resp)
		if readErr != nil {
			return nil, noAnswer(name, "an answer whose body could not be read", cut.why(readErr))
		}
		return resp, err
	}
	limit := int64(maxResponse)
	if rawIn && answered {
		limit = maxReceipt
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, noAnswer(name, "an answer whose body could not be read", cut.why(err))
	}
	if !answered {
		e := &APIError{Status: resp.StatusCode}
		// A body that is not problem+json, read as any answer is, leaves the
		// code empty: one that breaks a rule is no answer, so nothing it got as
		// far as is kept (PROTOCOL.md §3.3). So does a code this client does
		// not know, one under a status that is not its own, or one beside a
		// type that is not its own (§11.3): no branch of this client is taken on
		// it, and nothing of it is shown.
		var p protocol.Problem
		if protocol.Unmarshal(data, &p) == nil && p.CodeAt(resp.StatusCode) != "" {
			e.Problem = p
		}
		e.RetryAfter = retryAfter(resp.Header.Get("Retry-After"))
		if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil && req.Header.Get("Authorization") != "" {
			e.Dated, e.Read = d.UTC(), b.now().UTC().Truncate(time.Second)
		}
		return resp, e
	}
	if out != nil {
		if err := protocol.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s: the response is not the JSON expected: %w", name, err)
		}
	}
	return resp, nil
}

// stall cuts a call of the default client that sends or fetches a
// ciphertext once requestTimeout passes with none of the ciphertext's bytes
// moving: before its answer's head, the wait from the last byte it sent, and
// in a fetched ciphertext, the wait for the next byte, as curl's
// --speed-time does with a limit of one byte. Nothing bounds those bytes
// whole, so a ciphertext of any size moves on a link that keeps moving it
// (#381). The rest of the call is not the ciphertext, and is bounded whole,
// by requestTimeout from where it begins (answering): a post's answer, from
// when its body is sent or its answer's head comes, whichever is first, and
// a fetch's answer that is not its ciphertext, from its head (#403 item 3).
// It reads the monotonic clock alone: when a byte last moved is kept as an
// offset from its start, so a step of the wall clock while a call is in
// flight moves no bound (#403 item 4). A nil stall cuts nothing: a client
// the box was given keeps its own timeouts.
type stall struct {
	cancel  context.CancelCauseFunc
	ctx     context.Context
	base    time.Time    // when the stall began, with its monotonic reading
	last    atomic.Int64 // when a byte last moved, in nanoseconds after base
	mu      sync.Mutex   // holds timer, which check may read before newStall has set it, whole and stopped
	timer   *time.Timer
	whole   bool // the rest of the call is bounded whole (answering)
	stopped bool
}

// errStalled is a call stall cut: no byte of its ciphertext moved in
// requestTimeout.
var errStalled = fmt.Errorf("no byte moved for as long as a call waits: %w", context.DeadlineExceeded)

// errUnanswered is a call stall cut once the rest of it, its answer, ran
// requestTimeout.
var errUnanswered = fmt.Errorf("no answer in as long as a call waits: %w", context.DeadlineExceeded)

// newStall is ctx, cut once requestTimeout passes with no byte moving.
func newStall(ctx context.Context) (context.Context, *stall) {
	s := &stall{base: time.Now()}
	s.ctx, s.cancel = context.WithCancelCause(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timer = time.AfterFunc(requestTimeout, s.check)
	return s.ctx, s
}

// moved records that a byte of the ciphertext moved, now.
func (s *stall) moved() { s.last.Store(int64(time.Since(s.base))) }

// check cuts the call when no byte has moved for requestTimeout, and
// otherwise looks again when that much will have passed since the last.
func (s *stall) check() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.whole {
		return
	}
	idle := time.Since(s.base) - time.Duration(s.last.Load())
	if idle >= requestTimeout {
		s.cancel(errStalled)
		return
	}
	s.timer.Reset(requestTimeout - idle)
}

// answering bounds the rest of the call whole, by requestTimeout from now,
// and ends the watch of its bytes: no byte of an answer that is not a
// ciphertext holds a call open by moving. Only its first call counts.
func (s *stall) answering() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.whole {
		return
	}
	s.whole = true
	s.timer.Stop()
	s.timer = time.AfterFunc(requestTimeout, func() { s.cancel(errUnanswered) })
}

// stop ends the stall's watch, once its call has returned.
func (s *stall) stop() {
	s.mu.Lock()
	s.stopped = true
	s.timer.Stop()
	s.mu.Unlock()
	s.cancel(nil)
}

// why is err, or the stall's cause where the stall cut the call: net/http
// reports it as the context canceled, which is not what happened.
func (s *stall) why(err error) error {
	if s == nil {
		return err
	}
	if cause := context.Cause(s.ctx); errors.Is(cause, errStalled) || errors.Is(cause, errUnanswered) {
		return cause
	}
	return err
}

// sending has each byte of req's body that is read to be sent count as one
// that moved, and the end of it bound the rest of the call whole.
func (s *stall) sending(req *http.Request) {
	if s == nil || req.Body == nil || req.Body == http.NoBody {
		return
	}
	req.Body = sent{s.reading(req.Body), s}
	if get := req.GetBody; get != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			b, err := get()
			if err != nil {
				return nil, err
			}
			return sent{s.reading(b), s}, nil
		}
	}
}

// reading is r, each byte read of it counted as one that moved.
func (s *stall) reading(r io.ReadCloser) io.ReadCloser {
	if s == nil {
		return r
	}
	return moving{r, s}
}

// moving is a body whose every read that gets a byte is a byte that moved.
type moving struct {
	io.ReadCloser
	s *stall
}

func (m moving) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	if n > 0 {
		m.s.moved()
	}
	return n, err
}

// sent is a request's body whose end, read to be sent, bounds the rest of
// its call whole: the wait for its answer.
type sent struct {
	io.ReadCloser
	s *stall
}

func (b sent) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.s.answering()
	}
	return n, err
}

// notListed is a fetch whose body is not the size its list gave: an answer
// that breaks its form, as a list or a JSON answer that breaks one is no
// answer.
func notListed(call string, size int64) error {
	return fmt.Errorf("%s: the response is not the %d bytes of ciphertext the list gives", call, size)
}

// transportError is a call that got no answer it could read, in this
// client's own words: the call, and what kind of failure it was. net/http's
// error quotes what the server sent (a status line, a header or trailer
// line, a Location, the names in its certificate), and a server's words are
// never printed (PROTOCOL.md §11.3), so that error is kept for errors.Is and
// errors.As and is no part of Error.
type transportError struct {
	call, kind string
	cause      error
}

func (e *transportError) Error() string { return e.call + ": " + e.kind }
func (e *transportError) Unwrap() error { return e.cause }

// noAnswer is err, net/http's, as a transportError: the kind its cause
// shows, or otherwise the kind given.
func noAnswer(call, otherwise string, err error) error {
	var timeout net.Error
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	kind := otherwise
	switch {
	case errors.Is(err, context.Canceled):
		kind = "stopped before an answer came"
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout():
		kind = "no answer within the wait"
	case errors.As(err, &certificate):
		kind = "the server's TLS certificate does not verify"
	case errors.As(err, &record) || hasOp(err, "remote error", "local error"):
		// A record that is not TLS, or an alert, the server's or this
		// client's own, which crypto/tls reports as a remote or a local
		// error (#299).
		kind = "TLS failed"
	case hasOp(err, "dial"):
		// Through a proxy too, where net/http wraps the dial's error in a
		// proxyconnect one (#299).
		kind = "could not connect"
	}
	return &transportError{call: call, kind: kind, cause: err}
}

// hasOp reports whether a *net.OpError of one of ops is anywhere in err's
// chain, not only the first one errors.As finds.
func hasOp(err error, ops ...string) bool {
	for err != nil {
		var op *net.OpError
		if !errors.As(err, &op) {
			return false
		}
		if slices.Contains(ops, op.Op) {
			return true
		}
		err = op.Err
	}
	return false
}

// retryAfter is the wait a Retry-After asks for: its delay-seconds, written in
// digits alone, as a server writes them (PROTOCOL.md §11.3). Anything else, an
// HTTP-date among them, asks for none. More than maxWaitSeconds is read as
// that, and never overflows the pause it becomes.
func retryAfter(v string) time.Duration {
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		n = maxWaitSeconds // more digits than any wait
	}
	return time.Duration(min(n, maxWaitSeconds)) * time.Second
}

// passRefused reports whether c is a server refusing the pass a call carried
// (every 401, PROTOCOL.md §11.3), which a new pass may cure.
func passRefused(c protocol.Code) bool {
	switch c {
	case protocol.CodeUnauthorized, protocol.CodePassExpired, protocol.CodeCertificateNotCurrent, protocol.CodeCertificateRevoked:
		return true
	}
	return false
}

// owner makes a request as this box, with in as its body when not nil (call):
// a call that carries the box's pass. If the server refuses the pass, because
// it ran out sooner by the server's clock or was signed under a certificate
// the server no longer takes, the box signs another and tries once more. A
// pass under a certificate that is not the box's current one at the server
// has the box read itself there first (known), which records a renewal the
// server took whose answer the box never had.
func (b *Box) owner(ctx context.Context, method, path string, in, out any) (*http.Response, error) {
	return b.ownerWith(ctx, method, path, nil, in, out)
}

// ownerWith is owner, with the request's headers hdr beside the pass.
func (b *Box) ownerWith(ctx context.Context, method, path string, hdr http.Header, in, out any) (*http.Response, error) {
	resp, _, err := b.ownerTaken(ctx, method, path, hdr, in, out)
	return resp, err
}

// ownerTaken is ownerWith, and, once the server has answered, the reading
// of this box's clock it took: the date of the pass the answered call
// carried.
func (b *Box) ownerTaken(ctx context.Context, method, path string, hdr http.Header, in, out any) (*http.Response, taken, error) {
	for attempt := 0; ; attempt++ {
		pass, err := b.pass()
		if err != nil {
			return nil, taken{}, err
		}
		h := hdr.Clone()
		if h == nil {
			h = http.Header{}
		}
		h.Set("Authorization", pass)
		resp, err := b.call(ctx, method, path, in, h, out)
		if attempt > 0 || !passRefused(code(err)) {
			if err != nil {
				return resp, taken{}, err
			}
			at, err := tk.By(pass)
			return resp, at, err
		}
		if code(err) == protocol.CodeCertificateNotCurrent {
			if _, err := b.known(ctx); err != nil {
				return nil, taken{}, err
			}
		}
		if err := b.dropPass(); err != nil {
			return nil, taken{}, err
		}
	}
}

// taken is a reading of this box's clock that a server took, which every
// deletion by the clock is by: a pass is the only way to one
// (client/internal/taken).
type taken = tk.Reading

// lookup GETs box a from this box's server (GET /v1/<a>), with no pass: the
// read is public, and a server reads no pass on it (PROTOCOL.md §11.8).
func (b *Box) lookup(ctx context.Context, a protocol.Address, out any) (*http.Response, error) {
	return b.call(ctx, http.MethodGet, "/v1/"+a.String(), nil, nil, out)
}
