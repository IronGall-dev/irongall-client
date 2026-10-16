package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// maxResponse bounds what is read of any response. A message is far smaller;
// the bound only stops a server from filling memory.
const maxResponse = 16 << 20

// maxWaitSeconds bounds a wait a server asks for, its Retry-After or a list's
// poll_after: a day, longer than any limit a server counts. A server may ask
// for less; a larger number is read as a day, and never overflows the pause
// it becomes.
const maxWaitSeconds = 24 * 60 * 60

// call makes one API request of this box's server. A request body is sent as
// JSON; a 2xx response body is decoded into out when out is not nil. Any
// status outside 2xx and 304 is an *APIError. It returns the response, whose
// body is consumed.
func (b *Box) call(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	return b.callAt(ctx, b.base, method, path, in, hdr, out)
}

// callAt is call, of the server at base: this box's own, or a revocation
// server, which is sent no pass.
func (b *Box) callAt(ctx context.Context, base, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		j, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read fully below
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &APIError{Status: resp.StatusCode}
		// A body that is not problem+json, read as any answer is, leaves the
		// code empty: one that breaks a rule is no answer, so nothing it got as
		// far as is kept (PROTOCOL.md §0b). So does a code this client does
		// not know, or one under a status that is not its own (§13): no
		// branch of this client is taken on it, and nothing of it is shown.
		var p protocol.Problem
		if protocol.Unmarshal(data, &p) == nil && p.Code.Known() && p.Code.Status() == resp.StatusCode {
			e.Problem = p
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(min(s, maxWaitSeconds)) * time.Second
		}
		if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil && req.Header.Get("Authorization") != "" {
			e.Dated, e.Read = d.UTC(), b.now().UTC().Truncate(time.Second)
		}
		return resp, e
	}
	if out != nil {
		if err := protocol.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s %s: the response is not the JSON expected: %w", method, path, err)
		}
	}
	return resp, nil
}

// passRefused reports whether c is a server refusing the pass a call carried
// (every 401, PROTOCOL.md §13), which a new pass may cure.
func passRefused(c protocol.Code) bool {
	switch c {
	case protocol.CodeUnauthorized, protocol.CodePassExpired, protocol.CodeCertificateNotCurrent, protocol.CodeCertificateRevoked:
		return true
	}
	return false
}

// owner makes a request as this box, with in as its JSON body when not nil:
// a call that carries the box's pass. If the server refuses the pass, because
// it ran out sooner by the server's clock or was signed under a certificate
// the server no longer takes, the box signs another and tries once more.
func (b *Box) owner(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		pass, err := b.pass()
		if err != nil {
			return nil, err
		}
		h := http.Header{}
		for k, v := range hdr {
			h[k] = v
		}
		h.Set("Authorization", pass)
		resp, err := b.call(ctx, method, path, in, h, out)
		if attempt > 0 || !passRefused(Code(err)) {
			return resp, err
		}
		if err := removeIfExists(b.path("pass")); err != nil {
			return nil, err
		}
	}
}

// lookup GETs what this box's server serves about box a (suffix is
// "/identity" or "/revocations"), with this box's pass, so the call is counted
// against this box and not against the address it comes from (PROTOCOL.md
// §4.1). What a box looks up about itself is asked without one, as is
// anything by a box that cannot sign a pass, as one restored from its
// identity before its first renewal: those are asked when the box's pass may
// be what is wrong.
func (b *Box) lookup(ctx context.Context, a protocol.Address, suffix string, out any) (*http.Response, error) {
	path := "/v1/" + a.String() + suffix
	if a == b.id.Address() {
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	if _, err := b.pass(); err != nil {
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	resp, err := b.owner(ctx, http.MethodGet, path, nil, nil, out)
	switch Code(err) {
	case protocol.CodeUnauthorized, protocol.CodePassExpired, protocol.CodeCertificateNotCurrent, protocol.CodeCertificateRevoked, protocol.CodeUnknownSender, protocol.CodeSenderRevoked:
		// What was refused is this box's pass, not the lookup: what is
		// public is asked again without it. A call that needs the pass
		// meets the same refusal, and that call says what it means.
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	return resp, err
}
