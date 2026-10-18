package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// maxResponse bounds what is read of any response. A message is far smaller;
// the bound only stops a server from filling memory.
const maxResponse = 16 << 20

// maxWaitSeconds bounds a wait a server asks for, the Retry-After of a refusal
// or of a list: a day, longer than any limit a server counts. A server may ask
// for less; a larger number is read as a day, and never overflows the pause
// it becomes.
const maxWaitSeconds = 24 * 60 * 60

// call makes one API request of this box's server. A request body is sent as
// JSON, or as it is when it is a message's ciphertext; a 2xx response body is
// read into out when out is not nil: as JSON, or as the ciphertext's bytes.
// A 304 to a request that carried If-None-Match is answered, with nothing
// read into out; one to a request that did not breaks its form. Any other
// status outside 2xx is an *APIError, a redirect among them, which no box
// follows ([followNone]). A server whose URL [checkServerURL] refuses is
// called not at all. It returns the response, whose body is
// consumed.
func (b *Box) call(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	return b.callAt(ctx, b.base, method, path, in, hdr, out)
}

// ciphertext is a message's ciphertext as the whole body of a send or of a
// fetch: the age file's exact bytes, never JSON (PROTOCOL.md §4.5, §5.2). As
// what a fetch reads into, size is the length its list gives, and a body of
// any other length is no answer.
type ciphertext struct {
	bytes []byte
	size  int64
}

// callAt is call, of the server at base: this box's own, or a revocation
// server, which is sent no pass.
func (b *Box) callAt(ctx context.Context, base, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	if err := checkServerURL(base); err != nil {
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
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read fully below
	if resp.StatusCode == http.StatusNotModified {
		// A 304 has no content (RFC 9110 §15.4.5), and answers only the
		// condition asked: one asked none is no answer.
		if req.Header.Get("If-None-Match") == "" {
			return resp, fmt.Errorf("%s %s: a 304 to a request that asked no condition", method, path)
		}
		return resp, nil
	}
	answered := resp.StatusCode >= 200 && resp.StatusCode <= 299
	ct, raw := out.(*ciphertext)
	limit := int64(maxResponse)
	if raw && answered {
		// A fetch reads no more than its list says the message holds, and a
		// byte past it to see that the body ends there.
		if ct.size < 0 || ct.size > maxResponse || resp.ContentLength >= 0 && resp.ContentLength != ct.size {
			return resp, notListed(method, path, ct.size)
		}
		limit = ct.size + 1
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if !answered {
		e := &APIError{Status: resp.StatusCode}
		// A body that is not problem+json, read as any answer is, leaves the
		// code empty: one that breaks a rule is no answer, so nothing it got as
		// far as is kept (PROTOCOL.md §0b). So does a code this client does
		// not know, one under a status that is not its own, or one beside a
		// type that is not its own (§13): no branch of this client is taken on
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
	switch {
	case raw:
		if int64(len(data)) != ct.size {
			return resp, notListed(method, path, ct.size)
		}
		ct.bytes = data
	case out != nil:
		if err := protocol.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s %s: the response is not the JSON expected: %w", method, path, err)
		}
	}
	return resp, nil
}

// notListed is a fetch whose body is not the size its list gave: an answer
// that breaks its form, as a list or a JSON answer that breaks one is no
// answer.
func notListed(method, path string, size int64) error {
	return fmt.Errorf("%s %s: the response is not the %d bytes of ciphertext the list gives", method, path, size)
}

// retryAfter is the wait a Retry-After asks for: its delay-seconds, written in
// digits alone, as a server writes them (PROTOCOL.md §13). Anything else, an
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
// (every 401, PROTOCOL.md §13), which a new pass may cure.
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
// the server no longer takes, the box signs another and tries once more.
func (b *Box) owner(ctx context.Context, method, path string, in, out any) (*http.Response, error) {
	return b.ownerWith(ctx, method, path, nil, in, out)
}

// ownerWith is owner, with the request's headers hdr beside the pass.
func (b *Box) ownerWith(ctx context.Context, method, path string, hdr http.Header, in, out any) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		pass, err := b.pass()
		if err != nil {
			return nil, err
		}
		h := hdr.Clone()
		if h == nil {
			h = http.Header{}
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

// lookup GETs box a from this box's server (GET /v1/<a>), with this box's
// pass, so the call is counted against this box and not against the address
// it comes from (PROTOCOL.md §4.1). What a box looks up about itself is asked
// without one, as is anything by a box that cannot sign a pass, as one
// restored from its identity before its first renewal: those are asked when
// the box's pass may be what is wrong.
func (b *Box) lookup(ctx context.Context, a protocol.Address, out any) (*http.Response, error) {
	path := "/v1/" + a.String()
	if a == b.id.Address() {
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	if _, err := b.pass(); err != nil {
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	resp, err := b.owner(ctx, http.MethodGet, path, nil, out)
	switch Code(err) {
	case protocol.CodeUnauthorized, protocol.CodePassExpired, protocol.CodeCertificateNotCurrent, protocol.CodeCertificateRevoked, protocol.CodeUnknownSender, protocol.CodeSenderRevoked:
		// What was refused is this box's pass, not the lookup: what is
		// public is asked again without it. A call that needs the pass
		// meets the same refusal, and that call says what it means.
		return b.call(ctx, http.MethodGet, path, nil, nil, out)
	}
	return resp, err
}
