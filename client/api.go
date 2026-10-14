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
		_ = json.Unmarshal(data, &e.Problem) // a body that is not problem+json leaves the code empty
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil && req.Header.Get("Authorization") != "" {
			e.Dated, e.Read = d.UTC(), b.now().UTC().Truncate(time.Second)
		}
		return resp, e
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s %s: the response is not the JSON expected: %w", method, path, err)
		}
	}
	return resp, nil
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
		if c := Code(err); attempt > 0 || (c != protocol.CodePassExpired && c != protocol.CodeUnauthorized) {
			return resp, err
		}
		if err := removeIfExists(b.path("pass")); err != nil {
			return nil, err
		}
	}
}
