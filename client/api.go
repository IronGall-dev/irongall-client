package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/drewstreib/crossbot-client/protocol"
)

// maxResponse bounds what is read of any response. A message is far smaller;
// the bound only stops a server from filling memory.
const maxResponse = 16 << 20

// call makes one API request. A request body is sent as JSON; a 2xx response
// body is decoded into out when out is not nil. Any status outside 2xx and
// 304 is an *APIError. It returns the response, whose body is consumed.
func (b *Box) call(ctx context.Context, method, path string, in any, hdr http.Header, out any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		j, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, body)
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
		return resp, e
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s %s: the response is not the JSON expected: %w", method, path, err)
		}
	}
	return resp, nil
}

// owner makes a request as the box's owner. On 401 token_stale it fetches the
// current token, decrypts it, and retries once. A refreshed token carried in a
// Crossbot-Token header is kept.
func (b *Box) owner(ctx context.Context, method, path string, hdr http.Header, out any) (*http.Response, error) {
	resp, err := b.ownerOnce(ctx, method, path, hdr, out)
	if Code(err) != protocol.CodeTokenStale {
		return resp, err
	}
	if err := b.RefreshToken(ctx); err != nil {
		return nil, err
	}
	return b.ownerOnce(ctx, method, path, hdr, out)
}

func (b *Box) ownerOnce(ctx context.Context, method, path string, hdr http.Header, out any) (*http.Response, error) {
	tok, err := os.ReadFile(b.path("token"))
	if err != nil {
		return nil, fmt.Errorf("no token: %w", err)
	}
	h := http.Header{}
	for k, v := range hdr {
		h[k] = v
	}
	h.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	resp, err := b.call(ctx, method, path, nil, h, out)
	if resp != nil {
		if v := resp.Header.Get(protocol.TokenHeader); v != "" {
			// A refresh that does not decrypt is ignored: the token_stale
			// rule still covers it.
			if ct, err := base64.StdEncoding.DecodeString(v); err == nil {
				_ = b.storeToken(ct)
			}
		}
	}
	return resp, err
}

// RefreshToken fetches the box's current owner token and keeps it. It is what
// a client does on 401 token_stale.
func (b *Box) RefreshToken(ctx context.Context) error {
	var tr protocol.TokenResponse
	if _, err := b.call(ctx, http.MethodPost, b.boxPath("/token"), nil, nil, &tr); err != nil {
		return err
	}
	return b.storeToken(tr.Token)
}
