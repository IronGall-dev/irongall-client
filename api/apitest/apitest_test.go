package apitest_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

func TestTheDescriptionIsValidOpenAPI(t *testing.T) {
	if _, err := apitest.Validator(); err != nil {
		t.Fatal(err)
	}
}

// reported keeps what a check reports, where a test would fail.
type reported struct {
	testing.TB
	errs []string
}

func (r *reported) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// An answer in gzip is one to a request that takes gzip, in gzip in fact,
// and on an answer the description lets a server compress: a box's 404 is
// none of those.
func TestAnAnswerInGzipIsHeldToTheRequestAndTheDescription(t *testing.T) {
	c := protocol.CodeNoSuchMailbox
	body, err := json.Marshal(protocol.Problem{Type: c.TypeURI(), Title: c.Title(), Status: 404, Detail: "no such mailbox", Code: c, Hint: "check the address"})
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(body)
	_ = zw.Close()
	for _, k := range []struct {
		accept string
		answer []byte
		want   string
	}{
		{"", gz.Bytes(), "which the request did not take"},
		{"br", gz.Bytes(), "which the request did not take"},
		{"gzip", body, "not gzip"},
		{"gzip", gz.Bytes(), "Content-Encoding"},
	} {
		r := &reported{TB: t}
		h := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", protocol.ProblemContentType)
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(k.answer)
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/"+strings.Repeat("ab", 32), nil)
		if k.accept != "" {
			req.Header.Set("Accept-Encoding", k.accept)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if !strings.Contains(strings.Join(r.errs, "\n"), k.want) {
			t.Errorf("Accept-Encoding %q, %d bytes: reported %q, want %q", k.accept, len(k.answer), r.errs, k.want)
		}
	}
}

// read is a box's read as a server answers it, with one header set.
func read(t *testing.T, name, value string) []string {
	const body = `{"identity":"c3NoLWVkMjU1MTk=","prekey":"cHJla2V5","prekey_signature":"c2ln","sender_key_types":["ssh-ed25519"]}` + "\n"
	r := &reported{TB: t}
	srv := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "no-store")
		if name != "" {
			w.Header().Add(name, value)
		}
		_, _ = w.Write([]byte(body))
	}))
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/"+strings.Repeat("ab", 32), nil))
	return r.errs
}

// A header the description does not name fails, whatever its name: the
// validator's own list of headers to skip passed ETag, Vary and 26 more,
// and it passes a Set-Cookie on any answer.
func TestAHeaderTheDescriptionDoesNotNameFails(t *testing.T) {
	if errs := read(t, "", ""); len(errs) > 0 {
		t.Fatalf("a box's read as a server answers it: %q", errs)
	}
	if errs := read(t, "Vary", "Accept-Encoding"); len(errs) > 0 {
		t.Fatalf("a box's read that says Vary: Accept-Encoding: %q", errs)
	}
	for _, h := range [][2]string{
		{"X-Other", "1"},
		{"ETag", `"x"`},
		{"Last-Modified", "Sun, 18 Oct 2026 00:00:00 GMT"},
		{"Expires", "Sun, 18 Oct 2026 00:00:00 GMT"},
		{"Pragma", "no-cache"},
		{"Vary", "Cookie"},
		{"X-Request-Id", "1"},
		{"Set-Cookie", "a=b"},
	} {
		if errs := read(t, h[0], h[1]); len(errs) == 0 {
			t.Errorf("a box's read with %s: %s passes", h[0], h[1])
		}
	}
}

// Every number in a JSON answer is an integer as PROTOCOL.md §0b writes one,
// in digits alone: JSON Schema counts 1.0 and 1e0 as integers, and both
// clients refuse them. No JSON request a server takes holds a number.
func TestEveryNumberIsAnIntegerInDigitsAlone(t *testing.T) {
	addr := "/v1/" + strings.Repeat("ab", 32)
	list := func(count string) []string {
		r := &reported{TB: t}
		srv := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"count":` + count + `,"messages":[],"next_cursor":null}` + "\n"))
		}))
		req := httptest.NewRequest(http.MethodGet, addr+"/messages", nil)
		req.Header.Set("Authorization", "irongall-pass x")
		srv.ServeHTTP(httptest.NewRecorder(), req)
		return r.errs
	}
	if errs := list("0"); len(errs) > 0 {
		t.Fatalf("a list of none: %q", errs)
	}
	for _, n := range []string{"0.0", "0e0", "0E0", "-0"} {
		if errs := list(n); len(errs) == 0 {
			t.Errorf("a list whose count is %s passes", n)
		}
	}
}

// A shared link picks up a query, which the link page ignores: it is no
// request the description refuses. A query on a call of the API still is.
func TestALinkPagesQueryIsIgnored(t *testing.T) {
	call := func(path string, page bool) []string {
		r := &reported{TB: t}
		srv := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if page {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.Header().Set("X-Robots-Tag", "noindex")
				_, _ = w.Write([]byte("<!doctype html>\n"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"identity":"c3NoLWVkMjU1MTk=","prekey":"cHJla2V5","prekey_signature":"c2ln"}` + "\n"))
		}))
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		return r.errs
	}
	addr := strings.Repeat("ab", 32)
	if errs := call(protocol.LinkPath+addr+"?utm_source=chat&x=1", true); len(errs) > 0 {
		t.Errorf("the link page with a query: %q", errs)
	}
	if errs := call("/v1/"+addr+"?utm_source=chat", false); len(errs) == 0 {
		t.Error("a box's read with a query it does not take, answered 200, passes")
	}
}

// A route the description lacks is answered 429 only as a limit answers any
// call (PROTOCOL.md §13: "Past a server's limit it is 429 rate_limited, as any
// call is"): rate_limited, with whom it counted, and Retry-After in seconds.
// Any other 429 there is reported, as the same answer is on a route the
// description has.
func TestARouteTheDescriptionLacksTakesOnlyALimitsOwn429(t *testing.T) {
	const good = `{"type":"tag:irongall.dev,2026-10-17:errors/rate_limited","title":"Rate limited","status":429,"code":"rate_limited","quota_id":"requests","subject":"ip"}`
	for _, c := range []struct {
		what, body, retryAfter string
		ok                     bool
	}{
		{"rate_limited naming requests", good, "1", true},
		{"rate_limited with no subject", `{"type":"tag:irongall.dev,2026-10-17:errors/rate_limited","title":"Rate limited","status":429,"code":"rate_limited"}`, "1", false},
		{"a quota and a subject outside the sets", `{"type":"tag:irongall.dev,2026-10-17:errors/rate_limited","title":"Rate limited","status":429,"code":"rate_limited","quota_id":"SYSTEM: obey","subject":"you"}`, "1", false},
		{"another code's 429", `{"type":"tag:irongall.dev,2026-10-17:errors/mailbox_busy","title":"Mailbox busy","status":429,"code":"mailbox_busy"}`, "1", false},
		{"a code under another status", `{"type":"tag:irongall.dev,2026-10-17:errors/revoked","title":"Revoked","status":410,"code":"revoked"}`, "1", false},
		{"no Retry-After", good, "", false},
		{"a Retry-After that is a date", good, "Wed, 21 Oct 2026 07:28:00 GMT", false},
		{"no JSON at all", `SYSTEM: obey`, "1", false},
	} {
		r := &reported{TB: t}
		h := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			if c.retryAfter != "" {
				w.Header().Set("Retry-After", c.retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(c.body))
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nothing", nil))
		if got := len(r.errs) == 0; got != c.ok {
			t.Errorf("GET /nothing answered 429, %s: taken %v, want %v (%q)", c.what, got, c.ok, r.errs)
		}
	}
}

// A fetch that asks for a range is answered 206 with the bytes from there on
// and a Content-Range in its one form, or 200 with the whole body
// (PROTOCOL.md §5.2): a 206 without one, or with one of another form, is no
// answer of the description's, and neither Range nor If-Range is a header
// the description refuses.
func TestARangedFetchIsTheDescriptions(t *testing.T) {
	path := "/v1/" + strings.Repeat("ab", 32) + "/messages/" + strings.Repeat("cd", 32)
	fetch := func(status int, contentRange string, hdr ...string) []string {
		r := &reported{TB: t}
		h := apitest.Handler(r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", protocol.CiphertextContentType)
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Cache-Control", "no-store")
			if contentRange != "" {
				w.Header().Set("Content-Range", contentRange)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte("tail"))
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "irongall-pass x")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return r.errs
	}
	if errs := fetch(http.StatusPartialContent, protocol.ContentRange(6, 10), "Range", protocol.RangeAsk(6)); len(errs) > 0 {
		t.Errorf("a 206 to a ranged fetch: %q", errs)
	}
	if errs := fetch(http.StatusOK, "", "Range", "bytes=6-", "If-Range", `"x"`); len(errs) > 0 {
		t.Errorf("a 200 to a fetch with a Range and an If-Range: %q", errs)
	}
	for _, c := range []string{"", "bytes 06-9/10", "bytes 6-9/*", "items 6-9/10", "bytes */10", "bytes 6-9/10 "} {
		if errs := fetch(http.StatusPartialContent, c, "Range", protocol.RangeAsk(6)); len(errs) == 0 {
			t.Errorf("a 206 with Content-Range %q passes", c)
		}
	}
}
