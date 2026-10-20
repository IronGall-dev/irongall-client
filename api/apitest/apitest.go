// Package apitest holds a server to the API's description, api.OpenAPI, in
// tests. Handler wraps a server's handler, and checks what passes through it:
//
//   - every answer, in strict mode, so a member, a status or a header the
//     description does not name fails, as does one it requires and the answer
//     lacks (a header it does not name is looked for only once every header
//     it names is right: the validator checks that last), and a Set-Cookie;
//   - every request: one the description refuses must not be answered 2xx,
//     and a query on the link page, which the page ignores, is dropped first;
//   - every number in a JSON answer, or in a JSON request answered 2xx, is an
//     integer written in digits alone (PROTOCOL.md §0b), where the schema
//     takes 1.0 and 1e0;
//   - a route the description lacks gets the router's plain 404 or 405, a
//     503 while the server is not ready, or a limit's 429 as PROTOCOL.md §13
//     gives it to any call: rate_limited, with a Retry-After in seconds;
//   - every error's code counts (protocol.Problem.CodeAt): one the
//     description knows, under its own status, beside its own type;
//   - an answer in gzip is one to a request that takes gzip, and is checked
//     as the JSON beneath; the description says which answers may be.
//
// The server and the Go client share protocol's structs, so a member that
// drifts from PROTOCOL.md passes every test the two run together. This is
// what fails then.
package apitest

import (
	"bytes"
	"compress/gzip"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/api"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi-validator/errors"
)

var (
	once    sync.Once
	checker validator.Validator
	built   error
	mu      sync.Mutex // validator is not documented as safe for concurrent use
)

// Validator returns the strict validator of api.OpenAPI, built once.
func Validator() (validator.Validator, error) {
	once.Do(func() {
		doc, err := libopenapi.NewDocument(api.OpenAPI)
		if err != nil {
			built = err
			return
		}
		v, errs := validator.NewValidator(doc, config.WithStrictMode(), config.WithFormatAssertions(),
			// Strict for every header but those no description names: what
			// a client's library, curl or a proxy in front puts on a
			// request, and an answer's Date, length and type (the content
			// map's). The validator's own list skips ETag, Vary and 14 more.
			config.WithStrictIgnoredHeaders("accept", "accept-encoding", "authorization", "connection", "content-length", "content-type", "date", "expect", "host", "transfer-encoding", "user-agent", "x-forwarded-for", "x-forwarded-proto"))
		if len(errs) > 0 {
			built = fmt.Errorf("the description does not build: %v", errs)
			return
		}
		if ok, errs := v.ValidateDocument(); !ok {
			built = fmt.Errorf("the description is not valid OpenAPI: %v", list(errs))
			return
		}
		checker = v
	})
	return checker, built
}

// Routes returns each operation the description has, as "METHOD /path",
// sorted: what a server's own list of routes is held to, so a route added on
// one side and not the other fails.
func Routes() ([]string, error) {
	doc, err := libopenapi.NewDocument(api.OpenAPI)
	if err != nil {
		return nil, err
	}
	m, err := doc.BuildV3Model()
	if err != nil {
		return nil, err
	}
	var routes []string
	for path, item := range m.Model.Paths.PathItems.FromOldest() {
		for method := range item.GetOperations().KeysFromOldest() {
			routes = append(routes, strings.ToUpper(method)+" "+path)
		}
	}
	slices.Sort(routes)
	return routes, nil
}

// Handler returns h, with each request and answer checked against the
// description and every disagreement reported to t.
func Handler(t testing.TB, h http.Handler) http.Handler {
	t.Helper()
	v, err := Validator()
	if err != nil {
		t.Fatal(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := &tee{r: r.Body}
		r.Body = body
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		check(t, v, r, body, rec)
	})
}

func check(t testing.TB, v validator.Validator, r *http.Request, body *tee, rec *recorder) {
	if !rec.wrote {
		rec.header = rec.ResponseWriter.Header().Clone()
	}
	read := body.done || r.ContentLength == 0
	where := r.Method + " " + r.URL.Path + " → " + fmt.Sprint(rec.status)
	req := r.Clone(r.Context())
	req.Body = io.NopCloser(bytes.NewReader(body.buf.Bytes()))
	// The protocol asks no Content-Type of a request: a server reads a send's
	// body as the ciphertext's bytes, and every other body as JSON.
	jsonBody := body.buf.Len() > 0 && (r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/messages"))
	if body.buf.Len() > 0 {
		ct := protocol.CiphertextContentType
		if jsonBody {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	if strings.HasPrefix(r.URL.Path, protocol.LinkPath) {
		// A shared link picks up a query (?utm_source=…), which the page
		// ignores, as the description says. Strict mode cannot declare "any
		// query": it reports one even under additionalProperties.
		req.URL.RawQuery = ""
	}
	mu.Lock()
	ok, errs := v.ValidateHttpRequest(req)
	mu.Unlock()
	if !ok && missing(errs) {
		// No such route: the router's plain answer, a server that is not
		// ready, which answers 503 to everything under /v1/, or a limit's
		// 429, which any request may meet (PROTOCOL.md §13).
		if rec.status == http.StatusTooManyRequests && isProblem(rec.header) {
			// A limit's own answer and no other 429: rate_limited, whom it
			// counted, and a Retry-After in seconds, read as the Go client
			// reads a problem.
			var p protocol.Problem
			if protocol.Unmarshal(rec.body.Bytes(), &p) != nil || p.CodeAt(rec.status) != protocol.CodeRateLimited ||
				!p.Subject.Known() || p.QuotaID != "" && !p.QuotaID.Known() || !delaySeconds(rec.header.Get("Retry-After")) {
				t.Errorf("apitest: %s: a route the description lacks is answered 429 with no rate_limited of the description's\n%s", where, rec.body.Bytes())
			}
			return
		}
		if (rec.status != http.StatusNotFound && rec.status != http.StatusMethodNotAllowed && rec.status != http.StatusServiceUnavailable) ||
			(rec.status != http.StatusServiceUnavailable && isProblem(rec.header)) {
			t.Errorf("apitest: %s: a route the description lacks is answered as one it has", where)
		}
		return
	}
	if !ok && rec.status < 400 && read {
		t.Errorf("apitest: %s: a request the description refuses is answered as taken: %s", where, list(errs))
	}
	if n := notInteger(body.buf.Bytes()); jsonBody && n != "" && rec.status < 400 && read {
		t.Errorf("apitest: %s: a request that writes %s, no integer (PROTOCOL.md §0b), is answered as taken", where, n)
	}
	answer, ok := decoded(t, where, r, rec)
	if !ok {
		return
	}
	if n := notInteger(answer); isJSON(rec.header) && n != "" {
		t.Errorf("apitest: %s: the answer writes %s, no integer (PROTOCOL.md §0b)\n%s", where, n, answer)
	}
	if len(rec.header.Values("Set-Cookie")) > 0 {
		// The validator passes a Set-Cookie on any answer, whatever it is told.
		t.Errorf("apitest: %s: the answer sets a cookie, and the description names Set-Cookie on none", where)
	}
	resp := &http.Response{
		StatusCode: rec.status,
		Header:     rec.header,
		Body:       io.NopCloser(bytes.NewReader(answer)),
		Request:    req,
	}
	req.Body = io.NopCloser(bytes.NewReader(body.buf.Bytes()))
	mu.Lock()
	ok, errs = v.ValidateHttpResponse(req, resp)
	mu.Unlock()
	if !ok {
		t.Errorf("apitest: %s: the answer is not the description's: %s\n%s", where, list(errs), answer)
	}
	if isProblem(rec.header) {
		var p protocol.Problem
		if protocol.Unmarshal(answer, &p) == nil && p.CodeAt(rec.status) == "" {
			t.Errorf("apitest: %s: the error's code does not count: one of this status, beside its own type\n%s", where, answer)
		}
	}
}

// decoded is the body of an answer as its Content-Encoding has it: gzip, to
// a request whose Accept-Encoding names gzip or "*", or none. That is a
// looser reading than RFC 9110 §12.5.3's, weights and all, which a server's
// own tests hold it to. Whether a coding may be on that answer at all is the
// description's to say.
func decoded(t testing.TB, where string, r *http.Request, rec *recorder) ([]byte, bool) {
	ce := rec.header.Get("Content-Encoding")
	if ce == "" || rec.body.Len() == 0 {
		return rec.body.Bytes(), true
	}
	ae := strings.ToLower(strings.Join(r.Header.Values("Accept-Encoding"), ","))
	if ce != "gzip" || !strings.Contains(ae, "gzip") && !strings.Contains(ae, "*") {
		t.Errorf("apitest: %s: an answer in %q, which the request did not take (Accept-Encoding %q)", where, ce, r.Header.Values("Accept-Encoding"))
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.body.Bytes()))
	if err != nil {
		t.Errorf("apitest: %s: an answer in gzip that is not gzip: %v", where, err)
		return nil, false
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Errorf("apitest: %s: an answer in gzip that is not gzip: %v", where, err)
		return nil, false
	}
	return b, true
}

func missing(errs []*errors.ValidationError) bool {
	for _, e := range errs {
		if e.IsPathMissingError() || e.IsOperationMissingError() {
			return true
		}
	}
	return false
}

func isProblem(h http.Header) bool {
	t, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return t == protocol.ProblemContentType
}

// delaySeconds reports whether v is a Retry-After of digits alone (PROTOCOL.md
// §13).
func delaySeconds(v string) bool {
	return v != "" && strings.Trim(v, "0123456789") == ""
}

func isJSON(h http.Header) bool {
	t, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return t == "application/json" || t == protocol.ProblemContentType
}

// notInteger returns the first number in a JSON text that is not written as
// PROTOCOL.md §0b writes an integer, in digits alone, or "" for none. Every
// number the description names is an Integer or a Serial, and JSON Schema
// counts 1.0 and 1e0 as integers, so this is the check the schema cannot
// make. A description that gains another kind of number fails here first.
// What is not JSON is the description's to refuse.
func notInteger(text []byte) string {
	d := jsontext.NewDecoder(bytes.NewReader(text))
	for {
		t, err := d.ReadToken()
		if err != nil {
			return ""
		}
		if t.Kind() == '0' {
			if _, err := strconv.ParseUint(t.String(), 10, 64); err != nil {
				return t.String()
			}
		}
	}
}

func list(errs []*errors.ValidationError) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString("\n  " + e.Message)
		if e.Reason != "" {
			b.WriteString(": " + e.Reason)
		}
		for _, f := range e.SchemaValidationErrors {
			b.WriteString("\n    " + f.Reason + " at " + f.FieldPath)
		}
	}
	return b.String()
}

// tee keeps what the handler reads of a request body; done is whether it
// read to the end. A handler that refuses a call before its body is read
// leaves the body unread, and the request is then checked no further.
type tee struct {
	r    io.ReadCloser
	buf  bytes.Buffer
	done bool
}

func (t *tee) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.buf.Write(p[:n])
	if err == io.EOF {
		t.done = true
	}
	return n, err
}

func (t *tee) Close() error { return t.r.Close() }

// recorder passes an answer through and keeps a copy.
type recorder struct {
	http.ResponseWriter
	status int
	header http.Header
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) WriteHeader(status int) {
	if !r.wrote {
		r.wrote = true
		r.status = status
		r.header = r.ResponseWriter.Header().Clone()
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	r.body.Write(p)
	return r.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the connection beneath, for the
// deadlines a server sets.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
