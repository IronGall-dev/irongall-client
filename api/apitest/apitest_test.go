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
