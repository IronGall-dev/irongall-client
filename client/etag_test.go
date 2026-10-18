package client_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// polls records each first-page list a box asks for: the If-None-Match it
// sent and the status it was answered.
type polls struct {
	mu     sync.Mutex
	asked  []string
	status []int
}

func (p *polls) watch(e *env, b interface{ Address() protocol.Address }) {
	path := "/v1/" + b.Address().String() + "/messages"
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method != http.MethodGet || r.URL.Path != path || r.URL.RawQuery != "" {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.asked = append(p.asked, r.Header.Get("If-None-Match"))
		p.status = append(p.status, sw.code)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// A poll that finds the box empty keeps its ETag, and the next sends it back:
// a 304 is answered with nothing to do, and the interval is its Retry-After
// (PROTOCOL.md §5.1).
func TestAnEmptyBoxPollsWithItsETag(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	var p polls
	p.watch(e, b)
	receive(t, b)
	tag, err := os.ReadFile(filepath.Join(b.Dir(), "etag"))
	if err != nil || !strings.HasPrefix(string(tag), `"`) {
		t.Fatalf("an empty box keeps %q (%v), want its ETag", tag, err)
	}
	res := receive(t, b)
	if len(p.asked) != 2 || p.asked[0] != "" || p.asked[1] != string(tag) || p.status[1] != http.StatusNotModified {
		t.Fatalf("polls sent %q and were answered %v, want none, then the kept tag answered 304", p.asked, p.status)
	}
	if res.PollAfter != 60 || len(res.Delivered) != 0 {
		t.Errorf("a 304 gives an interval of %d and %d messages, want the Retry-After, 60, and none", res.PollAfter, len(res.Delivered))
	}
}

// A tag is kept only from an empty box: a page with mail drops it, so a 304
// can never hide mail; the box's next empty poll keeps a new one.
func TestMailDropsTheETag(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	receive(t, b)
	tag := filepath.Join(b.Dir(), "etag")
	if !exists(tag) {
		t.Fatal("an empty box kept no ETag")
	}
	send(t, a, b, "after the empty poll")
	var p polls
	p.watch(e, b)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want the message the kept tag no longer matched", len(res.Delivered))
	}
	if p.status[0] != http.StatusOK {
		t.Fatalf("the poll after mail came was answered %d, want 200", p.status[0])
	}
	if exists(tag) {
		t.Error("a page with mail left the ETag kept")
	}
	receive(t, b)
	if p.asked[len(p.asked)-1] != "" || !exists(tag) {
		t.Errorf("the next poll sent %q, and the box keeps a tag: %v; want none sent, and the empty box's tag kept", p.asked[len(p.asked)-1], exists(tag))
	}
}

// A 304 answers only the condition a poll asked: one to a poll that sent no
// If-None-Match is no answer, and so is a list answer without a Retry-After of
// digits alone.
func TestAListAnswerOutOfItsFormIsNoAnswer(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	for name, answer := range map[string]func(w http.ResponseWriter){
		"a 304 unasked": func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusNotModified)
		},
		"no Retry-After": func(w http.ResponseWriter) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.MessageList{Messages: []protocol.MessageInfo{}})
		},
		"a Retry-After of another form": func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "1e2")
			fakeserver.WriteList(w, protocol.MessageList{Messages: []protocol.MessageInfo{}})
		},
	} {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
				answer(w)
				return
			}
			next.ServeHTTP(w, r)
		})
		if err := os.Remove(filepath.Join(b.Dir(), "etag")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if _, err := b.Receive(context.Background()); err == nil {
			t.Errorf("%s: the drain went on", name)
		}
	}
}

// A server's tag is sent back only in the form of an entity-tag (RFC 9110
// §8.8.3), printable ASCII and short: any other is not kept. A control byte
// never reaches the box: Go's transport refuses the answer.
func TestAnETagOfAnotherFormIsNotKept(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	for _, bad := range []string{`unquoted`, `"a b"`, `"a"b"`, `"` + strings.Repeat("x", 129) + `"`, `W/unquoted`, `"é"`} {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
				w.Header().Set("ETag", bad)
				fakeserver.WriteList(w, protocol.MessageList{Messages: []protocol.MessageInfo{}})
				return
			}
			next.ServeHTTP(w, r)
		})
		receive(t, b)
		if exists(filepath.Join(b.Dir(), "etag")) {
			t.Errorf("the ETag %q was kept", bad)
		}
	}
}
