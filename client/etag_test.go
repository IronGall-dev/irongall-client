package client_test

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// polls records each first-page list a mailbox asks for: the If-None-Match it
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

// A poll that finds the mailbox empty keeps its ETag, and the next sends it back:
// a 304 is answered with nothing to do, and the interval is its Retry-After
// (PROTOCOL.md §12.3).
func TestAnEmptyMailboxPollsWithItsETag(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	var p polls
	p.watch(e, b)
	receive(t, b)
	tag, ok := stateOf(b, "etag")
	if !ok || !strings.HasPrefix(string(tag), `"`) {
		t.Fatalf("an empty mailbox keeps %q, want its ETag", tag)
	}
	res := receive(t, b)
	if len(p.asked) != 2 || p.asked[0] != "" || p.asked[1] != string(tag) || p.status[1] != http.StatusNotModified {
		t.Fatalf("polls sent %q and were answered %v, want none, then the kept tag answered 304", p.asked, p.status)
	}
	if res.PollAfter != 60 || len(res.Delivered) != 0 {
		t.Errorf("a 304 gives an interval of %d and %d messages, want the Retry-After, 60, and none", res.PollAfter, len(res.Delivered))
	}
}

// A tag is kept only from an empty mailbox: a page with messages drops it, so a 304
// can never hide messages; the mailbox's next empty poll keeps a new one.
func TestAPageWithMessagesDropsTheETag(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	receive(t, b)
	if !has(b, "etag") {
		t.Fatal("an empty mailbox kept no ETag")
	}
	send(t, a, b, "after the empty poll")
	var p polls
	p.watch(e, b)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want the message the kept tag no longer matched", len(res.Delivered))
	}
	if p.status[0] != http.StatusOK {
		t.Fatalf("the poll after a message came was answered %d, want 200", p.status[0])
	}
	if has(b, "etag") {
		t.Error("a page with messages left the ETag kept")
	}
	receive(t, b)
	if p.asked[len(p.asked)-1] != "" || !has(b, "etag") {
		t.Errorf("the next poll sent %q, and the mailbox keeps a tag: %v; want none sent, and the empty mailbox's tag kept", p.asked[len(p.asked)-1], has(b, "etag"))
	}
}

// A 304 answers only the condition a poll asked: one to a poll that sent no
// If-None-Match is no answer, and so is a list answer without a Retry-After of
// digits alone.
func TestAListAnswerOutOfItsFormIsNoAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
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
// never reaches the mailbox: Go's transport refuses the answer.
func TestAnETagOfAnotherFormIsNotKept(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
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
		if has(b, "etag") {
			t.Errorf("the ETag %q was kept", bad)
		}
	}
}

// A tag a hostile server hands an empty mailbox once, which RFC 9110 §8.8.3
// allows to hold a comma and a "*", is one tag to an honest server: its polls
// are answered in full, and the message sent after is delivered at the next.
func TestAPlantedTagHidesNoMessage(t *testing.T) {
	t.Parallel()
	for _, plant := range []string{`",*,"`, `"x,*,y"`, `W/"a,W/*,b"`} {
		e := newEnv(t)
		a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/messages") || r.URL.RawQuery != "" {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			maps.Copy(w.Header(), rec.Header())
			w.Header().Set("ETag", plant)
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
		receive(t, b)
		if kept, _ := stateOf(b, "etag"); string(kept) != plant {
			t.Fatalf("the mailbox keeps %q, want the planted %s", kept, plant)
		}
		var p polls
		p.watch(e, b)
		send(t, a, b, "after")
		if res := receive(t, b); len(res.Delivered) != 1 || p.status[0] != http.StatusOK {
			t.Errorf("with %s kept: delivered %d, the poll answered %v; want 1, and 200", plant, len(res.Delivered), p.status)
		}
	}
}

// A 304 is about the page its ETag names (RFC 9110 §15.4.5): one about
// another tag than the poll sent is no answer (RFC 9111 §4.3.4). The drain
// fails, so no prekey a message may be sealed to is deleted, and the kept tag
// goes, so the next poll asks for the page in full. One whose tag a proxy
// marked weak is the answer.
func TestA304AboutAnotherTagIsNoAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	receive(t, b)
	kept, ok := stateOf(b, "etag")
	if !ok {
		t.Fatal("an empty mailbox kept no ETag")
	}
	answer := func(tag string) {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") && r.Header.Get("If-None-Match") != "" {
				w.Header().Set("ETag", tag)
				w.Header().Set("Retry-After", fakeserver.PollInterval)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	answer("W/" + string(kept))
	if res := receive(t, b); len(res.Delivered) != 0 || !has(b, "etag") {
		t.Fatalf("a 304 with the tag sent, marked weak: delivered %d, a tag kept %v; want none, and the tag kept", len(res.Delivered), has(b, "etag"))
	}
	send(t, a, b, "sealed to the prekey current now")
	e.clock.Add(25 * time.Hour) // the next drain renews, and retires that prekey
	answer(`"another"`)
	if _, err := b.Receive(context.Background()); err == nil {
		t.Fatal("a 304 about another tag was taken as an answer")
	}
	if has(b, "etag") {
		t.Error("a 304 about another tag left the mailbox's tag kept")
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Errorf("delivered %d, refused %v; want the message the 304 left on the server", len(res.Delivered), res.Refused)
	}
}
