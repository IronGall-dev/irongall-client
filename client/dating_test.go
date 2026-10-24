package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Each post dates its envelope afresh: sent_at is the time of the post, and
// the outbox keeps the envelope as written, for its 33 days. So a message
// that waited 20 days in the outbox is fresh to its reader for the 33 days
// after it was posted, as long as the server keeps it (PROTOCOL.md §12.2, §13).
func TestAPostIsDatedAtThePost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	r, s := e.box(protocol.Classic), e.box(protocol.Classic)
	e.srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
		if q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, "/messages") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, q)
	})
	written := e.clock.Now()
	if _, err := s.Send(ctx, r.Address(), "written 20 days before it was posted"); err == nil {
		t.Fatal("the post went through")
	}
	outbox, err := filepath.Glob(filepath.Join(s.Dir(), "outbox", "*.P"))
	if err != nil || len(outbox) != 1 {
		t.Fatalf("outbox: %v, %v", outbox, err)
	}
	kept, err := os.ReadFile(outbox[0])
	if err != nil {
		t.Fatal(err)
	}

	e.clock.Add(20 * 24 * time.Hour)
	receive(t, r) // renews its prekey, which a send needs
	e.srv.SetMiddle(nil)
	posted := e.clock.Now()
	sent, err := s.Flush(ctx)
	if err != nil || len(sent) != 1 {
		t.Fatalf("flush: %v, %v", sent, err)
	}
	record, err := os.ReadFile(filepath.Join(s.Dir(), "sent", filepath.Base(strings.TrimSuffix(outbox[0], ".P"))+".json"))
	if err != nil || !strings.Contains(string(record), `"sent_at":"`+posted.UTC().Format(protocol.TimeLayout)+`"`) {
		t.Errorf("sent/ keeps %s, want the envelope dated at its post, %s (%v)", record, posted.UTC().Format(protocol.TimeLayout), err)
	}
	if !strings.Contains(string(kept), `"sent_at":"`+written.UTC().Format(protocol.TimeLayout)+`"`) {
		t.Errorf("the outbox kept %s, want the envelope as written", kept)
	}
	if exp, _ := protocol.ParseTime(sent[0].ExpiresAt); !exp.Equal(posted.Add(protocol.Retention)) {
		t.Errorf("the receipt's expires_at %s, want the TTL less the hour after the post", sent[0].ExpiresAt)
	}

	e.clock.Add(30 * 24 * time.Hour)
	res := receive(t, r)
	if len(res.Delivered) != 1 || !res.Delivered[0].Envelope.SentAt.Equal(posted) {
		t.Fatalf("read 30 days after its post, 50 after it was written: delivered %d, refused %v", len(res.Delivered), res.Refused)
	}
	d := res.Delivered[0].Envelope
	w, err := protocol.OpenEnvelopeRecord(kept, s.Address(), r.Address())
	if err != nil {
		t.Fatal(err)
	}
	if d.MsgID != w.MsgID || string(d.Body) != string(w.Body) {
		t.Errorf("the post changed more than sent_at: %+v, written %+v", d, w)
	}
}

// A retry dated afresh is still dropped by its msg_id: a post whose answer
// was lost on day 0, delivered, and posted again on day 32 and a half, is
// read once, at day 33 and two hours too, since the reader keeps its line
// 66 days and an hour (protocol.SeenFor).
func TestARetryDatedAfreshIsDeliveredOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	r, s := e.box(protocol.Classic), e.box(protocol.Classic)
	e.srv.SetMiddle(func(w http.ResponseWriter, q *http.Request, next http.Handler) {
		if q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, "/messages") {
			next.ServeHTTP(httptest.NewRecorder(), q) // stored, and the answer never comes
			http.Error(w, "lost", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, q)
	})
	if _, err := s.Send(ctx, r.Address(), "pay invoice 9 once"); err == nil {
		t.Fatal("the answer came")
	}
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Fatalf("the first copy: delivered %d", len(res.Delivered))
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(32*24*time.Hour + 12*time.Hour)
	receive(t, s) // renews, so its certificate outlasts what it signs
	if sent, err := s.Flush(ctx); err != nil || len(sent) != 1 {
		t.Fatalf("the retry: %v, %v", sent, err)
	}
	e.clock.Add(26 * time.Hour)
	res := receive(t, r)
	if len(res.Delivered) != 0 || len(res.Duplicates) != 1 || len(res.Refused) != 0 {
		t.Errorf("the retry, read at day 33 and two hours: delivered %d, duplicates %d, refused %v; want one duplicate", len(res.Delivered), len(res.Duplicates), res.Refused)
	}
}
