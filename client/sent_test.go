package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// sentRecords returns a box's sent/ files, by name.
func sentRecords(t *testing.T, b *client.Box) map[string][]byte {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(b.Dir(), "sent", "*"))
	if err != nil {
		t.Fatal(err)
	}
	recs := map[string][]byte{}
	for _, n := range names {
		data, err := os.ReadFile(n) //nolint:gosec // a test's own directory
		if err != nil {
			t.Fatal(err)
		}
		recs[filepath.Base(n)] = data
	}
	return recs
}

// The optional fields are the sender's, and reach the recipient inside the
// envelope: in what it delivers and in the line it prints.
func TestSendWithFields(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	f := client.Fields{Subject: "re: <yours> & \"mine\"", InReplyTo: "11111111-2222-4333-8444-555555555555", Supersedes: "22222222-2222-4333-8444-555555555555"}
	if _, err := a.SendWith(context.Background(), b.Address(), "the answer", f); err != nil {
		t.Fatal(err)
	}
	res := receive(t, b)
	if len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	env := res.Delivered[0].Envelope
	if env.Subject != f.Subject || env.InReplyTo != f.InReplyTo || env.Supersedes != f.Supersedes || bodyOf(t, res.Delivered[0]) != "the answer" {
		t.Fatalf("delivered %+v", env)
	}
	var line struct {
		Subject    string `json:"subject"`
		InReplyTo  string `json:"in_reply_to"`
		Supersedes string `json:"supersedes"`
	}
	if err := json.Unmarshal(res.Delivered[0].Line, &line); err != nil || client.Fields(line) != f {
		t.Fatalf("the line carries %+v, %v: %s", line, err, res.Delivered[0].Line)
	}

	// A plain Send sets none of them, and the line has no such member.
	send(t, a, b, "plain")
	if l := string(receive(t, b).Delivered[0].Line); strings.Contains(l, "subject") || strings.Contains(l, "in_reply_to") || strings.Contains(l, "supersedes") {
		t.Fatalf("a plain send's line: %s", l)
	}
}

// in_reply_to and supersedes name a message by its msg_id. Anything else is
// refused before any mail is made: above all the 64-character id the server
// gives a message, which is what send prints.
func TestSendRefusesFieldsThatAreNotMsgIDs(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	r := send(t, a, b, "first")
	posts := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		if req.Method == http.MethodPost {
			posts++
		}
		next.ServeHTTP(w, req)
	})
	for name, f := range map[string]client.Fields{
		"the server's id as in_reply_to": {InReplyTo: r.ID},
		"words as supersedes":            {Supersedes: "the one before"},
		"an uppercase msg_id":            {InReplyTo: "11111111-2222-4333-8444-55555555555A"},
		"a subject that is not UTF-8":    {Subject: "\xff\xfe"},
	} {
		_, err := a.SendWith(context.Background(), b.Address(), "refused", f)
		if err == nil {
			t.Errorf("%s: sent with %+v", name, f)
		}
	}
	if _, err := a.SendWith(context.Background(), b.Address(), "x", client.Fields{InReplyTo: r.ID}); err == nil || !strings.Contains(err.Error(), "in_reply_to is not a msg_id") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
	if made, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*")); len(made) != 0 || posts != 0 {
		t.Fatalf("a refused field made mail: %v, %d posts", made, posts)
	}
}

// sent/ keeps each message the server took: one line, the line the recipient
// delivers, with the server's receipt as its last member. Nothing is left in
// the outbox.
func TestSentKeepsTheEnvelopeAndTheReceipt(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	body := "kept\u0085 by   its   sender"
	r, err := a.SendWith(context.Background(), b.Address(), body, client.Fields{Subject: "s"})
	if err != nil {
		t.Fatal(err)
	}
	d := receive(t, b).Delivered[0]
	recs := sentRecords(t, a)
	name := b.Address().String() + "." + d.Envelope.MsgID + ".json"
	rec, ok := recs[name]
	if len(recs) != 1 || !ok {
		t.Fatalf("sent/ holds %v, not %s", recs, name)
	}
	if strings.ContainsAny(string(rec), "\n\u0085  ") {
		t.Fatalf("the record is not one line: %q", rec)
	}
	if fi, err := os.Stat(filepath.Join(a.Dir(), "sent", name)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the record's mode: %v %v", fi.Mode(), err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(rec, &got); err != nil {
		t.Fatal(err)
	}
	var receipt protocol.Receipt
	if err := json.Unmarshal(got["receipt"], &receipt); err != nil || receipt != *r || receipt.ID != d.ID || receipt.ReceivedAt == "" || receipt.ExpiresAt == "" {
		t.Fatalf("the receipt kept is %+v, the server's %+v, the message %s: %v", receipt, *r, d.ID, err)
	}
	delete(got, "receipt")
	var delivered map[string]json.RawMessage
	if err := json.Unmarshal(d.Line, &delivered); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(delivered) {
		t.Fatalf("the record has %d members beside the receipt, the delivered line %d", len(got), len(delivered))
	}
	for k, v := range delivered {
		if string(got[k]) != string(v) {
			t.Errorf("%s: sent %s, delivered %s", k, got[k], v)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.*")); len(left) != 0 {
		t.Fatalf("the outbox still holds %v", left)
	}
}

// Only a message the server took is in sent/: one that failed is recorded
// when a flush delivers it, and one that can never be delivered never is.
func TestSentHoldsOnlyWhatTheServerTook(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	failOnce(e, http.MethodPost, "/v1/"+b.Address().String())
	if _, err := a.Send(ctx, b.Address(), "fails once"); err == nil {
		t.Fatal("the send did not fail")
	}
	if recs := sentRecords(t, a); len(recs) != 0 {
		t.Fatalf("a failed send is in sent/: %v", recs)
	}
	rs, err := a.Flush(ctx)
	if err != nil || len(rs) != 1 {
		t.Fatalf("flush: %v %v", rs, err)
	}
	recs := sentRecords(t, a)
	if len(recs) != 1 {
		t.Fatalf("after the flush sent/ holds %v", recs)
	}
	for _, rec := range recs {
		if !strings.Contains(string(rec), `"receipt":{"id":"`+rs[0].ID+`"`) || !strings.Contains(string(rec), `"body":"fails once"`) {
			t.Fatalf("the flushed record: %s", rec)
		}
	}

	// Refused for good: it moves to outbox/failed/, and never to sent/.
	e.srv.SetMiddle(func(w http.ResponseWriter, req *http.Request, next http.Handler) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/v1/"+b.Address().String()) {
			fakeserver.WriteJSON(w, http.StatusGone, protocol.Problem{Code: protocol.CodeRevoked, Status: http.StatusGone})
			return
		}
		next.ServeHTTP(w, req)
	})
	if _, err := a.Send(ctx, b.Address(), "never goes"); err == nil || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("the refused send: %v", err)
	}
	if recs := sentRecords(t, a); len(recs) != 1 {
		t.Fatalf("a message refused for good is in sent/: %v", recs)
	}
}
