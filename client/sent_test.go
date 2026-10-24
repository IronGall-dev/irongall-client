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
	"github.com/IronGall-dev/irongall-client/internal/forge"
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
	t.Parallel()
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
	t.Parallel()
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

// A JSON body arrives as the value sent, compact and as written, in what the
// recipient delivers and in the line it prints, and so does the sender's sent/
// record.
func TestSendJSON(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	in := "{\"action\": \"approve\",\n \"ids\": [3, 1.50, 2e3], \"note\": \"<&>\", \"none\": null}\n"
	want := `{"action":"approve","ids":[3,1.50,2e3],"note":"<&>","none":null}`
	s, err := a.SendJSON(context.Background(), b.Address(), []byte(in), client.Fields{Subject: "the order"})
	if err != nil {
		t.Fatal(err)
	}
	res := receive(t, b)
	if len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != want || res.Delivered[0].Envelope.Subject != "the order" {
		t.Fatalf("delivered %+v", res.Delivered)
	}
	if !strings.Contains(string(res.Delivered[0].Line), `"body":`+want+`,`) {
		t.Errorf("the line: %s", res.Delivered[0].Line)
	}
	if rec := sentRecords(t, a)[b.Address().String()+"."+s.MsgID+".json"]; !strings.Contains(string(rec), `"body":`+want+`,`) {
		t.Errorf("sent/: %s", rec)
	}
}

// What its reader would refuse for its form is refused before anything is
// written or posted, and the recipient is not allowed for it: a JSON body
// that breaks a rule of PROTOCOL.md §3.3, and a noncharacter in a text body or
// a subject, which seal once refused only after the outbox kept it.
func TestNothingIsWrittenForAMessageItsReaderRefuses(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	op := watch(e, nil)
	ctx := context.Background()
	nonchar := string(rune(0xFFFE))
	for name, in := range map[string]string{
		"a name twice":              `{"action":"approve","action":"reject"}`,
		"two values":                `{} {}`,
		"bytes after it":            `{}x`,
		"not UTF-8":                 "\"\xff\"",
		"a noncharacter":            `"` + nonchar + `"`,
		"33 deep with its envelope": strings.Repeat("[", 32) + strings.Repeat("]", 32),
		"no JSON at all":            "approve",
	} {
		if _, err := a.SendJSON(ctx, b.Address(), []byte(in), client.Fields{}); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	for name, err := range map[string]error{
		"a text body": func() error { _, err := a.Send(ctx, b.Address(), "a"+nonchar); return err }(),
		"a subject":   func() error { _, err := a.SendWith(ctx, b.Address(), "a", client.Fields{Subject: nonchar}); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "nothing is written or sent") {
			t.Errorf("a noncharacter in %s: %v", name, err)
		}
	}
	made, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*"))
	allowed, _ := os.ReadFile(filepath.Join(a.Dir(), "allowed")) //nolint:gosec // a test's own directory
	if len(made) != 0 || op.count(http.MethodPost, postTo(b)) != 0 || strings.Contains(string(allowed), b.Address().String()) {
		t.Fatalf("a refused message made mail: outbox %v, %d posts, allowed %q", made, op.count(http.MethodPost, postTo(b)), allowed)
	}
}

// sent/ keeps each message the server took: one line, the line the recipient
// delivers as its envelope, byte for byte, and the server's receipt beside
// it, and no member beside the envelope's own but the receipt (#356).
// Nothing is left in the outbox.
func TestSentKeepsTheEnvelopeAndTheReceipt(t *testing.T) {
	t.Parallel()
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
	if err := json.Unmarshal(got["receipt"], &receipt); err != nil || receipt != r.Receipt || receipt.ID != d.ID || receipt.ReceivedAt == "" || receipt.ExpiresAt == "" {
		t.Fatalf("the receipt kept is %+v, the server's %+v, the message %s: %v", receipt, r.Receipt, d.ID, err)
	}
	if len(got) != 2 || string(got["envelope"]) != string(d.Line) {
		t.Fatalf("the record is %s, want the delivered line %s as its envelope and the receipt beside it", rec, d.Line)
	}
	if left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.*")); len(left) != 0 {
		t.Fatalf("the outbox still holds %v", left)
	}
}

// Only a message the server took is in sent/: one that failed is recorded
// when a flush delivers it, and one that can never be delivered never is.
func TestSentHoldsOnlyWhatTheServerTook(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	forge.FailOnce(e.srv, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
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
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/v1/"+b.Address().String()+"/messages") {
			fakeserver.WriteJSON(w, http.StatusRequestEntityTooLarge, protocol.Problem{Type: protocol.CodeTooLarge.TypeURI(), Code: protocol.CodeTooLarge, Status: http.StatusRequestEntityTooLarge})
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
