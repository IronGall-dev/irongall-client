package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	a, err := ParseAddress(good)
	if err != nil || a.String() != good {
		t.Fatalf("ParseAddress(%q) = %v, %v", good, a, err)
	}
	for _, s := range []string{"", good[:63], good + "0", strings.ToUpper(good), good[:63] + "g", " " + good[1:]} {
		if _, err := ParseAddress(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	var got struct{ A Address }
	if err := json.Unmarshal([]byte(`{"A":"`+strings.ToUpper(good)+`"}`), &got); err == nil {
		t.Error("JSON accepted an uppercase address")
	}
}

func TestArmor(t *testing.T) {
	for _, n := range []int{0, 1, 52, 53, 54, 400} {
		blob := bytes.Repeat([]byte{0xa5}, n)
		armored := Armor(blob)
		for _, line := range strings.Split(strings.TrimSuffix(string(armored), "\n"), "\n") {
			if len(line) > armorWidth && !strings.HasPrefix(line, "-----") {
				t.Errorf("%d: line longer than %d", n, armorWidth)
			}
		}
		for name, in := range map[string][]byte{
			"as armored":           armored,
			"CRLF after BEGIN":     bytes.Replace(armored, []byte("-----\n"), []byte("-----\r\n"), 1),
			"CRLF lines":           bytes.ReplaceAll(armored, []byte("\n"), []byte("\r\n")),
			"junk after END":       append(bytes.Clone(armored), "junk"...),
			"no newline after END": bytes.TrimSuffix(armored, []byte("\n")),
			"other line lengths":   []byte(armorBegin + strings.Join(splitEvery(b64(blob), 64), "\n") + "\n" + armorEnd + "\n"),
		} {
			got, err := dearmor(in)
			if err != nil || !bytes.Equal(got, blob) {
				t.Errorf("%d, %s: %v", n, name, err)
			}
		}
	}
	blob := []byte{1, 2, 3, 4}
	for name, in := range map[string]string{
		"no BEGIN":          "U1NI\n" + armorEnd + "\n",
		"junk before":       "x" + string(Armor(blob)),
		"no END":            armorBegin + "AQIDBA==\n",
		"END not on a line": armorBegin + "AQIDBA==" + armorEnd + "\n",
		"bad base64":        armorBegin + "AQID*A==\n" + armorEnd + "\n",
		"non-zero pad bits": armorBegin + "AQIDBB==\n" + armorEnd + "\n",
		"wrong type":        "-----BEGIN SSH SIGNATURX-----\nAQIDBA==\n" + armorEnd + "\n",
	} {
		if _, err := dearmor([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	from, to := Address{1}, Address{2}
	now := time.Date(2026, 10, 10, 12, 0, 0, 500, time.UTC)
	e, err := NewEnvelope(from, to, "<b>&é☃", now)
	if err != nil {
		t.Fatal(err)
	}
	e.Subject = "hi"
	b, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"from":"` + from.String() + `","to":"` + to.String() + `","sent_at":"2026-10-10T12:00:00Z","msg_id":"` + e.MsgID + `","body":"<b>&é☃","subject":"hi"}`
	if string(b) != want {
		t.Errorf("Marshal:\n got %s\nwant %s", b, want)
	}
	got, err := OpenEnvelope(b, from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.MsgID != e.MsgID || !got.SentAt.Equal(now.Truncate(time.Second)) || string(got.Body) != `"<b>&é☃"` || got.Subject != "hi" {
		t.Errorf("OpenEnvelope gave %+v", got)
	}
	if _, err := OpenEnvelope(b, to, to, now); err == nil {
		t.Error("accepted with the wrong signer")
	}
	if _, err := OpenEnvelope(b, from, from, now); err == nil {
		t.Error("accepted for the wrong box")
	}
	if _, err := OpenEnvelope(b, from, to, now.Add(TTL+time.Second)); err == nil {
		t.Error("accepted after the TTL")
	}
	if _, err := (&Envelope{From: from, To: to}).Marshal(); err == nil {
		t.Error("marshalled an envelope with no body")
	}
}

// A JSON body is sent as written, compact, and refused when its reader would
// refuse the envelope it is in: the sender and the reader hold it to one set
// of rules (PROTOCOL.md §3.3, §12.3 check 3).
func TestAJSONBodyIsSentAsWrittenOrRefused(t *testing.T) {
	from, to := Address{1}, Address{2}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	written := func(body string) []byte { // an envelope with this text in the body's place
		return []byte(`{"v":1,"from":"` + from.String() + `","to":"` + to.String() + `","sent_at":"2026-10-10T12:00:00Z","msg_id":"0b1a7d2e-5c0f-4a6e-9f1d-2b3c4d5e6f70","body":` + body + `}`)
	}
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	for in, want := range map[string]string{
		"{\n  \"b\": [1, 2.50, 1e3],\n  \"a\": \"\\u00e9\\/ x\",\n  \"n\": null\n}\n": `{"b":[1,2.50,1e3],"a":"\u00e9\/ x","n":null}`,
		`"text"`:       `"text"`,
		" 42 ":         `42`,
		"null":         `null`,
		"true":         `true`,
		deep(31):       deep(31),
		`{"é☃":"<&>"}`: `{"é☃":"<&>"}`,
	} {
		e, err := NewJSONEnvelope(from, to, []byte(in), now)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if string(e.Body) != want {
			t.Errorf("%q: the body is %s, want %s", in, e.Body, want)
		}
		line, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenEnvelope(line, from, to, now)
		if err != nil || string(got.Body) != want {
			t.Errorf("%q: its reader takes %v, %v", in, got, err)
		}
	}
	// The line escapes U+2028 and U+2029 in a JSON body, as in a text body.
	sep := string(rune(0x2028)) + string(rune(0x2029))
	for _, mk := range []func() (*Envelope, error){
		func() (*Envelope, error) { return NewJSONEnvelope(from, to, []byte(`{"a":"`+sep+`"}`), now) },
		func() (*Envelope, error) { return NewEnvelope(from, to, sep, now) },
	} {
		e, err := mk()
		if err != nil {
			t.Fatal(err)
		}
		if line, _ := e.Marshal(); !bytes.Contains(line, []byte(`"\u2028\u2029"`)) || bytes.Contains(line, []byte(sep)) {
			t.Errorf("the line: %q", line)
		}
	}
	if j, err := NewJSONEnvelope(from, to, []byte(`"text"`), now); err != nil {
		t.Fatal(err)
	} else if s, _ := NewEnvelope(from, to, "text", now); string(j.Body) != string(s.Body) {
		t.Errorf("a JSON string body %s is not the text body %s", j.Body, s.Body)
	}
	for _, in := range []string{
		"", " ", "1 2", `{"a":1}x`, `{"a":1,"a":2}`, `{"x":[{"a":1,"a":2}]}`, "\"\xff\"", "\ufeff{}",
		`"\uFFFE"`, "\"\uFDD0\"", `{"\uFFFF":1}`, `"\uD800"`, "NaN", "01", "+1", ".5", "[1,]", "{'a':1}", deep(32),
		"1e400", `{"n":[-1e1000000000]}`, "1.797693134862315808e308",
	} {
		if _, err := NewJSONEnvelope(from, to, []byte(in), now); err == nil {
			t.Errorf("%q: sent", in)
		}
		if _, err := OpenEnvelope(written(in), from, to, now); err == nil {
			t.Errorf("%q: the sender refuses it and its reader takes it", in)
		}
	}
	// Not one value: written in the body's place, it would make a second member.
	if _, err := NewJSONEnvelope(from, to, []byte(`1,"x":2`), now); err == nil {
		t.Error("two members in the body's place: sent")
	}
}

func TestNewMsgID(t *testing.T) {
	v4 := regexp.MustCompile(`\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z`)
	seen := map[string]bool{}
	for range 1000 {
		id, err := NewMsgID()
		if err != nil {
			t.Fatal(err)
		}
		if !v4.MatchString(id) || !msgIDGrammar.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated msg_id %q", id)
		}
		seen[id] = true
	}
}

func TestNewIdentityRejectsSmallOrder(t *testing.T) {
	if _, err := NewIdentity(make(ed25519.PublicKey, 32)); err == nil {
		t.Error("accepted a small-order key")
	}
	if _, err := NewIdentity(make(ed25519.PublicKey, 31)); err == nil {
		t.Error("accepted a 31-byte key")
	}
}

func TestPrekeyLifetime(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	for d, ok := range map[time.Duration]bool{
		0:                               false,
		time.Second:                     true,
		MaxPrekeyLifetime:               true,
		MaxPrekeyLifetime + time.Second: false,
	} {
		p := &Prekey{NotAfter: now.Add(d)}
		if (p.CheckLifetime(now) == nil) != ok {
			t.Errorf("not_after = now + %v: lifetime ok %v, want %v", d, !ok, ok)
		}
	}
}

func TestParseTime(t *testing.T) {
	for _, s := range []string{"2026-10-10T00:00:00Z", "2026-02-28T23:59:59Z"} {
		if _, err := ParseTime(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"2026-10-10T00:00:00", "2026-10-10T00:00:00.0Z", "2026-1-10T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-10T24:00:00Z", "2026-10-10t00:00:00Z", " 2026-10-10T00:00:00Z"} {
		if _, err := ParseTime(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

// Every code this version knows has a status, a title and a code's form:
// the codes are read from Codes(), never typed here (#426 item 4).
func TestCodes(t *testing.T) {
	for _, c := range Codes() {
		if c.Status() == 0 || c.Title() == "" || !c.Known() || !regexp.MustCompile(`\A[a-z0-9_]{1,40}\z`).MatchString(string(c)) {
			t.Errorf("%s has no status or title, or is not a code's form", c)
		}
	}
	if Code("nope").Status() != 0 {
		t.Error("an unknown code has a status")
	}
	b, _ := json.Marshal(Problem{Type: CodeMailboxBusy.TypeURI(), Title: "t", Status: 429, Code: CodeMailboxBusy})
	if string(b) != `{"type":"tag:dromas.dev,2026-10-26:errors/mailbox_busy","title":"t","status":429,"code":"mailbox_busy"}` {
		t.Errorf("Problem JSON %s", b)
	}
}

// Every quota a rate_limited names has the form of a code and one of the two
// subjects, and the two members are written as Google's QuotaFailure names them.
// The quotas are read from Quotas(), never typed here (#426 item 4).
func TestQuotas(t *testing.T) {
	for _, q := range Quotas() {
		if !q.Known() || !q.Subject().Known() || !regexp.MustCompile(`\A[a-z0-9_]{1,40}\z`).MatchString(string(q)) {
			t.Errorf("%s is not known, has no subject, or is not a code's form", q)
		}
	}
	if Quota("nope").Known() || Quota("nope").Subject() != "" || Subject("nope").Known() {
		t.Error("an unknown quota or subject is known")
	}
	b, _ := json.Marshal(Problem{Type: CodeRateLimited.TypeURI(), Title: "t", Status: 429, Code: CodeRateLimited, QuotaID: QuotaSends, Subject: SubjectBox})
	if string(b) != `{"type":"tag:dromas.dev,2026-10-26:errors/rate_limited","title":"t","status":429,"code":"rate_limited","quota_id":"sends","subject":"box"}` {
		t.Errorf("Problem JSON %s", b)
	}
}

// A problem's code counts only where it is known, under its own status, and
// beside its own type: a body that names its problem twice and disagrees
// names none, and is read by its status alone.
func TestACodeCountsOnlyBesideItsOwnType(t *testing.T) {
	for _, c := range []struct {
		p      Problem
		status int
		want   Code
	}{
		{Problem{Type: CodeNotRevoked.TypeURI(), Code: CodeNotRevoked}, 404, CodeNotRevoked},
		{Problem{Type: CodeNotRevoked.TypeURI(), Code: CodeNotRevoked}, 400, ""},
		{Problem{Type: CodeRevoked.TypeURI(), Code: CodeNotRevoked}, 404, ""},
		{Problem{Type: "https://dromas.dev/errors/not_revoked", Code: CodeNotRevoked}, 404, ""},
		{Problem{Type: "tag:dromas.dev,2026-10:errors/not_revoked", Code: CodeNotRevoked}, 404, ""},
		{Problem{Type: "tag:irongall.dev,2026-10-17:errors/not_revoked", Code: CodeNotRevoked}, 404, ""}, // the type before the rename names no code
		{Problem{Code: CodeNotRevoked}, 404, ""},
		{Problem{Type: TypePrefix + "nope", Code: "nope"}, 404, ""},
	} {
		if got := c.p.CodeAt(c.status); got != c.want {
			t.Errorf("%+v at %d: %q, want %q", c.p, c.status, got, c.want)
		}
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
