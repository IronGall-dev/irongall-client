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
			got, err := Dearmor(in)
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
		if _, err := Dearmor([]byte(in)); err == nil {
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

func TestCodes(t *testing.T) {
	codes := []Code{
		CodeBadRequest, CodeBadAddress, CodeBadEncoding, CodeIdentityMismatch, CodeBadKey, CodeUnsupportedKeyType, CodeNotAge, CodeWrongRecipientType,
		CodeUnauthorized, CodePassExpired,
		CodeUnknownSender, CodeSenderRevoked, CodeSenderNotAllowed, CodeSenderKeyType, CodeAdoptKeyRefused,
		CodeNoSuchMailbox, CodeNoSuchMessage,
		CodeConflict, CodeStalePrekey, CodePrekeyExpired,
		CodeRevoked, CodeTooLarge,
		CodeRateLimited, CodePairFull, CodeMailboxFull,
		CodeUnavailable,
	}
	if len(codes) != len(statuses) {
		t.Errorf("%d codes listed, %d in the status map", len(codes), len(statuses))
	}
	for _, c := range codes {
		if c.Status() == 0 {
			t.Errorf("%s has no status", c)
		}
	}
	if Code("nope").Status() != 0 {
		t.Error("an unknown code has a status")
	}
	b, _ := json.Marshal(Problem{Type: CodePairFull.TypeURI(), Title: "t", Status: 429, Code: CodePairFull})
	if string(b) != `{"type":"https://irongall.dev/errors/pair_full","title":"t","status":429,"code":"pair_full"}` {
		t.Errorf("Problem JSON %s", b)
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
