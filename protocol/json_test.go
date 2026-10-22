package protocol

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every json/ vector gets the verdict its name gives: ok-* is a JSON text as
// the protocol reads one (PROTOCOL.md §0b), bad-* is not.
func TestVectorJSON(t *testing.T) {
	files := glob(t, "json/*.json")
	if len(files) != 52 {
		t.Fatalf("%d json/ vectors, want 52", len(files))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		err := Unmarshal(read(t, "json/"+filepath.Base(f)), &struct{}{})
		switch {
		case strings.HasPrefix(name, "ok-") && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case strings.HasPrefix(name, "bad-") && !errors.Is(err, ErrJSON):
			t.Errorf("%s: %v, want ErrJSON", name, err)
		}
	}
}

// answerTypes is what each kind of answer/ vector is read into, as the Go
// client reads that answer.
var answerTypes = map[string]func() any{
	"box":     func() any { return new(BoxResponse) },
	"list":    func() any { return new(MessageList) },
	"record":  func() any { return new(Revocations) },
	"receipt": func() any { return new(Receipt) },
	"problem": func() any { return new(Problem) },
}

// Every answer/ vector gets the verdict its name gives when read as the Go
// client reads that kind of answer: <kind>-ok-* is taken, <kind>-bad-* is no
// answer.
func TestVectorAnswers(t *testing.T) {
	files := glob(t, "answer/*.json")
	if len(files) != 58 {
		t.Fatalf("%d answer/ vectors, want 58", len(files))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		kind, verdict, _ := strings.Cut(name, "-")
		v, ok := answerTypes[kind]
		if !ok {
			t.Fatalf("%s: no kind of answer is %q", name, kind)
		}
		err := Unmarshal(read(t, "answer/"+filepath.Base(f)), v())
		switch {
		case strings.HasPrefix(verdict, "ok-") || verdict == "ok":
			if err != nil {
				t.Errorf("%s: refused: %v", name, err)
			}
		case strings.HasPrefix(verdict, "bad-"):
			if err == nil {
				t.Errorf("%s: taken", name)
			}
		default:
			t.Errorf("%s: neither ok nor bad", name)
		}
	}
	// A record whose names are in another case shows nothing: they are
	// members the record does not have.
	var rec Revocations
	if err := Unmarshal(read(t, "answer/record-ok-names-in-another-case.json"), &rec); err != nil || rec.Identity != nil || rec.Revocation != nil {
		t.Errorf("a record's names in another case are read as its members: %+v, %v", rec, err)
	}
}

// A request is read as an answer is, and a member its call does not take is
// refused, by name.
func TestUnmarshalRequest(t *testing.T) {
	var req RegisterRequest
	err := UnmarshalRequest([]byte(`{"identity":"AAAA","prekey":"AAAA","prekey_signature":"AAAA","Prekey":"AAAA"}`), &req)
	if !errors.Is(err, ErrUnknownMember) || !strings.Contains(err.Error(), `"Prekey"`) {
		t.Errorf("a member in another case: %v, want ErrUnknownMember naming it", err)
	}
	for _, c := range []struct {
		body string
		into func() any
		want error
	}{
		{`{"allow":[],"deny":[]}`, acl, nil},
		{`{"allow":[],"allow":[],"deny":[]}`, acl, ErrJSON},
		{`{"allow":"*","deny":[]}`, acl, ErrJSON},
		{`{"version":1,"allow":[],"deny":[]}`, acl, ErrUnknownMember},
		{`{"prekey":"AAA=","prekey_signature":"AAAA"}`, prekey, nil},
		{`{"prekey":"AAB=","prekey_signature":"AAAA"}`, prekey, ErrNotBase64},
		{`{"prekey":"AAA","prekey_signature":"AAAA"}`, prekey, ErrNotBase64},
		{`{"prekey":"AA\nAA","prekey_signature":"AAAA"}`, prekey, ErrNotBase64},
		{`{"prekey":5,"prekey_signature":"AAAA"}`, prekey, ErrNotBase64},
	} {
		err := UnmarshalRequest([]byte(c.body), c.into())
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.body, err, c.want)
		}
	}
}

func acl() any    { return new(ACLDocument) }
func prekey() any { return new(PrekeyRequest) }

// A send's query is read as a statement writes a serial: each of the two
// once, digits with no leading zero, from 1 to MaxSerial, and no other
// parameter. A refusal names the parameter at fault, which a server answers
// in member.
func TestParseSendQuery(t *testing.T) {
	for raw, want := range map[string]SendQuery{
		"prekey_serial=1&certificate_serial=2":                {1, 2},
		"certificate_serial=2&prekey_serial=1":                {1, 2},
		"prekey_serial=9007199254740991&certificate_serial=1": {MaxSerial, 1},
	} {
		if q, err := ParseSendQuery(raw); err != nil || q != want {
			t.Errorf("%s: %+v, %v", raw, q, err)
		}
	}
	if q := (SendQuery{3, 1792000000}); q.Encode() != "prekey_serial=3&certificate_serial=1792000000" {
		t.Errorf("Encode: %s", q.Encode())
	} else if back, err := ParseSendQuery(q.Encode()); err != nil || back != q {
		t.Errorf("Encode does not read back: %+v, %v", back, err)
	}
	for raw, param := range map[string]string{
		"":                                                          PrekeySerialParam,
		"prekey_serial=1":                                           CertificateSerialParam,
		"certificate_serial=1":                                      PrekeySerialParam,
		"prekey_serial=0&certificate_serial=1":                      PrekeySerialParam,
		"prekey_serial=01&certificate_serial=1":                     PrekeySerialParam,
		"prekey_serial=+1&certificate_serial=1":                     PrekeySerialParam,
		"prekey_serial=-1&certificate_serial=1":                     PrekeySerialParam,
		"prekey_serial=1.0&certificate_serial=1":                    PrekeySerialParam,
		"prekey_serial=&certificate_serial=1":                       PrekeySerialParam,
		"prekey_serial=1&certificate_serial=9007199254740992":       CertificateSerialParam,
		"prekey_serial=1&certificate_serial=1&prekey_serial=1":      PrekeySerialParam,
		"prekey_serial=1&certificate_serial=1&cursor=abc":           "cursor",
		"prekey_serial=1&certificate_serial=1&Prekey_serial=1":      "Prekey_serial",
		"prekey_serial=1&certificate_serial=1&certificate_serial=1": CertificateSerialParam,
	} {
		_, err := ParseSendQuery(raw)
		var qe *QueryError
		if !errors.Is(err, ErrQuery) || !errors.As(err, &qe) || qe.Param != param {
			t.Errorf("%q: %v, want a refusal naming %q", raw, err, param)
		}
	}
	// A query that is not one names no parameter.
	for _, raw := range []string{"%zz", "prekey_serial=1;certificate_serial=1"} {
		var qe *QueryError
		if _, err := ParseSendQuery(raw); !errors.As(err, &qe) || qe.Param != "" {
			t.Errorf("%q: %v", raw, err)
		}
	}
	if v, err := ParseQuery("cursor=abc", "cursor"); err != nil || v["cursor"] != "abc" {
		t.Errorf("a list's cursor: %v, %v", v, err)
	}
	if v, err := ParseQuery("", "cursor"); err != nil || len(v) != 0 {
		t.Errorf("no query: %v, %v", v, err)
	}
}

// A list's cursor is one or more of base64url's alphabet: opaque, and safe
// in a URL as it is.
func TestCheckCursor(t *testing.T) {
	for _, c := range []string{"A", "AZaz09-_", "MTc5MjAwMDAwMA"} {
		if CheckCursor(c) != nil {
			t.Errorf("%q refused", c)
		}
	}
	for _, c := range []string{"", "a/b", "a%2Fb", "a+b", "a=", "a b", "a&b", "a\nb", "é"} {
		if CheckCursor(c) == nil {
			t.Errorf("%q taken", c)
		}
	}
}

// What every reader refuses is said in fixed words: none of the text they
// refuse is quoted.
func TestAJSONRefusalQuotesNothing(t *testing.T) {
	for _, body := range []string{`{"evil":"\ud800"}`, `{"evil":1,"evil":2}`, `{"allow":"evil"}`, "{\"evil\":\"\xff\"}", `{"evil":NaN}`} {
		err := Unmarshal([]byte(body), new(ACLDocument))
		if err == nil || strings.Contains(err.Error(), "evil") {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// The depth is counted from the outermost object, and the limit is the
// same whatever kind of value nests.
func TestMaxDepth(t *testing.T) {
	nest := func(n int, open, inner, closeWith string) []byte {
		return []byte(`{"a":` + strings.Repeat(open, n) + inner + strings.Repeat(closeWith, n) + `}`)
	}
	for _, c := range []struct{ open, inner, closeWith string }{{"[", "", "]"}, {`{"b":`, "0", "}"}} {
		if err := Unmarshal(nest(MaxDepth-1, c.open, c.inner, c.closeWith), &struct{}{}); err != nil {
			t.Errorf("%s nested to %d: %v", c.open, MaxDepth, err)
		}
		if err := Unmarshal(nest(MaxDepth, c.open, c.inner, c.closeWith), &struct{}{}); !errors.Is(err, ErrJSON) {
			t.Errorf("%s nested to %d: %v, want ErrJSON", c.open, MaxDepth+1, err)
		}
	}
}

// A request member holding a value its call does not take, of another JSON
// type or a number that is no integer of its range, is named in the error,
// as §13's bad_request names it in member (#272): every member of every
// request a server reads, given a value of each JSON type.
func TestATypeErrorNamesItsMember(t *testing.T) {
	for _, v := range []any{&AdoptRequest{}, &ACLDocument{}, &RegisterRequest{}, &PrekeyRequest{}, &Revocations{}} {
		typ := reflect.TypeOf(v).Elem()
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			for _, value := range []string{`5`, `1.5`, `-1`, `true`, `[]`, `{}`, `"x"`, `[5]`} {
				body := `{"` + name + `":` + value + `}`
				err := UnmarshalRequest([]byte(body), reflect.New(typ).Interface())
				if errors.Is(err, ErrJSON) && !errors.Is(err, ErrUnknownMember) && Member(err) != name {
					t.Errorf("%s %s: %v names %q", typ.Name(), body, err, Member(err))
				}
			}
		}
	}
}
