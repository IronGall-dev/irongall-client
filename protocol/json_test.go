package protocol

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Every json/ vector gets the verdict its name gives: ok-* is a JSON text as
// the protocol reads one (PROTOCOL.md §0b), bad-* is not.
func TestVectorJSON(t *testing.T) {
	files := glob(t, "json/*.json")
	if len(files) != 46 {
		t.Fatalf("%d json/ vectors, want 46", len(files))
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
	"message": func() any { return new(Message) },
	"record":  func() any { return new(Revocations) },
	"receipt": func() any { return new(Receipt) },
	"problem": func() any { return new(Problem) },
}

// Every answer/ vector gets the verdict its name gives when read as the Go
// client reads that kind of answer: <kind>-ok-* is taken, <kind>-bad-* is no
// answer.
func TestVectorAnswers(t *testing.T) {
	files := glob(t, "answer/*.json")
	if len(files) != 54 {
		t.Fatalf("%d answer/ vectors, want 54", len(files))
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
	var req SendRequest
	err := UnmarshalRequest([]byte(`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AAAA","Ciphertext":"AAAA"}`), &req)
	if !errors.Is(err, ErrUnknownMember) || !strings.Contains(err.Error(), `"Ciphertext"`) {
		t.Errorf("a member in another case: %v, want ErrUnknownMember naming it", err)
	}
	for body, want := range map[string]error{
		`{"prekey_serial":9007199254740991,"certificate_serial":1,"ciphertext":"AAAA"}`:      nil,
		`{"prekey_serial":9007199254740992,"certificate_serial":1,"ciphertext":"AAAA"}`:      ErrJSON,
		`{"prekey_serial":1.0,"certificate_serial":1,"ciphertext":"AAAA"}`:                   ErrJSON,
		`{"prekey_serial":1e0,"certificate_serial":1,"ciphertext":"AAAA"}`:                   ErrJSON,
		`{"prekey_serial":"1","certificate_serial":1,"ciphertext":"AAAA"}`:                   ErrJSON,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AAAA","ciphertext":"AAAA"}`: ErrJSON,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AAA="}`:                     nil,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AAB="}`:                     ErrNotBase64,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AAA"}`:                      ErrNotBase64,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":"AA\nAA"}`:                   ErrNotBase64,
		`{"prekey_serial":1,"certificate_serial":1,"ciphertext":5}`:                          ErrNotBase64,
	} {
		err := UnmarshalRequest([]byte(body), new(SendRequest))
		if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, want %v", body, err, want)
		}
	}
}

// What every reader refuses is said in fixed words: none of the text they
// refuse is quoted.
func TestAJSONRefusalQuotesNothing(t *testing.T) {
	for _, body := range []string{`{"evil":"\ud800"}`, `{"evil":1,"evil":2}`, `{"prekey_serial":"evil"}`, "{\"evil\":\"\xff\"}", `{"evil":NaN}`} {
		err := Unmarshal([]byte(body), new(SendRequest))
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
