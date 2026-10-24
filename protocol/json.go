package protocol

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Every JSON text the protocol carries is read by one set of rules
// (PROTOCOL.md §3.3), by the server and both clients:
// it is I-JSON (RFC 7493), its names match exactly, it is one value, and it
// nests at most MaxDepth deep. The parsing is encoding/json/v2's, whose
// defaults already refuse invalid UTF-8, a byte-order mark, a name twice and
// anything after the value; the checks here are the ones it leaves to its
// caller.

// MaxDepth is how deeply a JSON text the protocol carries may nest objects
// and arrays, the outermost counted as one. It is well under every parser's
// own limit (jq 1.7 refuses 257, Go 10,001: both measured), so a text one
// reader takes is never one another's parser refuses.
const MaxDepth = 32

// MaxInteger is the largest integer a member the protocol defines may hold:
// 2^53 − 1, the largest RFC 7493 says every reader holds exactly. Serials are
// bounded by it, since an answer names one as a JSON number.
const MaxInteger = 1<<53 - 1

// ErrJSON is a JSON text the protocol does not take. Its words are fixed:
// they never quote the text, whose author may be a server or a sender.
var ErrJSON = errors.New("not a JSON text as the protocol reads one")

// ErrUnknownMember is a request body with a member its call does not take
// (PROTOCOL.md §3.3). Its words name the member, for the caller who sent it,
// and so does [Member].
var ErrUnknownMember = errors.New("the body has a member this call does not take")

// ErrMemberValue is a JSON text with a member the protocol knows that holds
// a value it does not take there: a revocation record that names a type
// other than RecordType, or a list whose next_cursor is not a cursor. Its
// words name the member, and so does [Member].
var ErrMemberValue = errors.New("a member holds a value the protocol does not take there")

// memberError is an [ErrUnknownMember], or with known set an
// [ErrMemberValue], naming its member.
type memberError struct {
	name  string
	known bool
}

func newUnknownMember(name string) error { return &memberError{name: name} }

func (e *memberError) Error() string {
	if e.known {
		return fmt.Sprintf("%v: %q", ErrMemberValue, e.name)
	}
	return fmt.Sprintf("%v: %q", ErrUnknownMember, e.name)
}

func (e *memberError) Is(target error) bool {
	return target == ErrMemberValue && e.known || target == ErrUnknownMember && !e.known
}

// Member is the name of the member an [ErrUnknownMember] or an
// [ErrMemberValue] names, or "" for any other error: a server answers it as a
// member of its own, beside the words (PROTOCOL.md §11.3).
func Member(err error) string {
	if e, ok := errors.AsType[*memberError](err); ok {
		return e.name
	}
	return ""
}

// typeChecked is a value with a check of its own after it is read: a
// revocation record's type, a list's cursor.
type typeChecked interface{ checkType() error }

// Unmarshal reads data, a JSON text the protocol carries, into v: the rules
// of PROTOCOL.md §3.3, then encoding/json/v2's with names matched exactly. A
// member v does not name is ignored, as a client ignores one in a response.
// A byte field (Bytes) is base64 in its one encoding, or ErrNotBase64. An
// integer field holds an integer from 0 to MaxInteger, written as one. JSON
// null is the same as leaving the member out.
func Unmarshal(data []byte, v any) error {
	return unmarshal(data, v, false)
}

// UnmarshalRequest is Unmarshal for a request body, which only a server
// reads: a member v does not name is ErrUnknownMember.
func UnmarshalRequest(data []byte, v any) error {
	return unmarshal(data, v, true)
}

func unmarshal(data []byte, v any, request bool) error {
	if why := checkJSON(data); why != "" {
		return fmt.Errorf("%w: %s", ErrJSON, why)
	}
	err := jsonv2.Unmarshal(data, v, jsonv2.RejectUnknownMembers(request), jsonv2.WithUnmarshalers(integers))
	switch serr, ok := errors.AsType[*jsonv2.SemanticError](err); {
	case err == nil:
		if c, ok := v.(typeChecked); ok {
			return c.checkType()
		}
		return nil
	case errors.Is(err, ErrNotBase64):
		return ErrNotBase64
	case ok && serr.Err == jsonv2.ErrUnknownName:
		return newUnknownMember(serr.JSONPointer.LastToken())
	}
	// A member the protocol knows that holds a value it does not take, of
	// another JSON type or a number that is no integer of its range, is named
	// by its name in the body: the first token of the error's JSON pointer,
	// always a name the Go type declares, never one a sender chose
	// (PROTOCOL.md §11.3; #272).
	why := errNotOfItsType
	if errors.Is(err, errNotInteger) {
		why = errNotInteger
	}
	if serr, ok := errors.AsType[*jsonv2.SemanticError](err); ok {
		for name := range serr.JSONPointer.Tokens() {
			return fmt.Errorf("%w: %w: %w", ErrJSON, why, &memberError{name: name, known: true})
		}
	}
	return fmt.Errorf("%w: %w", ErrJSON, why)
}

// errNotOfItsType is a member holding a value of another JSON type than the
// one the protocol gives it.
var errNotOfItsType = errors.New("a member is not of the type the protocol gives it")

// checkJSON holds data to the rules encoding/json/v2's parser does not make
// by itself: one object, nested at most MaxDepth deep, with no surrogate or
// noncharacter in a name or a string (RFC 7493 §2.1) and no number of greater
// magnitude than a binary64 holds (§2.2). Its parser makes the
// rest as it reads. It returns why data breaks a rule, in fixed words, or ""
// for none.
func checkJSON(data []byte) string { return checkText(data, true, MaxDepth) }

// checkText is checkJSON for a JSON text that need not be an object, nested
// at most depth deep: an envelope's body, which its reader meets one level
// down, as a member of the envelope.
func checkText(data []byte, object bool, depth int) string {
	d := jsontext.NewDecoder(bytes.NewReader(data))
	for first := true; ; first = false {
		t, err := d.ReadToken()
		switch {
		case errors.Is(err, jsontext.ErrDuplicateName):
			return whyTwice
		case err != nil:
			return "it is not one JSON text in UTF-8"
		case first && object && t.Kind() != '{':
			return "it is not a JSON object"
		case d.StackDepth() > depth:
			return fmt.Sprintf("it nests more than %d deep", depth)
		case t.Kind() == '"' && hasNoncharacter(t.String()):
			return "a string in it holds a Unicode noncharacter"
		case t.Kind() == '0' && pastBinary64(t.String()):
			return "a number in it is larger than binary64 holds"
		}
		if d.StackDepth() == 0 {
			break
		}
	}
	if _, err := d.ReadToken(); err != io.EOF {
		return "it is not one JSON text in UTF-8"
	}
	return ""
}

// pastBinary64 reports whether a JSON number is of greater magnitude than a
// binary64 holds (RFC 7493 §2.2: "for example, 1E400"): strconv reads it as
// ±Inf with ErrRange, and jq writes 1e1000000000 as the largest binary64, so
// one text would be two values. A number too small for binary64 reads as
// zero, and is taken (PROTOCOL.md §3.3).
func pastBinary64(n string) bool {
	_, err := strconv.ParseFloat(n, 64)
	return errors.Is(err, strconv.ErrRange)
}

// whyTwice is checkJSON's word for a name given twice in one object.
const whyTwice = "an object in it has a member named twice"

// hasNoncharacter reports whether s holds one of Unicode's 66 noncharacters:
// U+FDD0 to U+FDEF, and the last two code points of each plane. A surrogate
// never reaches here: the parser refuses one, escaped or not.
func hasNoncharacter(s string) bool {
	for _, r := range s {
		if r >= 0xFDD0 && (r <= 0xFDEF || r&0xFFFE == 0xFFFE) {
			return true
		}
	}
	return false
}

var errNotInteger = errors.New("an integer member is not an integer from 0 to 2^53 − 1, written as one")

// integers reads every uint64 and int64 Unmarshal fills: a JSON number
// written as digits alone, with no sign, fraction or exponent, from 0 to
// MaxInteger. encoding/json/v2 would take 2^64 − 1, which jq and JavaScript
// read as another number.
var integers = jsonv2.JoinUnmarshalers(
	jsonv2.UnmarshalFromFunc(func(d *jsontext.Decoder, n *uint64) error {
		u, err := integer(d)
		*n = u
		return err
	}),
	jsonv2.UnmarshalFromFunc(func(d *jsontext.Decoder, n *int64) error {
		u, err := integer(d)
		*n = int64(u) //nolint:gosec // at most MaxInteger
		return err
	}),
)

func integer(d *jsontext.Decoder) (uint64, error) {
	t, err := d.ReadToken()
	if err != nil {
		return 0, err
	}
	if t.Kind() == 'n' {
		return 0, nil
	}
	if t.Kind() != '0' {
		return 0, errNotInteger
	}
	u, err := strconv.ParseUint(t.String(), 10, 64)
	if err != nil || u > MaxInteger {
		return 0, errNotInteger
	}
	return u, nil
}
