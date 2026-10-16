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
// (PROTOCOL.md §0b), by the server, the revocation server and both clients:
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
// bounded by it, since a send names them as JSON numbers.
const MaxInteger = 1<<53 - 1

// ErrJSON is a JSON text the protocol does not take. Its words are fixed:
// they never quote the text, whose author may be a server or a sender.
var ErrJSON = errors.New("not a JSON text as the protocol reads one")

// ErrUnknownMember is a request body with a member its call does not take
// (PROTOCOL.md §0a). Its words name the member, for the caller who sent it,
// and so does [UnknownMember].
var ErrUnknownMember = errors.New("the body has a member this call does not take")

type unknownMemberError struct{ name string }

func (e *unknownMemberError) Error() string {
	return fmt.Sprintf("%v: %q", ErrUnknownMember, e.name)
}

func (e *unknownMemberError) Is(target error) bool { return target == ErrUnknownMember }

// UnknownMember is the name of the member an [ErrUnknownMember] names, or ""
// for any other error: a server answers it as a member of its own, beside the
// words (PROTOCOL.md §13).
func UnknownMember(err error) string {
	if e, ok := errors.AsType[*unknownMemberError](err); ok {
		return e.name
	}
	return ""
}

// Unmarshal reads data, a JSON text the protocol carries, into v: the rules
// of PROTOCOL.md §0b, then encoding/json/v2's with names matched exactly. A
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
		return nil
	case errors.Is(err, ErrNotBase64):
		return ErrNotBase64
	case ok && serr.Err == jsonv2.ErrUnknownName:
		return &unknownMemberError{serr.JSONPointer.LastToken()}
	case errors.Is(err, errNotInteger):
		return fmt.Errorf("%w: %w", ErrJSON, errNotInteger)
	}
	return fmt.Errorf("%w: a member is not of the type the protocol gives it", ErrJSON)
}

// checkJSON holds data to the rules encoding/json/v2's parser does not make
// by itself: one object, nested at most MaxDepth deep, with no surrogate or
// noncharacter in a name or a string (RFC 7493 §2.1). Its parser makes the
// rest as it reads. It returns why data breaks a rule, in fixed words, or ""
// for none.
func checkJSON(data []byte) string {
	d := jsontext.NewDecoder(bytes.NewReader(data))
	for first := true; ; first = false {
		t, err := d.ReadToken()
		switch {
		case errors.Is(err, jsontext.ErrDuplicateName):
			return whyTwice
		case err != nil:
			return "it is not one JSON text in UTF-8"
		case first && t.Kind() != '{':
			return "it is not a JSON object"
		case d.StackDepth() > MaxDepth:
			return fmt.Sprintf("it nests more than %d deep", MaxDepth)
		case t.Kind() == '"' && hasNoncharacter(t.String()):
			return "a string in it holds a Unicode noncharacter"
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
