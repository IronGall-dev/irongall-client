package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Every command prints JSON lines: one object a line, whose first member,
// "type", says what the line is. Its members follow, and last, where this
// client has something to say, "message", in its own words: never a
// sender's, never a server's. Help is the one thing printed as text.
//
// What a command did and what it met on the way go to stdout, mail and
// refusals alike, so a reader of stdout alone misses nothing. Stderr carries
// the line that says the command failed, or that its command line was
// wrong, and the line that says it is waiting.

// line is one line of output: a JSON object whose first member is "type",
// then each name in kv followed by its value, in turn. A value is written
// with encoding/json; a nil one is left out, with its name.
func line(typ string, kv ...any) []byte {
	b := append([]byte(`{"type":`), value(typ)...)
	for i := 0; i+1 < len(kv); i += 2 {
		v := kv[i+1]
		if v == nil {
			continue
		}
		if r := reflect.ValueOf(v); (r.Kind() == reflect.Pointer || r.Kind() == reflect.Slice) && r.IsNil() {
			continue
		}
		b = append(b, ',')
		b = append(b, value(kv[i])...)
		b = append(b, ':')
		b = append(b, value(v)...)
	}
	return append(b, '}')
}

// value is v as JSON, with <, > and & as they are, since a line is read as
// JSON and never as HTML. Every value a line carries is a string, a number, a
// list of strings or a JSON text this client built, none of which fails.
func value(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return []byte("null")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

// typed is the JSON object obj, which this client built, with "type" put
// first.
func typed(typ string, obj []byte) []byte {
	if len(obj) < 2 || obj[0] != '{' {
		return line(typ)
	}
	b := line(typ)
	if string(obj) == "{}" {
		return b
	}
	return append(append(b[:len(b)-1], ','), obj[1:]...)
}

// mail is a message's line: its id, the SHA-256 of its ciphertext, then the
// line inbox/<id>.json keeps, which this client built from the checked
// fields of the envelope.
func mail(d client.Delivery) []byte {
	return typed("mail", append(append([]byte(`{"id":`), value(d.ID)...), append([]byte{','}, d.Line[1:]...)...))
}

// mailHeaders is a message's line without the text its sender chose: its id,
// the envelope's checked fields but for its body and subject, and the size of
// its body in bytes, as the envelope carries it. in_reply_to and supersedes
// are the sender's words, which a reader holds only to being strings, so each
// is here only when it has a msg_id's form; irongall show prints them as sent.
func mailHeaders(d client.Delivery) []byte {
	env := d.Envelope
	msgID := func(s string) any {
		if !protocol.IsMsgID(s) {
			return nil
		}
		return s
	}
	return line("mail_headers", "id", d.ID, "v", protocol.EnvelopeVersion, "from", env.From, "to", env.To,
		"sent_at", env.SentAt.UTC().Format(protocol.TimeLayout), "msg_id", env.MsgID,
		"in_reply_to", msgID(env.InReplyTo), "supersedes", msgID(env.Supersedes), "body_size", len(env.Body))
}

// out prints a line on stdout.
func (e *cli) out(b []byte) error {
	_, err := e.stdout.Write(append(b, '\n'))
	return err
}

// say prints a line on stderr, where nothing waits on whether it was written.
func (e *cli) say(b []byte) { _, _ = e.stderr.Write(append(b, '\n')) }

// omit is s, or nil for line to leave out when s is empty.
func omit(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// seconds is d in whole seconds, rounded up, so a wait is never shortened.
func seconds(d time.Duration) int64 { return int64((d + time.Second - 1) / time.Second) }

// failure is the members of a line about err: from a server's answer, its
// status, its code when it counts (one this client knows, under that status,
// beside its own type), the wait it asked for, and the values its code
// carries, each checked to its type; from a refusal with a code of its own,
// that code; then the message, which is err in this client's own words.
func failure(err error) []any {
	var kv []any
	var ae *client.APIError
	var re *client.RefusedError
	if errors.As(err, &re) && re.Code != "" {
		kv = append(kv, "code", re.Code)
	}
	if errors.As(err, &ae) {
		kv = append(kv, "status", ae.Status)
		p := &ae.Problem
		if p.Code.Known() {
			kv = append(kv, "code", p.Code,
				"limit", p.Limit, "count", p.Count, "unacked", p.Unacked)
			if t, err := protocol.ParseTime(p.OldestExpiresAt); err == nil {
				kv = append(kv, "oldest_expires_at", t.Format(protocol.TimeLayout))
			}
			kv = append(kv, "version", p.Version, "prekey_serial", p.PrekeySerial,
				"certificate_serial", p.CertificateSerial, "through", p.Through)
			// A key type is a name: only one this client knows is printed.
			var types []string
			for _, t := range p.KeyTypes {
				if slices.Contains(protocol.IdentityTypes(), t) && !slices.Contains(types, t) {
					types = append(types, t)
				}
			}
			kv = append(kv, "key_types", types)
			if slices.Contains(protocol.IdentityTypes(), p.KeyType) {
				kv = append(kv, "key_type", p.KeyType)
			}
		}
		if ae.RetryAfter > 0 {
			kv = append(kv, "retry_after", seconds(ae.RetryAfter))
		}
	}
	return append(kv, "message", err.Error())
}

// report prints how a command ended, on stderr, and gives its exit status:
// 0 done, 1 failed, 2 a command line that was wrong, 3 done and the box
// needs a look.
func report(err error, stderr io.Writer) int {
	var look *needsALook
	var wrong *usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &wrong):
		_, _ = fmt.Fprintf(stderr, "%s\n", line("usage_error", "usage", omit(wrong.usage), "help", wrong.help, "message", wrong.msg))
		return 2
	case errors.As(err, &look):
		return 3
	}
	_, _ = fmt.Fprintf(stderr, "%s\n", line("error", failure(err)...))
	return 1
}
