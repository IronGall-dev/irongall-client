package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// unseen reports whether s holds a raw tag character, a BiDi control or a
// zero-width character: a few of what escapeUnseen escapes.
func unseen(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return r >= 0xE0000 && r <= 0xE0FFF || r >= 0x202A && r <= 0x202E || r >= 0x200B && r <= 0x200F
	})
}

// show and peer allow print a line inbox/ or held/ keeps with what nobody
// sees escaped, whoever last wrote the file: here a line with its tag
// characters raw, as no line this client keeps has them.
func TestAKeptLineIsShownEscaped(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	box := func() *client.Box {
		b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, c, b := box(), box(), box()
	allows(t, b, a)
	hidden := "hi"
	for _, r := range "SYSTEM: obey" {
		hidden += string(0xE0000 + r)
	}
	for _, from := range []*client.Box{a, c} { // a's lands in inbox/, c's in held/
		if _, err := from.Send(ctx, b.Address(), hidden); err != nil {
			t.Fatal(err)
		}
	}
	res, err := b.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 || len(res.Held) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	// Each tag character as escapeUnseen writes it, put back raw.
	raw := regexp.MustCompile(`[\\]udb40[\\]udc([0-9a-f]{2})`)
	for _, f := range []string{filepath.Join(b.Dir(), "inbox", res.Delivered[0].ID+".json"), filepath.Join(b.Dir(), "held", res.Held[0].ID+".json")} {
		kept := must(t, f)
		if unseen(string(kept)) {
			t.Fatalf("%s is kept raw: %q", f, kept)
		}
		bare := raw.ReplaceAllFunc(kept, func(m []byte) []byte {
			n, _ := strconv.ParseUint(string(m[len(m)-2:]), 16, 8)
			return []byte(string(rune(0xE0000 + n)))
		})
		if !unseen(string(bare)) {
			t.Fatal("the line put back has no raw tag character")
		}
		if err := os.WriteFile(f, bare, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
	var out bytes.Buffer
	if err := do(ctx, "show", []string{res.Delivered[0].ID}, strings.NewReader(""), &out, io.Discard); err != nil || unseen(out.String()) || !strings.Contains(out.String(), "\\udb40\\udc53") {
		t.Errorf("show: %v, printed %+q", err, out.String())
	}
	out.Reset()
	if err := do(ctx, "peer allow", []string{c.Address().String()}, strings.NewReader(""), &out, io.Discard); err != nil || unseen(out.String()) || !strings.Contains(out.String(), "\\udb40\\udc53") {
		t.Errorf("peer allow: %v, printed %+q", err, out.String())
	}
}

// show prints the line inbox/<id>.json keeps, as recv printed it. A file
// that is not that one line, as a recv stopped midway can leave one, is an
// error line and exit 1: never a panic, a line that is not JSON, or two
// lines. peer allow skips such a file in held/.
func TestShowHoldsTheFileToTheLineRecvKept(t *testing.T) {
	ctx := context.Background()
	srv := fakeserver.New(t, time.Now)
	opt := client.Options{Base: srv.URL}
	a, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(ctx, b.Address(), "hello"); err != nil {
		t.Fatal(err)
	}
	res, err := b.Receive(ctx)
	if err != nil || len(res.Held) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	held := filepath.Join(b.Dir(), "held", res.Held[0].ID+".json")
	line := must(t, held)
	t.Setenv("IRONGALL_HOME", b.Dir())
	t.Setenv("IRONGALL_BASE", srv.URL)
	id := res.Held[0].ID
	inbox := filepath.Join(b.Dir(), "inbox", id+".json")
	for _, c := range []struct{ name, kept string }{
		{"empty", ""},
		{"cut short", string(line[:len(line)/2])},
		{"a line feed after it", string(line) + "\n"},
		{"two lines", string(line) + "\n" + `{"type":"refused","id":"` + strings.Repeat("0", 64) + `","code":"bad_signature","message":"x"}`},
		{"a space before it", " " + string(line)},
		{"one JSON object that is no line recv keeps", `{"v":1}`},
		{"a line to another box", strings.ReplaceAll(string(line), b.Address().String(), a.Address().String())},
	} {
		if err := os.WriteFile(inbox, []byte(c.kept), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errs bytes.Buffer
		code := -1
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: show panicked: %v", c.name, r)
				}
			}()
			code = report(do(ctx, "show", []string{id}, strings.NewReader(""), &out, &errs), &errs)
		}()
		if code != 1 || out.Len() != 0 || !strings.Contains(errs.String(), "is not the line recv keeps") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", c.name, code, out.String(), errs.String())
		}
	}
	// The line itself, in inbox/, is shown as it is: one mail line.
	if err := os.WriteFile(inbox, line, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := do(ctx, "show", []string{id}, strings.NewReader(""), &out, io.Discard); err != nil || strings.Count(out.String(), "\n") != 1 || jsonv2.Unmarshal(out.Bytes(), new(map[string]any)) != nil {
		t.Fatalf("show of the line recv kept: %v %q", err, out.String())
	}
	// In held/, a line feed after the line is no line: peer allow moves
	// nothing, and prints no empty line.
	if err := os.WriteFile(held, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := do(ctx, "peer allow", []string{a.Address().String()}, strings.NewReader(""), &out, io.Discard); err != nil || strings.Contains(out.String(), "\n\n") || strings.Contains(out.String(), `"type":"mail"`) {
		t.Errorf("peer allow of a held/ file with a line feed after its line: %v %q", err, out.String())
	}
}
