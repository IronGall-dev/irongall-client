package client

import (
	"encoding/json"
	"fmt"
	"testing"
	"unicode/utf16"
)

// A line a reader is shown escapes every character of Unicode's
// Default_Ignorable_Code_Point and the line breaks other than LF, as JSON
// escapes them, lowercase and a surrogate pair above U+FFFF; a character
// beside each range is kept as it is; and the value is the same.
func TestEscapeUnseenEscapesWhatNobodySees(t *testing.T) {
	t.Parallel()
	esc := func(r rune) string {
		if r > 0xFFFF {
			hi, lo := utf16.EncodeRune(r)
			return fmt.Sprintf(`\u%04x\u%04x`, hi, lo)
		}
		return fmt.Sprintf(`\u%04x`, r)
	}
	check := func(r rune, hidden bool) {
		t.Helper()
		in := `{"body":"a` + string(r) + `b"}`
		want := in
		if hidden {
			want = `{"body":"a` + esc(r) + `b"}`
		}
		got := escapeUnseen([]byte(in))
		if string(got) != want {
			t.Errorf("U+%04X: %q, want %q", r, got, want)
		}
		var v struct{ Body string }
		if err := json.Unmarshal(got, &v); err != nil || v.Body != "a"+string(r)+"b" {
			t.Errorf("U+%04X: the value is %q, %v", r, v.Body, err)
		}
	}
	for _, x := range defaultIgnorable {
		check(x[0], true)
		check(x[1], true)
		check(x[0]-1, escaped(x[0]-1))
		check(x[1]+1, escaped(x[1]+1))
	}
	for _, r := range []rune{0x85, 0x2028, 0x2029} {
		check(r, true)
	}
	// What GitHub's MCP server strips from issue bodies (pkg/sanitize,
	// read 2026-10-16) is all in it: tags, BiDi controls and marks,
	// zero-width characters, and variation selectors.
	for _, r := range []rune{0xE0001, 0xE0020, 0xE007F, 0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C,
		0x200B, 0x200C, 0x00AD, 0xFEFF, 0x180E, 0x2060, 0x2064, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF} {
		check(r, true)
	}
	for _, r := range []rune{'a', 'é', 0x2027, 0x1F600, 0xFFF9, 0xE1000, 0x10FFFF} {
		check(r, false)
	}
}
