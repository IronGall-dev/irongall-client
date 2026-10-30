package protocol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pageTag is a page's tag as a server writes one: strong, 32 hex digits.
const pageTag = `"0123456789abcdef0123456789abcdef"`

// ifNoneMatchCases are If-None-Match fields, one line each unless split at
// "\n" into lines, and whether each names pageTag.
var ifNoneMatchCases = []struct {
	field string
	names bool
}{
	{pageTag, true},
	{"W/" + pageTag, true},
	{`"other", ` + pageTag, true},
	{pageTag + `, "other"`, true},
	{`W/"other",W/` + pageTag, true},
	{" \t" + pageTag + "\t ", true},
	{`, ,` + pageTag + `,`, true},
	{`"a" ,` + pageTag, true},
	{`"x,y", ` + pageTag, true},
	{"\"\xc3\xa9\", " + pageTag, true},
	{`"other"` + "\n" + pageTag, true},
	{"*", true},
	{" * ", true},
	{"", false},
	{`"other"`, false},
	{pageTag[1 : len(pageTag)-1], false},
	{`",*,"`, false},
	{`"x,*,y"`, false},
	{`W/"a,W/*,b"`, false},
	{pageTag[:len(pageTag)-1] + `,x"`, false},
	{`*, ` + pageTag, false},
	{pageTag + `, *`, false},
	{"*\n" + pageTag, false},
	{"*,", false},
	{pageTag + ` junk`, false},
	{`junk, ` + pageTag, false},
	{pageTag + `, junk`, false},
	{`"other"` + pageTag, false},
	{pageTag + ` ` + pageTag, false},
	{`w/` + pageTag, false},
	{`W/ ` + pageTag, false},
	{`"a` + "\x01" + `", ` + pageTag, false},
	{`"a b", ` + pageTag, false},
	{pageTag[:len(pageTag)-1], false},
	{`W/`, false},
	{`"`, false},
}

// If-None-Match is read as RFC 9110 §13.1.2 has a server evaluate it: "*" as
// the whole value, or a list of entity-tags each read through its closing
// quote; anything else names no page, the tags a hostile server could hand a
// mailbox among them (dromas-dev/dromas-client#149).
func TestIfNoneMatch(t *testing.T) {
	for _, c := range ifNoneMatchCases {
		if got := IfNoneMatch(strings.Split(c.field, "\n"), pageTag); got != c.names {
			t.Errorf("If-None-Match %q names %s: %v, want %v", c.field, pageTag, got, c.names)
		}
	}
	if !IfNoneMatch([]string{pageTag}, "W/"+pageTag) {
		t.Error("a page whose own tag is weak is not named by its tag")
	}
	if IfNoneMatch(nil, pageTag) {
		t.Error("no field names the page")
	}
}

// Every field that names a page names it to net/http too (ServeContent's
// checkIfNoneMatch), "*" alone aside. The reading is stricter than net/http's,
// which matches a tag whatever follows it, and takes "*" among tags.
func FuzzIfNoneMatch(f *testing.F) {
	for _, c := range ifNoneMatchCases {
		f.Add(c.field)
	}
	f.Fuzz(func(t *testing.T, field string) {
		if !IfNoneMatch([]string{field}, pageTag) || strings.Trim(field, " \t") == "*" {
			return
		}
		w := httptest.NewRecorder()
		w.Header().Set("ETag", pageTag)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("If-None-Match", field)
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader(""))
		if w.Code != http.StatusNotModified {
			t.Errorf("%q names %s here, and to net/http not: %d", field, pageTag, w.Code)
		}
	})
}

// If-Match is evaluated as RFC 9110 §13.1.1 has an origin server evaluate
// it: strongly, "*" true only as the whole value, and any other form false,
// "*" among tags and a tag followed by anything but a comma among them
// (#333), where net/http's checkIfMatch is true at the first "*" or matching
// tag.
func TestIfMatch(t *testing.T) {
	const tag = `"abc"`
	for _, c := range []struct {
		lines []string
		etag  string
		want  bool
	}{
		{nil, tag, true},
		{[]string{`*`}, tag, true},
		{[]string{`*`}, "", true},
		{[]string{tag}, tag, true},
		{[]string{`"x", ` + tag}, tag, true},
		{[]string{`"x"`, tag}, tag, true},
		{[]string{` ,, ` + tag + ` `}, tag, true},
		{[]string{`W/"abc"`}, tag, false},
		{[]string{tag}, `W/"abc"`, false},
		{[]string{`"x"`}, tag, false},
		{[]string{tag}, "", false},
		{[]string{`abc`}, tag, false},
		{[]string{``}, tag, false},
		{[]string{`"x", *`}, tag, false},
		{[]string{`*, "x"`}, tag, false},
		{[]string{`*`, tag}, tag, false},
		{[]string{`*junk`}, tag, false},
		{[]string{tag + ` junk`}, tag, false},
		{[]string{tag + `"x"`}, tag, false},
		{[]string{` * `}, tag, true},
	} {
		if got := IfMatch(c.lines, c.etag); got != c.want {
			t.Errorf("If-Match %q on a page tagged %q: %v, want %v", c.lines, c.etag, got, c.want)
		}
	}
}
