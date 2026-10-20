package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A post dates the envelope's line as written, its sent_at's value the one
// change, so a body or a subject in either client's spelling is never
// spelled again (PROTOCOL.md §4.5; client#253): the script's jq writes U+2028
// and U+2029 raw, where Line escapes them, and keeps a number as written.
func TestDatedChangesOnlySentAt(t *testing.T) {
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	later := at.Add(5 * 24 * time.Hour)
	bodies := []string{
		`"plain"`, "\"x y\"", `"x y"`, "{\"a\":\"x y\",\"n\":1.0}",
		`{"n":1E+5,"m":-0,"e":"é","f":"é","g":"<&>","h":"\/"}`, `[1.50,2e3,"😀"]`,
		`"\"quoted\" \\ back"`, `{"a":{"b":[true,false,null]}}`,
	}
	// And every JSON vector a reader takes, as a sender writes it: compact.
	oks, _ := filepath.Glob(filepath.Join("..", "testdata", "vectors", "json", "ok-*.json"))
	for _, f := range oks {
		raw, err := os.ReadFile(f) //nolint:gosec // a vector of this repo
		var c bytes.Buffer
		if err != nil || json.Compact(&c, raw) != nil {
			t.Fatalf("%s: %v", f, err)
		}
		bodies = append(bodies, c.String())
	}
	if len(oks) < 10 {
		t.Fatalf("%d JSON vectors", len(oks))
	}
	for _, body := range bodies {
		line := `{"v":1,"from":"` + strings.Repeat("a", 64) + `","to":"` + strings.Repeat("b", 64) + `","sent_at":"` + at.Format(TimeLayout) +
			`","msg_id":"0f0e0d0c-0b0a-4908-8706-050403020100","identity":"aWQ=","body":` + body + ",\"subject\":\"s t\"}\n"
		got, err := Dated([]byte(line), later)
		want := strings.Replace(line, at.Format(TimeLayout), later.Format(TimeLayout), 1)
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Errorf("%s: %q, %v; want %q", body, got, err, want)
		}
	}
	for _, line := range []string{`{"sent_at":"2026-10-20T00:00:00Z"}`, `{"sent_at":"2026-10-20T00:00:00Z"}{}` + "\n", `[1]` + "\n", "{\"sent_at\":\"2026-10-20T00:00:00Z\"}\n\n", "{\"sent_at\": \"2026-10-20T00:00:00Z\"}\n", " {\"sent_at\":\"2026-10-20T00:00:00Z\"}\n", "{\"sent_at\":\"2026-10-20T00:00:00.5Z\"}\n"} {
		if got, err := Dated([]byte(line), later); err == nil {
			t.Errorf("%q dated: %q", line, got)
		}
	}
}
