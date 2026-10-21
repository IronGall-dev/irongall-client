package client

import (
	"strings"
	"testing"
)

// With no HTTP client given, requests time out: a server that never answers
// cannot hold the box's lock for ever.
func TestDefaultClientTimesOut(t *testing.T) {
	if b, err := newBox(t.TempDir(), Options{}); err != nil || b.http.Timeout <= 0 {
		t.Fatal("the default HTTP client has no timeout")
	}
}

// A pass names the server as an origin is written: its host, lowercase, with
// no user before it, and its port as a number only when that is not the
// scheme's default, so https://irongall.dev:443 and https://irongall.dev name
// one server, as the server reads its Host (PROTOCOL.md §6.1b).
func TestAPassNamesTheServerAsAnOrigin(t *testing.T) {
	for base, want := range map[string]string{
		"https://irongall.dev":              "irongall.dev",
		"https://irongall.dev:443":          "irongall.dev",
		"https://IronGall.dev:0443/":        "irongall.dev",
		"https://someone@irongall.dev:8443": "irongall.dev:8443",
		"https://irongall.dev:80":           "irongall.dev:80",
		"http://irongall:8080":              "irongall:8080",
		"http://irongall:80":                "irongall",
		"http://irongall:":                  "irongall",
		"http://[::1]:8080":                 "[::1]:8080",
		"https://[::1]:443":                 "[::1]",
	} {
		if got, err := (&Box{base: strings.TrimRight(base, "/")}).serverName(); err != nil || got != want {
			t.Errorf("%s: the pass names %q, %v; want %q", base, got, err, want)
		}
	}
	if got, err := (&Box{base: "https://irongall.dev:65536"}).serverName(); err == nil {
		t.Errorf("a port that is no port: named %q", got)
	}
}
