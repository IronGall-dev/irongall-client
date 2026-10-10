package client

import "testing"

// With no HTTP client given, requests time out: a server that never answers
// cannot hold the box's lock for ever.
func TestDefaultClientTimesOut(t *testing.T) {
	if b := newBox(t.TempDir(), Options{}); b.http.Timeout <= 0 {
		t.Fatal("the default HTTP client has no timeout")
	}
}
