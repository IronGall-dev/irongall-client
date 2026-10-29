package client

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTheDefaultClientResumesTLSOnANewConnection: a connection the default
// client makes after another to the same server resumes the TLS session,
// rather than making a full handshake.
func TestTheDefaultClientResumesTLSOnANewConnection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	tr := defaultTransport(&holding{})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.TLSClientConfig.RootCAs = pool
	c := &http.Client{Transport: tr}
	var resumed []bool
	for range 2 {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		resumed = append(resumed, resp.TLS.DidResume)
		c.CloseIdleConnections() // the next request makes a new connection
	}
	if resumed[0] || !resumed[1] {
		t.Fatalf("resumed %v, want a full handshake then a resumed one", resumed)
	}
}

// TestNoKeepAliveUntilAConnectionDrops: the default client's dialer sends
// no keep-alive, where net's default sends it, until a connection drops
// part way through a hold; the next then keeps alive below the drop.
func TestNoKeepAliveUntilAConnectionDrops(t *testing.T) {
	var h holding
	// net.Dialer: keep-alive is off only with KeepAliveConfig.Enable false
	// and KeepAlive negative.
	if d := h.dialer(); d.KeepAliveConfig.Enable || d.KeepAlive >= 0 {
		t.Fatalf("a box that has seen no drop dials with keep-alive: %+v", d)
	}
	h.dropped(3*time.Minute, false)
	d := h.dialer()
	if ka := d.KeepAliveConfig; !ka.Enable || ka.Idle != 3*time.Minute-holdMargin || ka.Interval != ka.Idle {
		t.Fatalf("after a drop at 3 minutes the dialer keeps alive with %+v", ka)
	}
}

// TestASilentDropHalvesTheKeepAlive: a drop seen only at the hold's
// deadline came at some time within the wait, so keep-alive halves at each,
// from the wait, to its floor; only then does the wait halve, to MinHold.
func TestASilentDropHalvesTheKeepAlive(t *testing.T) {
	var h holding
	held := DefaultHold + holdMargin
	type step struct{ wait, keepAlive time.Duration }
	var got []step
	for range 7 {
		w, ka := h.dropped(held, true)
		got = append(got, step{w, ka})
	}
	want := []step{
		{DefaultHold, 2*time.Minute + 22*time.Second},
		{DefaultHold, time.Minute + 11*time.Second},
		{DefaultHold, 35 * time.Second},
		{DefaultHold, minKeepAlive},
		{2*time.Minute + 22*time.Second, minKeepAlive},
		{time.Minute + 11*time.Second, minKeepAlive},
		{MinHold, minKeepAlive},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("silent drops came to %v, want %v", got, want)
		}
	}
}
