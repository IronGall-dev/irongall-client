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

// TestNoKeepAliveUntilAConnectionDrops: the default client's connections
// send no keep-alive, until one drops part way through a hold; the next
// then keeps alive below the hold that dropped.
func TestNoKeepAliveUntilAConnectionDrops(t *testing.T) {
	var h holding
	if ka := h.keepAliveOf(); ka.Enable {
		t.Fatalf("a box that has seen no drop keeps alive: %+v", ka)
	}
	h.dropped(3 * time.Minute)
	ka := h.keepAliveOf()
	if !ka.Enable || ka.Idle != 3*time.Minute-holdMargin || ka.Interval != ka.Idle {
		t.Fatalf("after a drop at 3 minutes the keep-alive is %+v", ka)
	}
}
