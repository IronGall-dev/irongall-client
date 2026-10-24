package client

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Every box's transport calls a server on this machine, or one named
// localhost in any case, through no proxy, whatever the environment names,
// and every other through the proxy the transport it was given chooses
// (PROTOCOL.md §0; #290). Read from the transport's own Proxy, so the
// environment, which net/http reads once a process, plays no part.
func TestNoProxyForThisMachine(t *testing.T) {
	t.Parallel()
	proxy, _ := url.Parse("http://proxy.example:3128")
	given := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return proxy, nil }}
	tr := newTransport(given).(transport).next.(*http.Transport)
	for host, direct := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "LocalHost": true, "127.0.0.1": true, "127.1.2.3": true, "[::1]": true,
		"irongall.dev": false, "localhost.example": false, "128.0.0.1": false,
	} {
		r, _ := http.NewRequest(http.MethodGet, "https://"+host+":8443/v1/x", nil)
		got, err := tr.Proxy(r)
		if err != nil || (got == nil) != direct {
			t.Errorf("%s: proxy %v, %v; want direct %v", host, got, err, direct)
		}
	}
}

// The transport holds every request's URL to checkServerURL, whatever made
// the request and whatever HTTP client the box was given: nothing goes over
// http off this machine (PROTOCOL.md §0).
func TestEveryRequestIsHeldToTheServerRule(t *testing.T) {
	t.Parallel()
	for _, c := range []*http.Client{nil, {}, {Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("a request the box refuses reached the transport it was given")
		return nil, http.ErrHandlerTimeout
	})}} {
		b, err := newBox(t.TempDir(), Options{Base: "https://irongall.dev", HTTPClient: c})
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.http.Get("http://irongall.dev/v1/x")
		if err == nil || !strings.Contains(err.Error(), "is not a server this client calls") {
			t.Errorf("a request over http off this machine: %v", err)
		}
	}
	if _, err := newBox("", Options{Base: "http://irongall.dev"}); err == nil {
		t.Error("a box was made for a server over http off this machine")
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A call with no HTTP answer is named by the kind of its failure, read from
// the whole chain of its error, not only the first *net.OpError in it
// (#299): an alert this client sends itself is TLS failing, as the
// server's is, and a dial's failure through a proxy, which net/http wraps
// in a proxyconnect error, is no connection.
func TestTheKindOfNoAnswerIsReadFromTheWholeChain(t *testing.T) {
	t.Parallel()
	refused := errors.New("connection refused")
	for _, c := range []struct {
		err  error
		want string
	}{
		{&url.Error{Op: "Get", URL: "https://irongall.dev/v1/x", Err: &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}}, "TLS failed"},
		{&url.Error{Op: "Get", URL: "https://irongall.dev/v1/x", Err: &net.OpError{Op: "local error", Err: errors.New("tls: bad record MAC")}}, "TLS failed"},
		{&url.Error{Op: "Get", URL: "https://irongall.dev/v1/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: refused}}, "could not connect"},
		{&url.Error{Op: "Get", URL: "https://irongall.dev/v1/x", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: &net.OpError{Op: "dial", Net: "tcp", Err: refused}}}, "could not connect"},
		{&url.Error{Op: "Get", URL: "https://irongall.dev/v1/x", Err: &net.OpError{Op: "read", Net: "tcp", Err: refused}}, "no answer that is HTTP"},
	} {
		var te *transportError
		if !errors.As(noAnswer("GET /v1/x", "no answer that is HTTP", c.err), &te) || te.kind != c.want {
			t.Errorf("%v: %+v, want %q", c.err, te, c.want)
		}
	}
}
