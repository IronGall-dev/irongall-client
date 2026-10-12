package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A message and an owner token are both age files to the box's prekey, so a
// server can offer a stored message where a token belongs. What the client
// decrypts there is kept and sent only if it has a token's form: otherwise
// the server would read the message in the box's next Authorization header.
func TestAMessageOfferedAsTheTokenIsNeverSentBack(t *testing.T) {
	const secret = "the body the server must not read"
	const header, stale = "irongall-token header", "token_stale"
	for _, kt := range []protocol.KeyType{protocol.Classic, protocol.PostQuantum} {
		for _, route := range []string{header, stale} {
			t.Run(fmt.Sprint(kt)+"/"+route, func(t *testing.T) {
				e := newEnv(t)
				a, b := e.box(kt), e.box(kt)
				posted := capture(e, http.MethodPost, "/v1/"+b.Address().String())
				send(t, a, b, secret)
				var req protocol.SendRequest
				if err := json.Unmarshal(*posted, &req); err != nil || len(req.Ciphertext) == 0 {
					t.Fatalf("no ciphertext captured: %v", err)
				}
				before, err := os.ReadFile(filepath.Join(b.Dir(), "token"))
				if err != nil {
					t.Fatal(err)
				}
				var mu sync.Mutex
				var bearers []string
				first := true
				e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					auth := r.Header.Get("Authorization")
					mu.Lock()
					if auth != "" {
						bearers = append(bearers, auth)
					}
					sayStale := route == stale && auth != "" && first
					if sayStale {
						first = false
					}
					mu.Unlock()
					switch {
					case route == header:
						w.Header().Set(protocol.TokenHeader, base64.StdEncoding.EncodeToString(req.Ciphertext))
					case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
						fakeserver.WriteJSON(w, http.StatusOK, protocol.TokenResponse{Token: req.Ciphertext})
						return
					case sayStale:
						w.Header().Set("Content-Type", "application/problem+json")
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte(`{"type":"https://irongall.dev/errors/token_stale","title":"token_stale","status":401,"code":"token_stale"}`))
						return
					}
					next.ServeHTTP(w, r)
				})
				res, err := b.Receive(context.Background())
				mu.Lock()
				defer mu.Unlock()
				if len(bearers) == 0 {
					t.Fatal("the box made no owner call, so nothing was tested")
				}
				for _, h := range bearers {
					if h != "Bearer "+string(before) {
						t.Errorf("the box sent a bearer that is not its token: %.80q", h)
					}
					if strings.Contains(h, secret) {
						t.Errorf("the server read the message in the Authorization header")
					}
				}
				if now, _ := os.ReadFile(filepath.Join(b.Dir(), "token")); string(now) != string(before) {
					t.Errorf("the token file changed: %.80q", now)
				}
				switch route {
				case header:
					// The offer is ignored, as a refresh that does not decrypt is.
					if err != nil || len(res.Delivered) != 1 {
						t.Errorf("the run was not ordinary: %v", err)
					}
				case stale:
					if err == nil || !strings.Contains(err.Error(), "is not a token") {
						t.Errorf("the refresh was not refused: %v", err)
					}
				}
			})
		}
	}
}
