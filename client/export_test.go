package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Code is the error's code, if err is an [APIError], for a test that knows
// which call answered.
func Code(err error) protocol.Code { return code(err) }

// SetLockPatience shortens how long a command waits for the box's lock, for
// one test.
func SetLockPatience(t *testing.T, d time.Duration) {
	old := lockPatience
	lockPatience = d
	t.Cleanup(func() { lockPatience = old })
}

// SetDrainLimits lowers what one drain takes, for one test.
func SetDrainLimits(t *testing.T, messages, bytes, pages int) {
	m, b, p := maxDrainMessages, maxDrainBytes, maxDrainPages
	maxDrainMessages, maxDrainBytes, maxDrainPages = messages, bytes, pages
	t.Cleanup(func() { maxDrainMessages, maxDrainBytes, maxDrainPages = m, b, p })
}

// PutRevocations puts a record to the server as it is, with none of the
// checks Revoke makes first: what a client that skipped them would send.
func PutRevocations(ctx context.Context, opt Options, a protocol.Address, rec *protocol.Revocations) (*http.Response, error) {
	b, err := newBox("", opt)
	if err != nil {
		return nil, err
	}
	return b.call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
}
