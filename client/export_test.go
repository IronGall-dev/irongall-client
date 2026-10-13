package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// SetRekeyLockWait shortens how long Rekey waits for the lock, for one test.
func SetRekeyLockWait(t *testing.T, d time.Duration) {
	old := rekeyLockWait
	rekeyLockWait = d
	t.Cleanup(func() { rekeyLockWait = old })
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
	return newBox("", opt).call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
}
