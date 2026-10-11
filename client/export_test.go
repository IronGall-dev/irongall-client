package client

import (
	"testing"
	"time"
)

// SetRekeyLockWait shortens how long Rekey waits for the lock, for one test.
func SetRekeyLockWait(t *testing.T, d time.Duration) {
	old := rekeyLockWait
	rekeyLockWait = d
	t.Cleanup(func() { rekeyLockWait = old })
}
