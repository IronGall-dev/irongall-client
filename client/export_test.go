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

// SetDrainLimits lowers what one drain takes, for one test.
func SetDrainLimits(t *testing.T, messages, bytes, pages int) {
	m, b, p := maxDrainMessages, maxDrainBytes, maxDrainPages
	maxDrainMessages, maxDrainBytes, maxDrainPages = messages, bytes, pages
	t.Cleanup(func() { maxDrainMessages, maxDrainBytes, maxDrainPages = m, b, p })
}
