//go:build unix

package client_test

import (
	"os"
	"os/exec"
	"syscall"
)

// killSelf ends the crash test's child at once, with SIGKILL: no deferred
// call runs and nothing is flushed.
func killSelf(string) { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }

// killedAt is whether the child died of killSelf.
func killedAt(exit *exec.ExitError, _ []byte, _ string) bool {
	return exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL
}
