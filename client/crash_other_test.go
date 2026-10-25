//go:build !unix

package client_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// killSelf ends the crash test's child at once where there are no signals:
// os.Process.Kill, which is TerminateProcess on Windows and runs no deferred
// call, as SIGKILL does. Its exit status is one a test that fails has too, so
// the child says first where it dies.
func killSelf(step string) {
	fmt.Printf("killed at %s\n", step)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Kill()
	}
}

// killedAt is whether the child died of killSelf at step: it said so, and
// ended with no word after.
func killedAt(exit *exec.ExitError, out []byte, step string) bool {
	return exit.ExitCode() != 0 && bytes.HasSuffix(out, []byte("killed at "+step+"\n"))
}
