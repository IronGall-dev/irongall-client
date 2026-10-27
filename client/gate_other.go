//go:build !(darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd) && !windows

package client

import "os"

// tryGate is noGate where a directory cannot be flocked: a system neither
// Windows nor one of gate_unix.go's.
func tryGate(dir string) (*os.File, bool, error) { return noGate(dir) }
