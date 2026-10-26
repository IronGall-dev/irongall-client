//go:build !unix && !windows

package client

import "os"

// tryGate is noGate where a directory cannot be flocked.
func tryGate(dir string) (*os.File, bool, error) { return noGate(dir) }
