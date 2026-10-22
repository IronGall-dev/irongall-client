//go:build !unix

package client

import "os"

// tryGate is no gate where a directory cannot be flocked: a waiting writer
// has no preference over readings there.
func tryGate(string) (*os.File, bool, error) { return nil, true, nil }
