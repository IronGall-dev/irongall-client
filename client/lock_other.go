//go:build !unix

package client

import "os"

// staleDetect is false where there is no flock: the lock directory alone
// excludes other consumers, and a stale one must be removed by hand, as with
// the recipe.
const staleDetect = false

func flock(*os.File) error { return nil }
