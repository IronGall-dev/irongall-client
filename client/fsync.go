//go:build !irongall_nofsync

package client

// fsync is whether a write is flushed to the disk before it is relied on. It is
// false only in a test build (-tags irongall_nofsync, scripts/check.sh): the
// tests kill a process, never the machine, so a flush changes nothing they can
// see, and on macOS each one is a full drive flush.
const fsync = true
