package revocationserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// store keeps one record for each address, as one file: the record a client
// keeps and a revocation server takes (PROTOCOL.md §6.3), as one line of JSON, at
// <dir>/<first two hex characters>/<address>.json. A file is written whole
// and moved into place, so a reader sees the record before or the record
// after, and a list is never kept without its signature.
//
// Which addresses have a file is held in memory, read from the directory
// once, when the server opens. Nearly every address a revocation server is
// asked about has no record, and that answer costs no read of the disk.
type store struct {
	dir  string
	lock *os.File
	mu   sync.RWMutex
	held map[protocol.Address]struct{}
}

// openStore opens the store in dir, making the directory if it is not there,
// and reads which addresses it holds. One process uses a directory at a
// time: a second would not know what the first had kept.
func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // a path inside the server's own directory
	if err != nil {
		return nil, err
	}
	if err := flock(lock); err != nil {
		lock.Close() //nolint:errcheck,gosec // the lock error wins
		return nil, fmt.Errorf("%s is in use by another revocation server: %w", dir, err)
	}
	s := &store{dir: dir, lock: lock, held: map[protocol.Address]struct{}{}}
	names, err := filepath.Glob(filepath.Join(dir, "??", "*.json"))
	if err != nil {
		lock.Close() //nolint:errcheck,gosec // the glob error wins
		return nil, err
	}
	for _, n := range names {
		// Only a file this store would have written, where it would have
		// written it: anything else in the directory is not a record.
		a, err := protocol.ParseAddress(strings.TrimSuffix(filepath.Base(n), ".json"))
		if err == nil && n == s.file(a) {
			s.held[a] = struct{}{}
		}
	}
	return s, nil
}

func (s *store) close() error { return s.lock.Close() }

func (s *store) file(a protocol.Address) string {
	h := a.String()
	return filepath.Join(s.dir, h[:2], h+".json")
}

func (s *store) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.held)
}

// read returns the record held for a, or nil. An address with no record is
// answered from memory. A file that is not a record is an error, never a
// quiet "nothing held".
func (s *store) read(a protocol.Address) (*protocol.Revocations, error) {
	s.mu.RLock()
	_, ok := s.held[a]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	raw, err := os.ReadFile(s.file(a))
	if err != nil {
		return nil, err
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil || rec.Identity == nil || (rec.Revocation == nil && rec.RevokedCertificates == nil) {
		return nil, fmt.Errorf("the file kept for %s is not a record", a)
	}
	return &rec, nil
}

// write keeps rec as the record of a, in place of any before it, and is
// durable when it returns.
func (s *store) write(a protocol.Address, rec *protocol.Revocations) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	name := s.file(a)
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(append(line, '\n')); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the write error wins
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the sync error wins
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		return err
	}
	// The file is there from the rename on, whatever the sync says.
	s.mu.Lock()
	s.held[a] = struct{}{}
	s.mu.Unlock()
	return syncDir(filepath.Dir(name))
}
