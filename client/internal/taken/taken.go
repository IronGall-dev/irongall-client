// Package taken is a reading of a box's clock that a server took: the date of
// a pass it checked, on a call it answered, the pass's not_after less
// protocol.PassLifetime. Every deletion by the clock is by one, and never by
// a reading of the clock (PROTOCOL.md §12.4): a box whose clock is far off is
// stopped at its pass, and one whose clock jumps or steps back while a call
// is in flight deletes nothing by where it went. A pass is the only way to a
// Reading, so no path of the client, a new one included, deletes by a reading
// no server saw.
package taken

import (
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Reading is a reading of the box's clock a server took. Its zero value is
// none: no server answered, and it is before every time, so it deletes
// nothing.
type Reading struct{ at time.Time }

// By is the reading pass is dated by, for a call the server answered.
func By(pass string) (Reading, error) {
	p, err := protocol.ParsePass(pass)
	if err != nil {
		return Reading{}, err
	}
	return Reading{p.NotAfter.Add(-protocol.PassLifetime)}, nil
}

// At is the reading, or the zero time for none.
func (r Reading) At() time.Time { return r.at }

// None reports whether r is no reading: no server answered.
func (r Reading) None() bool { return r.at.IsZero() }
