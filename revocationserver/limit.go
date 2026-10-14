package revocationserver

import (
	"sync"
	"time"
)

// maxCallers bounds what a limiter remembers. Past it, a caller it has no
// count for is refused until a period ends: the memory a limit takes is
// bounded whoever calls.
const maxCallers = 100_000

// limiter counts what each caller takes in a period: per a period, in a
// window that opens with the caller's first.
type limiter struct {
	per    int
	period time.Duration
	mu     sync.Mutex
	seen   map[string]*window
}

type window struct {
	opened time.Time
	n      int
}

// newLimiter returns a limiter of per a period; per below 1 limits nothing.
func newLimiter(per int, period time.Duration) *limiter {
	return &limiter{per: per, period: period, seen: map[string]*window{}}
}

// take counts one against key at now. It reports whether the caller is
// within its limit, and if not, how long until it is.
func (l *limiter) take(key string, now time.Time) (ok bool, wait time.Duration) {
	if l.per < 1 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.seen[key]
	if w != nil && now.Sub(w.opened) >= l.period {
		w = nil
	}
	if w == nil {
		if len(l.seen) >= maxCallers {
			l.sweep(now)
		}
		if len(l.seen) >= maxCallers {
			return false, l.period
		}
		w = &window{opened: now}
		l.seen[key] = w
	}
	if w.n >= l.per {
		return false, w.opened.Add(l.period).Sub(now)
	}
	w.n++
	return true, 0
}

// sweep forgets every caller whose window has closed.
func (l *limiter) sweep(now time.Time) {
	for k, w := range l.seen {
		if now.Sub(w.opened) >= l.period {
			delete(l.seen, k)
		}
	}
}
