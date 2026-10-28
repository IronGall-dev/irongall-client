package sh_test

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The clock: every check is exact at the clock of whoever makes it, and what
// a box makes leaves an hour of room. The server keeps the machine's clock;
// a box's is dr_now.

// at is a box on a clock off from the machine's.
type at struct {
	*sbox
	off time.Duration
}

func (b at) sh(cmd string) ran {
	b.w.t.Helper()
	return b.sbox.sh(igNow(b.off) + cmd)
}

func (b at) must(cmd string) string {
	b.w.t.Helper()
	return b.sbox.must(igNow(b.off) + cmd)
}

func (b at) recv() drain {
	b.w.t.Helper()
	return b.sbox.recv(igNow(b.off))
}

func (b at) now() int64 { return time.Now().Add(b.off).Unix() }

// A box whose clock is 9 minutes slow, or 49 fast, registers, renews, and
// exchanges mail with a box made that moment: its certificate starts an hour
// back. One 11 minutes slow is refused at its pass and told what its clock
// reads beside the server's word.
func TestScriptAtTheEdgesOfAClock(t *testing.T) {
	w := newWorld(t)
	for _, off := range []time.Duration{-9 * time.Minute, 49 * time.Minute} {
		s := at{w.empty(), off}
		s.must("dr_init")
		s.addr = mustAddress(t, s.dir)
		var serial, start, end int64
		if _, err := fmt.Sscan(s.must(fmt.Sprintf(`dr_cert "$DR/prekeys/%d.txt.sig" "$DR/identity.doc" %s`, s.num(), s.addr)), &serial, &start, &end); err != nil || s.now()-start < 3600 || s.now()-start > 3660 {
			t.Errorf("%v: the certificate does not start an hour before it was made: %d, %v", off, start, err)
		}
		f := w.box()
		f.mustSend(s.sbox, "to the box whose clock is off")
		if d := s.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"to the box whose clock is off"}) {
			t.Errorf("%v: it reads: %v", off, d)
		}
		if r := s.sh("printf 'from the box whose clock is off' | dr_send " + f.addr.String()); r.rc != 0 {
			t.Errorf("%v: it sends: %v", off, r)
		}
		if r := s.sh("dr_rekey"); r.rc != 0 {
			t.Errorf("%v: it renews: %v", off, r)
		}
		if d := f.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"from the box whose clock is off"}) {
			t.Errorf("%v: its mail is read: %v", off, d)
		}
	}
	slow := at{w.empty(), -11 * time.Minute}
	r := slow.sh("dr_init")
	if r.rc == 0 || !strings.Contains(r.err, "pass_expired") || !strings.Contains(r.err, "the server dates its answer 20") || strings.Contains(r.err, "has run out") ||
		!regexp.MustCompile(`this machine's clock reads .*Check this machine's clock against a time source you trust, not against the server`).MatchString(r.err) || strings.Contains(strings.ToLower(r.err), "set this machine's clock") {
		t.Errorf("a box 11 minutes slow: %v", r)
	}
}

// A box first made, or renewed, while its clock read over an hour ahead, or
// 55 minutes: refused, and with the clock right it registers again under a
// new certificate, for the same prekey, and a renewal it left is spent; a
// serial never goes back.
func TestScriptAfterAClockAhead(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct {
		ahead time.Duration
		code  string
	}{{61 * time.Minute, "prekey_time"}, {55 * time.Minute, "prekey_time"}} { // its certificate not begun protocol.PassLifetime before the server's clock, which it reads before the pass
		b := at{w.empty(), c.ahead}
		if r := b.sh("dr_init"); r.rc == 0 || !strings.Contains(r.err, c.code) {
			t.Fatalf("a box %v fast registered: %v", c.ahead, r)
		}
		f1 := b.newest()
		k1, a1 := b.read(fmt.Sprintf("work/%d.pub", f1)), b.read(fmt.Sprintf("prekeys/%d.agekey", f1))
		right := at{b.sbox, 0}
		right.must("dr_init")
		b.addr = mustAddress(t, b.dir)
		if b.read(fmt.Sprintf("work/%d.pub", f1)) == k1 || b.read(fmt.Sprintf("prekeys/%d.agekey", f1)) != a1 || b.num() != f1 {
			t.Errorf("%v: with the clock right, not a new first certificate for the same prekey at %d: serial %d", c.ahead, f1, b.num())
		}
		ahead := at{b.sbox, c.ahead}
		if c.ahead > time.Hour {
			ahead.off = 2 * time.Hour
		}
		s0, t0 := b.num(), ahead.now()
		if r := ahead.sh("dr_rekey"); r.rc == 0 {
			t.Fatalf("a renewal signed %v ahead was taken", ahead.off)
		}
		m := b.newest()
		if m <= s0 || c.ahead > time.Hour && int64(m) < t0 {
			t.Errorf("%v: the renewal left no statement numbered by that clock: %d after %d, at %d", ahead.off, m, s0, t0)
		}
		right.must("dr_rekey")
		if p, _ := w.served(b.sbox); b.num() != m+1 || p != m+1 {
			t.Errorf("%v: the renewal with the clock right is not one above the spent one, %d: %d, served %d", ahead.off, m, b.num(), p)
		}
	}
}

// A box's number is its machine's clock once the clock has passed the last
// number, and one above the last when it has not.
func TestScriptNumbersByTheClock(t *testing.T) {
	w := newWorld(t)
	b := w.box()
	n1 := b.num()
	fast := at{b, 90 * time.Second}
	fast.must("dr_rekey")
	n2 := b.num()
	if _, c := w.served(b); int64(n2) > fast.now() || int64(n2) < fast.now()-30 || n2 <= n1+60 || c != n2 {
		t.Errorf("a renewal 90 seconds on: %d after %d, the certificate served %d", n2, n1, c)
	}
	at{b, -90 * time.Second}.must("dr_rekey")
	if p, c := w.served(b); b.num() != n2+1 || p != n2+1 || c != n2+1 {
		t.Errorf("a renewal with the clock behind its last number: %d after %d, served %d under %d", b.num(), n2, p, c)
	}
}

// A send from a clock two hours fast is refused at its pass and keeps
// nothing; a kept pass is not used once the clock has gone back; mail dated
// more than an hour ahead of its reader is refused as future.
func TestScriptSendsAndReadsByItsClock(t *testing.T) {
	w := newWorld(t)
	p, q := w.box(), w.box()
	if r := (at{p, 2 * time.Hour}).sh("printf 'dated two hours ahead' | dr_send " + q.addr.String()); r.rc == 0 || !strings.Contains(r.err, "pass_expired") || !p.bare() {
		t.Errorf("a send from a clock two hours fast: %v", r)
	}
	if d := q.recv(); len(d.mail) != 0 || strings.Contains(d.said, "future") || w.srv.Count(q.addr) != 0 {
		t.Errorf("its reader was sent something: %v", d)
	}
	p.must("dr_pass > /dev/null")
	if kept := p.read("pass"); (at{p, -30 * time.Minute}).must("dr_pass") == kept {
		t.Error("the kept pass was used after the clock went back")
	}
	l := p.line(q.addr, "00000000-0000-4000-8000-0000000000f1", "dated ahead", -3700*time.Second)
	w.inject(q, "", l, p.sign(q.addr, l))
	if d := q.recv(); len(d.mail) != 0 || !strings.Contains(d.said, "future: sent_at is more than 60 minutes ahead") {
		t.Errorf("sent_at more than an hour ahead of the reader's clock: %v", d)
	}
}

// The replay set: pruned by the box's clock only once the server has taken a
// pass dated by it, a line kept 66 days and an hour from its sent_at, and a
// floor below which mail is stale whatever the clock reads.
func TestScriptKeepsItsReplaySetByItsClock(t *testing.T) {
	w := newWorld(t)
	p, q := w.box(), w.box()
	l := p.line(q.addr, "00000000-0000-4000-8000-0000000000f2", "pay invoice 7 once", 33*24*time.Hour-49*time.Minute)
	sig := p.sign(q.addr, l)
	oid := w.inject(q, "", l, sig)
	if d := q.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"pay invoice 7 once"}) {
		t.Fatalf("the first delivery: %v", d)
	}
	if d := (at{q, 50 * time.Minute}).recv(); d.rc != 0 { // 33 days and a minute old by this clock, which a server takes
		t.Fatalf("a drain 50 minutes fast: %v", d)
	}
	w.inject(q, oid, l, sig)
	if d := (at{q, -9 * time.Minute}).recv(); len(d.mail) != 0 || d.rc != 0 || !strings.Contains(q.read("seen"), oid+" ") || q.has("seen-floor") {
		t.Errorf("the server's replay of it after the clock stepped back: %v", d)
	}
	seen := q.read("seen")
	if d := (at{q, 70 * 24 * time.Hour}).recv(); d.rc == 0 || q.read("seen") != seen || q.has("seen-floor") {
		t.Errorf("a recv refused for a clock 70 days fast pruned: %v", d)
	}
	old := fmt.Sprintf("%064d", 7)
	q.must(fmt.Sprintf(`printf '%%s %%s %%s %%s\n' %s %d %s 00000000-0000-4000-8000-0000000000f3 >> "$DR/seen"`, old, time.Now().Add(-67*24*time.Hour).Unix(), p.addr))
	t0 := time.Now().Add(-66*24*time.Hour - time.Hour).Unix()
	q.recv()
	f, err := strconv.ParseInt(strings.TrimSpace(q.read("seen-floor")), 10, 64)
	if err != nil || f < t0 || f > t0+5 || strings.Contains(q.read("seen"), old+" ") || !strings.Contains(q.read("seen"), oid+" ") {
		t.Errorf("the floor after a prune: %q, the cutoff %d", q.read("seen-floor"), t0)
	}
	writeFile(t, q.file("seen-floor"), fmt.Appendf(nil, "%d\n", time.Now().Unix()+100))
	under := p.line(q.addr, "00000000-0000-4000-8000-0000000000f4", "under the floor", 0)
	w.inject(q, "", under, p.sign(q.addr, under))
	if d := q.recv(); len(d.mail) != 0 || !strings.Contains(d.said, "stale: sent_at is before this box's replay set reaches back to") {
		t.Errorf("mail under the floor: %v", d)
	}
	writeFile(t, q.file("seen-floor"), []byte("soon\n"))
	none := p.line(q.addr, "00000000-0000-4000-8000-0000000000f5", "a floor that names no time", 0)
	w.inject(q, "", none, p.sign(q.addr, none))
	if d := q.recv(); d.rc == 0 || len(d.mail) != 0 || !strings.Contains(d.said, "seen-floor names no time") || w.srv.Count(q.addr) != 1 {
		t.Errorf("a seen-floor that names no time: %v", d)
	}
	q.must(`rm "$DR/seen-floor"`)
	if d := q.recv(); !slices.Equal(d.bodies(), []string{"a floor that names no time"}) {
		t.Errorf("the drain once the floor is gone: %v", d)
	}
}
