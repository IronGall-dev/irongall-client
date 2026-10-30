package protocol

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Every check is exact at the verifier's own clock, and whoever makes a
// time-limited thing leaves MaxSkew of room (PROTOCOL.md §3.4). MaxSkew is the
// width of the clocks a server's pass check takes. This holds the claim
// itself, with the real checks: it finds the fastest and the slowest clock a
// server takes a new pass from, and then has the mailbox with the fastest clock
// make a certificate, a prekey statement and an envelope, and the server and
// the mailbox with the slowest clock check them.
func TestWhatAMailboxWithTheFastestClockMakesIsTakenByTheSlowest(t *testing.T) {
	b := newCertMailbox(t)
	server := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	const name = "dromas.example"
	taken := func(off time.Duration) bool { // is a mailbox whose clock is off by this much taken by the server?
		at := server.Add(off)
		cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 1, at)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := cert.Signer(b.work)
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := NewPass(signer, b.id.Address(), name, at)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePass(h)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Verify(b.id, name, server)
		return err == nil
	}
	// The edges, to the second.
	fastest, slowest := MaxPassLifetime-PassLifetime, -(PassLifetime - time.Second)
	if !taken(fastest) || taken(fastest+time.Second) || !taken(slowest) || taken(slowest-time.Second) {
		t.Fatalf("a server takes a pass from a clock %v fast: %v, a second more: %v; %v slow: %v, a second more: %v",
			fastest, taken(fastest), taken(fastest+time.Second), -slowest, taken(slowest), taken(slowest-time.Second))
	}
	if apart := fastest - slowest; apart >= MaxSkew {
		t.Fatalf("the two clocks furthest apart that a server takes are %v apart, and MaxSkew is %v", apart, MaxSkew)
	}

	fast, slow := server.Add(fastest), server.Add(slowest)
	// A certificate the fastest makes has begun for the slowest, and for the server.
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 1, fast)
	if err != nil {
		t.Fatal(err)
	}
	for who, at := range map[string]time.Time{"the slowest mailbox": slow, "the server": server} {
		if _, err := CheckCertificate(b.id, cert.PublicKey(), at); err != nil {
			t.Errorf("a certificate made by the fastest clock, checked by %s: %v", who, err)
		}
	}
	// A prekey statement the fastest signs is one the server publishes.
	if err := (&Prekey{NotAfter: fast.Add(PrekeyLifetime)}).CheckLifetime(server); err != nil {
		t.Errorf("a prekey statement signed by the fastest clock: %v", err)
	}
	// An envelope the fastest dates is one the slowest reads.
	other := newCertMailbox(t)
	env, err := NewEnvelope(b.id.Address(), other.id.Address(), "hello", fast)
	if err != nil {
		t.Fatal(err)
	}
	line, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnvelope(line, b.id.Address(), other.id.Address(), slow); err != nil {
		t.Errorf("an envelope dated by the fastest clock, read by the slowest: %v", err)
	}
	// And what the slowest makes is taken by the fastest: nothing it makes
	// has ended for a clock under an hour ahead.
	cert, err = NewCertificate(b.id, b.identity, b.work.PublicKey(), 2, slow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCertificate(b.id, cert.PublicKey(), fast); err != nil {
		t.Errorf("a certificate made by the slowest clock, checked by the fastest: %v", err)
	}
}

// A verdict on a certificate's dates is given only for one the identity
// signed. Bytes that name the identity as their signer and carry no
// signature of it are not "not begun": they are not the identity's.
func TestOnlyACertificateTheIdentitySignedIsJudgedByItsDates(t *testing.T) {
	b := newCertMailbox(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for name, change := range map[string]func(c *ssh.Certificate){
		"not begun": func(c *ssh.Certificate) { c.ValidAfter = uint64(now.Add(time.Hour).Unix()) },
		"ended":     func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 1, 2 },
	} {
		// Signed, then its dates changed: the signature no longer covers it.
		forged := b.rawCert(now)
		if err := forged.SignCert(rand.Reader, b.identity); err != nil {
			t.Fatal(err)
		}
		change(forged)
		if _, err := CheckCertificate(b.id, forged, now); !errors.Is(err, ErrCertificate) || errors.Is(err, ErrCertificateTime) {
			t.Errorf("%s, and not signed as it stands: %v, want a bad certificate and no verdict on its dates", name, err)
		}
		// Control: the same dates under the identity's signature get the verdict on the dates.
		signed := b.rawCert(now)
		change(signed)
		if err := signed.SignCert(rand.Reader, b.identity); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckCertificate(b.id, signed, now); !errors.Is(err, ErrCertificateTime) {
			t.Errorf("%s, signed: %v, want a verdict on its dates", name, err)
		}
	}
}

// A certificate starts MaxSkew before it is made, so a verifier whose clock
// is that far behind its maker's takes it at once, and one a second further
// behind does not.
func TestACertificateStartsMaxSkewBeforeItIsMade(t *testing.T) {
	b := newCertMailbox(t)
	made := time.Date(2026, 10, 13, 12, 0, 30, 0, time.UTC)
	cert, err := NewCertificate(b.id, b.identity, b.work.PublicKey(), 1, made)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		at   time.Time
		want error
	}{
		{made, nil},
		{made.Add(-MaxSkew), nil},
		{made.Add(-MaxSkew - time.Second), ErrCertificateNotBegun},
		{made.Add(CertificateLifetime - time.Second), nil},
		{made.Add(CertificateLifetime), ErrCertificateEnded},
	} {
		if _, err := CheckCertificate(b.id, cert.PublicKey(), c.at); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("checked %v after it was made: %v, want %v", c.at.Sub(made), err, c.want)
		}
	}
	// Each of the two is the class a caller already handles.
	if !errors.Is(ErrCertificateNotBegun, ErrCertificateTime) || !errors.Is(ErrCertificateEnded, ErrCertificateTime) || errors.Is(ErrCertificateEnded, ErrCertificateNotBegun) {
		t.Error("not begun and ended are not two kinds of ErrCertificateTime")
	}
}

// A server takes a prekey that ends up to MaxSkew past what a client asks
// for: a client whose clock is ahead of the server's by less than that is
// not refused, and a statement a second longer is.
func TestAPrekeyIsTakenUpToMaxSkewPastWhatAClientAsksFor(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for d, ok := range map[time.Duration]bool{
		time.Second:                    true,
		PrekeyLifetime:                 true,
		PrekeyLifetime + 2*time.Second: true, // a client two seconds fast
		PrekeyLifetime + MaxPassLifetime - PassLifetime: true, // the fastest clock a pass is taken from
		PrekeyLifetime + MaxSkew:                        true,
		PrekeyLifetime + MaxSkew + time.Second:          false,
		0:                                               false,
	} {
		p := &Prekey{NotAfter: now.Add(d)}
		if err := p.CheckLifetime(now); (err == nil) != ok {
			t.Errorf("a prekey ending %v from now: %v, want taken=%v", d, err, ok)
		}
	}
}
