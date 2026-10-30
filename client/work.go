package client

import (
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/client/internal/sign"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A mailbox's identity signs certificates and revocations, and nothing else.
// What the mailbox says,
// its prekey statements, its messages and its passes, is signed by a working key
// under a certificate the identity gave it (PROTOCOL.md §5). This client
// keeps both keys in the mailbox and makes a new working key, with a new
// certificate, each time it makes a new prekey: work/<n> is the working key
// made with prekey n, in the files ssh-keygen keeps for one,
//
//	work/<n>            the working key, OpenSSH format
//	work/<n>.pub        its public key
//	work/<n>-cert.pub   its certificate, serial n
//
// so "ssh-keygen -Y sign -f work/<n>-cert.pub" signs with it. The one in use
// is the one made with the prekey this mailbox published last. Older ones are
// deleted once a newer prekey is published: the server then takes no pass
// under them, and what they signed is already signed.

func (b *Mailbox) workStem(n uint64) string { return b.path("work", strconv.FormatUint(n, 10)) }

// makeWork makes working key n and its certificate, new whatever the mailbox
// holds of them, and returns the key's signer under the certificate: it is
// called for a statement not yet signed, which nothing the mailbox holds of n has
// signed either.
func (b *Mailbox) makeWork(n uint64) (*sign.Work, *protocol.Certificate, error) {
	stem := b.workStem(n)
	if err := os.MkdirAll(b.path("work"), 0o700); err != nil {
		return nil, nil, err
	}
	priv, err := newKey(protocol.WorkingKeyType(b.id.Type()))
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, err
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, nil, err
	}
	cert, err := b.identity.Certify(b.id, sshPub, n, b.now())
	if err != nil {
		return nil, nil, err
	}
	// The certificate last: a key with no certificate is one that signed
	// nothing, and is made again.
	if err := writeFile(stem, pem.EncodeToMemory(block)); err != nil {
		return nil, nil, err
	}
	if err := writeFile(stem+".pub", ssh.MarshalAuthorizedKey(sshPub)); err != nil {
		return nil, nil, err
	}
	if err := writeFile(stem+"-cert.pub", ssh.MarshalAuthorizedKey(cert.PublicKey())); err != nil {
		return nil, nil, err
	}
	return b.worker(n)
}

// worker returns working key n's signer under its certificate, checked
// against the mailbox's identity at the mailbox's clock: a certificate that has
// ended signs nothing.
func (b *Mailbox) worker(n uint64) (*sign.Work, *protocol.Certificate, error) {
	stem := b.workStem(n)
	pemBytes, err := os.ReadFile(stem) //nolint:gosec // a path inside the mailbox's own directory
	if err != nil {
		return nil, nil, fmt.Errorf("this mailbox holds no working key %d: dromas prekey renew makes one: %w", n, err)
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d: %w", n, err)
	}
	work, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d: %w", n, err)
	}
	line, err := os.ReadFile(stem + "-cert.pub") //nolint:gosec // a path inside the mailbox's own directory
	if err != nil {
		return nil, nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d's certificate: %w", n, err)
	}
	cert, err := protocol.CheckCertificate(b.id, key, b.now())
	if errors.Is(err, protocol.ErrCertificateNotBegun) {
		return nil, nil, refuse("this mailbox's certificate has not begun, by this machine's clock: the clock reads earlier than when the certificate was made. Check this machine's clock against a time source you trust. If the clock is right now and was ahead then, dromas prekey renew makes a new working key, certificate and prekey")
	}
	if errors.Is(err, protocol.ErrCertificateTime) {
		return nil, nil, refuse("this mailbox's certificate has ended: dromas prekey renew makes a new working key, certificate and prekey")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d's certificate: %w", n, err)
	}
	signer, err := cert.Signer(work)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d does not match its certificate: %w", n, err)
	}
	return sign.NewWork(signer, b.finished), cert, nil
}

// currentWorker returns the working key in use: the one made with the prekey
// this mailbox published last.
func (b *Mailbox) currentWorker() (*sign.Work, *protocol.Certificate, error) {
	n, err := b.publishedSerial()
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, nil, errors.New("this mailbox has published no prekey: dromas init registers it, and dromas prekey renew recovers one restored from its identity")
	}
	return b.worker(n)
}

// dropWork deletes every working key older than n.
func (b *Mailbox) dropWork(n uint64) error {
	names, err := filepath.Glob(b.path("work", "*-cert.pub"))
	if err != nil {
		return err
	}
	for _, name := range names {
		k, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), "-cert.pub"), 10, 64)
		if err != nil || k >= n {
			continue
		}
		for _, ext := range []string{"", ".pub", "-cert.pub"} {
			if err := removeIfExists(b.workStem(k) + ext); err != nil {
				return err
			}
		}
	}
	return nil
}

// serverName is the server's name as this mailbox calls it, which a pass names:
// the host of the server's URL, lowercase in ASCII (protocol.LowerASCII: a
// host with a letter only Unicode's rules lower names no server), and its
// port only when that is not the scheme's default, as an origin is written
// (RFC 6454 §6.2): the port as a number, and none for https on 443 or http
// on 80.
func (b *Mailbox) serverName() (string, error) {
	u, err := url.Parse(b.base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("the server's URL %q has no host to name in a pass", b.base)
	}
	port := u.Port()
	name := strings.TrimSuffix(protocol.LowerASCII(u.Host), ":"+port)
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", fmt.Errorf("the server's URL %q has no port to name in a pass", b.base)
		}
		if defaultPort[protocol.LowerASCII(u.Scheme)] != n {
			name += ":" + strconv.FormatUint(n, 10)
		}
	}
	return name, protocol.CheckServerName(name)
}

// defaultPort is each scheme's own port, which an origin leaves unwritten.
var defaultPort = map[string]uint64{"https": 443, "http": 80}

// passMargin is how long a kept pass must still have to run to be used
// again: the time a call may take to reach the server.
const passMargin = 30 * time.Second

// pass returns the Authorization value for a call as this mailbox: the pass kept
// in the mailbox while it has more than passMargin left, and otherwise a new one,
// signed by the working key in use and kept. One pass serves every call for
// its ten minutes, so a server checks its signature once.
//
// A kept pass with more than PassLifetime left is not used: this mailbox never
// signs one that long, so this machine's clock has gone back since it was
// signed. The new pass is dated by the clock as it is now, and a server
// refuses it if the clock is too far behind: a mailbox whose clock is wrong is
// stopped at its pass, before it fetches messages it would judge by that clock.
//
// A mailbox that holds its own revocation uses no pass, the kept one included:
// this is the one place a call gets its pass, so the check is here, and a
// new pass is the working key's signature, which sign refuses too.
func (b *Mailbox) pass() (string, error) {
	if err := b.finished(); err != nil {
		return "", err
	}
	var kept []byte
	if err := b.view(func(s store) error { kept = s.get(bucketMailbox, "pass"); return nil }); err != nil {
		return "", err
	}
	if p, err := protocol.ParsePass(string(kept)); err == nil && p.Address == b.id.Address() {
		if left := p.NotAfter.Sub(b.now()); left > passMargin && left <= protocol.PassLifetime {
			return string(kept), nil
		}
	}
	work, _, err := b.currentWorker()
	if err != nil {
		return "", err
	}
	h, err := b.signPass(work)
	if err != nil {
		return "", err
	}
	return h, b.keepPass(h)
}

// signPass signs a pass with work, a working key under its certificate.
func (b *Mailbox) signPass(work *sign.Work) (string, error) {
	server, err := b.serverName()
	if err != nil {
		return "", err
	}
	h, _, err := work.Pass(b.id.Address(), server, b.now())
	return h, err
}

// keepPass keeps a pass in the mailbox, for the calls that follow.
func (b *Mailbox) keepPass(h string) error {
	return b.update(func(s store) error { return s.put(bucketMailbox, "pass", []byte(h)) })
}

// dropPass drops the pass the mailbox keeps, so the next call signs another.
func (b *Mailbox) dropPass() error {
	return b.update(func(s store) error { return s.del(bucketMailbox, "pass") })
}
