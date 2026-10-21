package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/client/internal/sign"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A box's identity signs certificates and revocations, and nothing else.
// What the box says,
// its prekey statements, its mail and its passes, is signed by a working key
// under a certificate the identity gave it (PROTOCOL.md §2b). This client
// keeps both keys in the box and makes a new working key, with a new
// certificate, each time it makes a new prekey: work/<n> is the working key
// made with prekey n, in the files ssh-keygen keeps for one,
//
//	work/<n>            the working key, OpenSSH format
//	work/<n>.pub        its public key
//	work/<n>-cert.pub   its certificate, serial n
//
// so "ssh-keygen -Y sign -f work/<n>-cert.pub" signs with it. The one in use
// is the one made with the prekey this box published last. Older ones are
// deleted once a newer prekey is published: the server then takes no pass
// under them, and what they signed is already signed.

func (b *Box) workStem(n uint64) string { return b.path("work", strconv.FormatUint(n, 10)) }

// makeWork makes working key n and its certificate, unless the box holds
// them, and returns the key's signer under the certificate.
func (b *Box) makeWork(n uint64) (*sign.Work, *protocol.Certificate, error) {
	stem := b.workStem(n)
	if exists(stem) && exists(stem+"-cert.pub") {
		return b.worker(n)
	}
	if err := os.MkdirAll(b.path("work"), 0o700); err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
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
// against the box's identity at the box's clock: a certificate that has
// ended signs nothing.
func (b *Box) worker(n uint64) (*sign.Work, *protocol.Certificate, error) {
	stem := b.workStem(n)
	pemBytes, err := os.ReadFile(stem) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, nil, fmt.Errorf("this box holds no working key %d: irongall prekey renew makes one: %w", n, err)
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d: %w", n, err)
	}
	work, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d: %w", n, err)
	}
	line, err := os.ReadFile(stem + "-cert.pub") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil, nil, fmt.Errorf("working key %d's certificate: %w", n, err)
	}
	cert, err := protocol.CheckCertificate(b.id, key, b.now())
	if errors.Is(err, protocol.ErrCertificateNotBegun) {
		return nil, nil, refuse("this box's certificate has not begun, by this machine's clock: the clock reads earlier than when the certificate was made. Check this machine's clock against a time source you trust. If the clock is right now and was ahead then, irongall prekey renew makes a new working key, certificate and prekey")
	}
	if errors.Is(err, protocol.ErrCertificateTime) {
		return nil, nil, refuse("this box's certificate has ended: irongall prekey renew makes a new working key, certificate and prekey")
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
// this box published last.
func (b *Box) currentWorker() (*sign.Work, *protocol.Certificate, error) {
	n, err := b.publishedSerial()
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, nil, errors.New("this box has published no prekey: irongall init registers it, and irongall prekey renew recovers one restored from its identity")
	}
	return b.worker(n)
}

// dropWork deletes every working key older than n.
func (b *Box) dropWork(n uint64) error {
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

// serverName is the server's name as this box calls it, which a pass names:
// the host of the server's URL, lowercase, and its port only when that is not
// the scheme's default, as an origin is written (RFC 6454 §6.2): the port as
// a number, and none for https on 443 or http on 80.
func (b *Box) serverName() (string, error) {
	u, err := url.Parse(b.base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("the server's URL %q has no host to name in a pass", b.base)
	}
	port := u.Port()
	name := strings.TrimSuffix(strings.ToLower(u.Host), ":"+port)
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", fmt.Errorf("the server's URL %q has no port to name in a pass", b.base)
		}
		if defaultPort[strings.ToLower(u.Scheme)] != n {
			name += ":" + strconv.FormatUint(n, 10)
		}
	}
	return name, protocol.CheckServerName(name)
}

// defaultPort is each scheme's own port, which an origin leaves unwritten.
var defaultPort = map[string]uint64{"https": 443, "http": 80}

// dropUnbegun deletes prekey n's statement and its working key, if the
// working key's certificate began less than protocol.MaxSkew before this
// machine's clock, so that both are made again. A client dates a certificate
// from MaxSkew before it makes it, so such a one was made while the clock
// read ahead of where it reads now, as a pass or an outbox entry made then is
// not used either (PROTOCOL.md §0): a reader whose clock a server takes may
// not have reached its start. The prekey's own key stays, and the new
// statement is for it: a box cannot know that a statement was never
// published (a server may have taken a registration whose answer was lost),
// so mail may be waiting that only this key opens.
func (b *Box) dropUnbegun(n uint64) error {
	line, err := os.ReadFile(b.workStem(n) + "-cert.pub")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil // not a certificate: whoever reads it next says so
	}
	if _, err := protocol.CheckCertificate(b.id, key, b.now().Add(-protocol.MaxSkew)); !errors.Is(err, protocol.ErrCertificateNotBegun) {
		return nil
	}
	stem := b.path("prekeys", strconv.FormatUint(n, 10))
	for _, name := range []string{stem + ".txt.sig", stem + ".made", stem + ".txt", b.workStem(n), b.workStem(n) + ".pub", b.workStem(n) + "-cert.pub"} {
		if err := removeIfExists(name); err != nil {
			return err
		}
	}
	return nil
}

// passMargin is how long a kept pass must still have to run to be used
// again: the time a call may take to reach the server.
const passMargin = 30 * time.Second

// pass returns the Authorization value for a call as this box: the pass kept
// in the box while it has more than passMargin left, and otherwise a new one,
// signed by the working key in use and kept. One pass serves every call for
// its ten minutes, so a server checks its signature once.
//
// A kept pass with more than PassLifetime left is not used: this box never
// signs one that long, so this machine's clock has gone back since it was
// signed. The new pass is dated by the clock as it is now, and a server
// refuses it if the clock is too far behind: a box whose clock is wrong is
// stopped at its pass, before it fetches mail it would judge by that clock.
//
// A box that holds its own revocation uses no pass, the kept one included:
// this is the one place a call gets its pass, so the check is here, and a
// new pass is the working key's signature, which sign refuses too.
func (b *Box) pass() (string, error) {
	if err := b.finished(); err != nil {
		return "", err
	}
	var kept []byte
	if err := b.view(func(s store) error { kept = s.get(bucketBox, "pass"); return nil }); err != nil {
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
func (b *Box) signPass(work *sign.Work) (string, error) {
	server, err := b.serverName()
	if err != nil {
		return "", err
	}
	h, _, err := work.Pass(b.id.Address(), server, b.now())
	return h, err
}

// keepPass keeps a pass in the box, for the calls that follow.
func (b *Box) keepPass(h string) error {
	return b.update(func(s store) error { return s.put(bucketBox, "pass", []byte(h)) })
}

// dropPass drops the pass the box keeps, so the next call signs another.
func (b *Box) dropPass() error {
	return b.update(func(s store) error { return s.del(bucketBox, "pass") })
}
