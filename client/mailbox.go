package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/client/internal/sign"
	tk "github.com/dromas-dev/dromas-client/client/internal/taken"
	"github.com/dromas-dev/dromas-client/protocol"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// DefaultBase is the server every mailbox talks to unless told otherwise.
const DefaultBase = "https://dromas.dev"

// EchoAddress is the echo mailbox dromas.dev runs (cmd/dromas-echo): send
// it anything, and it answers with a signed reply saying what it checked and
// carrying the body back. Its prekey is post-quantum. A message to it is readable
// by dromas.dev's operator, who runs it.
const EchoAddress = "82be51e181471140db80904d4992a99383028c1fbc92e1f53614341def8c2225"

// EchoAddressNoPQ is dromas.dev's second echo mailbox, whose prekey is X25519
// only: the one a sender on age 1.2 can reach (sh/dromas.sh; this client
// reaches both). It answers as EchoAddress does, and a message to it is as
// readable by dromas.dev's operator.
const EchoAddressNoPQ = "518a0a89c533354f0d5a890599722a86d01b9b2d8c87549bb24c3276e819048c"

// requestTimeout bounds a request of the default HTTP client (stall): the
// bytes of a ciphertext it sends or fetches, by how long they may go with
// none moving, and the rest of that request, and any other, whole. A var
// for a test (SetRequestTimeout).
var requestTimeout = time.Minute

// Options configures a [Mailbox]. The zero value is ready to use.
type Options struct {
	// Base is the server's base URL; DefaultBase if empty. It is https, or
	// http only to a server on this machine ([checkServerURL]).
	Base string
	// HTTPClient makes the requests; if nil, a client that cuts a request
	// after a minute, so a server that stops answering cannot hold the mailbox's
	// lock for ever: a send or a fetch of a ciphertext once a minute passes
	// with no byte of it moving, the wait for its answer's head among them,
	// with no bound on the whole, so a message of any size moves on a slow
	// link (#381); the rest of such a request, a send's answer once its
	// ciphertext is sent and a fetch's answer that is not its ciphertext, and
	// any other request, after a minute in all. A client
	// given here is used as it is, its own timeouts its choice, and none of
	// those bounds is added. The mailbox uses a copy of it that follows no
	// redirect ([followNone]).
	HTTPClient *http.Client
	// Now is the clock; time.Now if nil.
	Now func() time.Time
	// IdentityType is the type of identity key Init makes for a new mailbox:
	// protocol.IdentityEd25519 if empty, and that is the one to use. Every
	// client verifies an Ed25519 identity; a mailbox of any other type can
	// neither send to nor receive from a mailbox whose client does not verify
	// that type. An existing identity key is used as it is, whatever this
	// says.
	IdentityType string
	// SenderKeyTypes is what the mailbox declares with each prekey it
	// publishes: the identity key types of the senders it takes messages from
	// (protocol.AcceptsSender). Nil: every type this client verifies, which
	// is the one to use. The one entry protocol.AnySender is for a mailbox that
	// would not show which types it verifies: the server then takes messages
	// for it from a sender of any type, and this client refuses what it
	// cannot verify.
	SenderKeyTypes []string
	// Waiting, if not nil, is told when a command finds the mailbox's lock held
	// by another command of the mailbox, once, before it waits for it: a mailbox's
	// commands write its files one at a time.
	Waiting func()
	// DrainTime is how long one Receive drains while bytes move, holding the
	// mailbox's lock: past it the drain stops, as at its other limits
	// (Result.More), and a fetch under way keeps what it read for the next
	// Receive to go on from. Zero is DefaultDrainTime.
	DrainTime time.Duration
	// Version is the version every request names in Dromas-Version
	// (PROTOCOL.md §11.17): the function [Version] if empty, and that is the one to
	// use. Another is for a test, and must be of a request's form
	// (protocol.ParseVersion).
	Version string
	// Versions, if not nil, keeps what every mailbox made with these options
	// meets of its version, for the caller to say once its command is done
	// ([Versions]). Otherwise each Mailbox keeps its own.
	Versions *Versions
}

// Mailbox is one mailbox: its state directory and the server it talks to. It is
// safe for concurrent use: a command or reading of one goroutine waits for
// another's, as one of another process does.
type Mailbox struct {
	dir  string
	base string
	http *http.Client
	// stall is set where http is the default client, whose requests are
	// bounded by requestTimeout (stall); one given is used as it is.
	stall bool
	now   func() time.Time
	// identity is the identity key, which signs certificates and revocations
	// and nothing else, and none once the mailbox is finished (sign).
	identity *sign.Identity
	id       *protocol.Identity
	// identityType is the type of key Init makes when the mailbox has none.
	identityType string
	// senderKeyTypes is what the mailbox declares with each prekey it publishes.
	senderKeyTypes []string
	// waiting is told when a command waits for the mailbox's lock ([Mailbox.hold]).
	waiting func()
	// drainTime bounds a Receive's drain (Options.DrainTime).
	drainTime time.Duration
	// db is the mailbox's state file while a command holds it ([Mailbox.hold]) or a
	// reading has it open read-only ([reading]), and tx the transaction of
	// it under way ([Mailbox.view], [Mailbox.update]). A Mailbox runs one command or
	// reading at a time ([Mailbox.claim]).
	db *bolt.DB
	tx *bolt.Tx
	// none is set while a reading runs whose open found no state file
	// ([reading]): each of its views reads nothing ([Mailbox.view]).
	none bool
	// slot is held by the one command or reading of this Mailbox under way, of
	// whichever goroutine ([Mailbox.claim]).
	slot chan struct{}
	// ended is this mailbox's own revocation once the command under way has kept
	// it, having begun with none (keepRevocation): that command asks nothing
	// more (call), and returns it (locked). Each command begins with none.
	ended *RevokedError
	// holding is what the mailbox has learned of its network while it holds
	// its list (Hold), which the default client's connections follow.
	holding holding
	// version is the version every request names (Options.Version), and met
	// what the answers to them said of it (Versions).
	version string
	met     *Versions
}

// Open opens an existing mailbox's state directory, its owner's alone as Init
// leaves it (makeDirs). A directory holding only the identity, a mailbox
// restored from its backup, gets the mailbox's other directories; [Mailbox.Rekey]
// then gives it a working key and a prekey, and
// the lists its server's ACL holds when it has none of its own.
func Open(dir string, opt Options) (*Mailbox, error) {
	b, err := newMailbox(dir, opt)
	if err != nil {
		return nil, err
	}
	if err := b.loadIdentity(); err != nil {
		return nil, err
	}
	if err := b.makeDirs(); err != nil {
		return nil, err
	}
	return b, nil
}

// newMailbox is how every mailbox is made, its directory read or not: its server's
// URL is held to checkServerURL, and an identity type to the ones this client
// makes, before anything is done, so Init writes nothing for either, and its
// HTTP client takes every request through one transport (newTransport) and
// follows no redirect (followNone).
func newMailbox(dir string, opt Options) (*Mailbox, error) {
	b := &Mailbox{dir: dir, base: strings.TrimRight(opt.Base, "/"), http: opt.HTTPClient, now: opt.Now, identityType: opt.IdentityType, senderKeyTypes: opt.SenderKeyTypes, waiting: opt.Waiting, slot: make(chan struct{}, 1)}
	if b.senderKeyTypes == nil {
		b.senderKeyTypes = protocol.IdentityTypes()
	}
	if b.base == "" {
		b.base = DefaultBase
	}
	if err := checkServerURL(b.base); err != nil {
		return nil, err
	}
	if b.identityType != "" && !slices.Contains(protocol.IdentityTypes(), b.identityType) {
		return nil, fmt.Errorf("this client makes no identity key of type %q: %s", b.identityType, strings.Join(protocol.IdentityTypes(), " or "))
	}
	if b.http == nil {
		b.http, b.stall = &http.Client{Transport: defaultTransport(&b.holding)}, true
	} else {
		c := *b.http
		b.http = &c
	}
	b.http.Transport = newTransport(b.http.Transport)
	b.http.CheckRedirect = followNone
	if b.now == nil {
		b.now = time.Now
	}
	b.drainTime = opt.DrainTime
	if b.drainTime <= 0 {
		b.drainTime = DefaultDrainTime
	}
	b.version = opt.Version
	if b.version == "" {
		b.version = Version()
	} else if _, err := protocol.ParseVersion(b.version); err != nil {
		return nil, fmt.Errorf("%.80q is not a version a request names: MAJOR.MINOR.PATCH and an optional pre-release, with no v", b.version)
	}
	b.met = opt.Versions
	if b.met == nil {
		b.met = &Versions{}
	}
	b.met.mu.Lock()
	b.met.own, b.met.now = b.version, b.now
	b.met.mu.Unlock()
	return b, nil
}

// transport is every mailbox's: it holds each request's URL to checkServerURL,
// whatever made the request, before anything is sent.
type transport struct{ next http.RoundTripper }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := checkServerURL(r.URL.Scheme + "://" + r.URL.Host); err != nil {
		return nil, err
	}
	return t.next.RoundTrip(r)
}

// newTransport is rt, or net/http's default, held to checkServerURL
// (transport). A transport of net/http's own type calls a server on this
// machine, or one named localhost in any case, through no proxy, whatever
// the environment names (PROTOCOL.md §11.1): Go's ProxyFromEnvironment
// exempts only the exact name localhost.
func newTransport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if ht, ok := rt.(*http.Transport); ok {
		c := ht.Clone()
		proxy := c.Proxy
		c.Proxy = func(r *http.Request) (*url.URL, error) {
			if h := protocol.LowerASCII(r.URL.Hostname()); h == "localhost" || onThisMachine(h) || proxy == nil {
				return nil, nil
			}
			return proxy(r)
		}
		rt = c
	}
	return transport{rt}
}

// followNone is every mailbox's redirect policy: a 3xx comes back as the answer
// it is, an [*APIError]. The API redirects nowhere (PROTOCOL.md §11.1), so a
// redirect is a server's mistake or its attack, and what one can do is send
// the pass, or the address a lookup asks about, somewhere else: Go's own
// policy keeps Authorization on a redirect to the same host name or a
// subdomain of it, whatever its scheme or port. The script's curl follows none either.
func followNone(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// checkServerURL holds the URL of the server a mailbox calls to https, or to http only for a server on this
// machine (onThisMachine). A pass is a bearer credential for the minutes it
// has left, and a lookup names the address it asks about, so neither
// crosses a network in the clear (RFC 6750 §5.3). Nothing allows more.
func checkServerURL(s string) error {
	u, err := url.Parse(s)
	if err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http" && onThisMachine(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("%.80q is not a server this client calls: one is https, or http only to this machine, by its address (127.0.0.0/8, ::1)", s)
}

// onThisMachine reports whether host is this machine's loopback, written as
// an address: one in 127.0.0.0/8, or ::1. A name is not: "localhost" is
// what a resolver says it is (RFC 8252 §8.3).
func onThisMachine(host string) bool {
	if host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && !strings.Contains(host, ":") && ip.To4()[0] == 127
}

// Address returns the mailbox's address.
func (b *Mailbox) Address() protocol.Address { return b.id.Address() }

// Link returns the mailbox's link, <server>/to/<address>: what to give whoever
// should write to it.
func (b *Mailbox) Link() string { return b.base + protocol.LinkPath + b.Address().String() }

// Destination parses where to send: an address, a link to one on this mailbox's
// server, or one of this mailbox's aliases (see [Mailbox.SetAlias]). A link to
// another server is refused, since a mailbox sends only through its own.
func (b *Mailbox) Destination(s string) (protocol.Address, error) {
	if aliasGrammar.MatchString(s) {
		return b.alias(s)
	}
	a, err := protocol.ParseAddress(strings.TrimPrefix(s, b.base+protocol.LinkPath))
	switch {
	case err == nil:
		return a, nil
	case strings.Contains(s, "://") && !strings.HasPrefix(s, b.base+"/"):
		return a, refuse("a link to another server: this mailbox's server is %s", b.base)
	}
	return a, refuse("not an address, a link to one, or an alias: %s", s)
}

// Identity returns the mailbox's identity.
func (b *Mailbox) Identity() *protocol.Identity { return b.id }

// Dir returns the mailbox's state directory.
func (b *Mailbox) Dir() string { return b.dir }

func (b *Mailbox) path(elem ...string) string {
	return filepath.Join(append([]string{b.dir}, elem...)...)
}

// Init creates a mailbox in dir, or finishes an init that stopped half way:
// it makes the identity, the first working key with its certificate, and the
// first prekey (of type kt) if they are missing, and registers the mailbox. The
// registration carries a pass the working key signs, so the mailbox is in use at
// once. Run again on a finished mailbox, it changes nothing.
func Init(ctx context.Context, dir string, opt Options, kt protocol.KeyType) (*Mailbox, error) {
	b, err := newMailbox(dir, opt)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := b.makeDirs(); err != nil {
		return nil, err
	}
	// Under the mailbox's lock from its identity on, as every command that writes
	// the mailbox, and with its outcome, once init has read that the mailbox is not
	// finished.
	return lockedFinished(ctx, b, func() (*Mailbox, error) {
		r, err := b.init(ctx, kt)
		return outcome(b, r, err)
	})
}

func (b *Mailbox) init(ctx context.Context, kt protocol.KeyType) (*Mailbox, error) {
	fresh := !exists(b.path("identity"))
	if fresh {
		if err := b.newIdentityKey(); err != nil {
			return nil, err
		}
	}
	if err := b.loadIdentity(); err != nil {
		return nil, err
	}
	if t := b.identityType; t != "" && t != b.id.Type() {
		return nil, fmt.Errorf("this mailbox's identity is already a key of the type %s: its address is that key's, so its type cannot change", b.id.Type())
	}
	if err := b.finished(); err != nil {
		return nil, err
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	if published > 0 {
		return b, nil
	}
	// The mailbox's first prekey is a renewal as every later one is (Rekey): read
	// from what its server holds of the mailbox (known), numbered by this
	// machine's clock above all that shows, and sent as a registration where
	// the server holds no mailbox for it. So a mailbox restored from its identity
	// alone and a registration whose answer was lost take one path, and what
	// an earlier attempt signed is sent again only while it can be
	// (PROTOCOL.md §12.4; #87). An identity made by this call has no history
	// a server could hold, and nobody else holds its key to have revoked
	// anything under it: its renewal goes as a registration with no read,
	// which a server would count as a miss of its address.
	if !fresh {
		_, err := b.rekeyAdopting(ctx, kt)
		return b, err
	}
	if kt == "" {
		kt = protocol.PostQuantum
	}
	if _, at, err := b.renewFrom(ctx, &ownRead{forgotten: true, kt: kt}); err != nil {
		return nil, err
	} else if err := b.prune(at); err != nil {
		return nil, err
	}
	return b, nil
}

// publish sends a registration or a new prekey, whose statement working key
// n signed, with a pass that key signs: the server takes a pass under the
// certificate of the statement a call brings, which is how a mailbox gets a
// certificate on record. Once the server has taken it, n is the prekey this
// mailbox published last, its working key is the one in use, and older working
// keys go. It returns the reading the server took, the pass's date, once the
// server has answered: an error beside it is a fault of this mailbox after the
// server took the call (#110).
func (b *Mailbox) publish(ctx context.Context, path string, req any, n uint64) (taken, error) {
	work, _, err := b.worker(n)
	if err != nil {
		return taken{}, err
	}
	pass, err := b.signPass(work)
	if err != nil {
		return taken{}, err
	}
	if _, err := b.call(ctx, http.MethodPut, path, req, http.Header{"Authorization": {pass}}, nil); err != nil {
		return taken{}, err
	}
	at, err := tk.By(pass)
	if err != nil {
		return taken{}, err
	}
	step("renewal taken")
	return at, b.recordTaken(n, pass)
}

// recordTaken records statement n as one the server took, before anything
// else is done, in one transaction: n as the prekey this mailbox published last,
// unless a higher one is; the renewal under way done, with any that failed
// before it, unless a later one is under way; and pass, which is under the
// certificate the server now holds this mailbox to, as the pass the mailbox keeps,
// or with none given, no pass. Then the working keys older than n go.
func (b *Mailbox) recordTaken(n uint64, pass string) error {
	if err := b.update(func(s store) error {
		if err := b.recordPublished(s, n); err != nil {
			return err
		}
		begun, err := decimal(s.get(bucketIntent, "renewal"), "renewal")
		if err != nil {
			return err
		}
		if begun <= n {
			for _, k := range []struct{ bucket, key string }{{bucketIntent, "renewal"}, {bucketMailbox, "renew-failed"}} {
				if err := s.del(k.bucket, k.key); err != nil {
					return err
				}
			}
		}
		if pass == "" {
			return s.del(bucketMailbox, "pass")
		}
		return s.put(bucketMailbox, "pass", []byte(pass))
	}); err != nil {
		return err
	}
	step("renewal recorded")
	return b.dropWork(n)
}

// makeDirs makes the mailbox's directories that are missing, its .gitignore and
// its state file, and the mailbox's directory and each of its own its owner's
// alone (private), at every open: a mailbox restored from its identity alone, or
// a directory made before the mailbox by someone else, is held to it too.
func (b *Mailbox) makeDirs() error {
	if err := private(b.dir); err != nil {
		return fmt.Errorf("the mailbox's directory, made its owner's alone: %w", err)
	}
	made := false
	for _, d := range []string{"work", "prekeys", "inbox", "held", "refused", "outbox", "sent"} {
		if _, err := os.Stat(b.path(d)); err != nil {
			if err := os.MkdirAll(b.path(d), 0o700); err != nil {
				return err
			}
			made = true
		}
		if err := private(b.path(d)); err != nil {
			return fmt.Errorf("the mailbox's %s/, made its owner's alone: %w", d, err)
		}
	}
	// A new directory is there after a crash only once its parent is synced.
	if made {
		if err := syncDir(b.dir); err != nil {
			return err
		}
	}
	// The directory ignores itself, wherever it is and whatever made it: a
	// mailbox restored from its identity alone too (#292). Written only where its
	// bytes differ, since every command opens the mailbox.
	if got, err := os.ReadFile(b.path(".gitignore")); err != nil || string(got) != "*\n" {
		if err := writeFile(b.path(".gitignore"), []byte("*\n")); err != nil {
			return err
		}
	}
	return b.makeState()
}

// newIdentityKey makes a new identity key, written as ssh-keygen writes one
// with no passphrase and no comment: Ed25519, unless the mailbox was told another
// type this client can make.
func (b *Mailbox) newIdentityKey() error {
	var priv crypto.Signer
	var err error
	switch b.identityType {
	case "", protocol.IdentityEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case protocol.IdentityP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return fmt.Errorf("this client makes no identity key of type %q: %s", b.identityType, strings.Join(protocol.IdentityTypes(), " or "))
	}
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return err
	}
	if err := writeFile(b.path("identity.pub"), ssh.MarshalAuthorizedKey(sshPub)); err != nil {
		return err
	}
	return writeFile(b.path("identity"), pem.EncodeToMemory(block))
}

// loadIdentity reads the identity key, and writes identity.doc and address
// from it, so all three always agree.
func (b *Mailbox) loadIdentity() error {
	pemBytes, err := os.ReadFile(b.path("identity"))
	if err != nil {
		return fmt.Errorf("no mailbox here: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return errors.New("the identity key has a passphrase, which this client does not support yet")
	}
	if err != nil {
		return fmt.Errorf("the identity key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return fmt.Errorf("the identity key: %w", err)
	}
	id, err := protocol.IdentityOf(signer.PublicKey())
	if errors.Is(err, protocol.ErrIdentityType) {
		return fmt.Errorf("the identity key is of the type %s, and this client runs a mailbox on %s", signer.PublicKey().Type(), strings.Join(protocol.IdentityTypes(), " or "))
	}
	if err != nil {
		return err
	}
	b.identity, b.id = sign.NewIdentity(signer, b.finished), id
	if doc, err := os.ReadFile(b.path("identity.doc")); err != nil || !bytes.Equal(doc, id.Document()) {
		if err := writeFile(b.path("identity.doc"), id.Document()); err != nil {
			return err
		}
	}
	addr := []byte(id.Address().String() + "\n")
	if a, err := os.ReadFile(b.path("address")); err != nil || !bytes.Equal(a, addr) {
		return writeFile(b.path("address"), addr)
	}
	return nil
}

// prekeyRecord is a prekey statement this mailbox signed, as the prekeys bucket
// keeps it by its serial: the statement, its signature, and when it was
// signed, which is what the mailbox times its renewals and the early deletion of
// its retired prekeys by ([Mailbox.made]; PROTOCOL.md §12.4), in one value, so the
// three are never out of line (#192). Its key is prekeys/<serial>.agekey.
type prekeyRecord struct {
	Statement protocol.Bytes `json:"statement"`
	Signature protocol.Bytes `json:"signature"`
	Made      string         `json:"made"`
}

// prekeyOf is the statement this mailbox signed at serial n, or nil.
func (b *Mailbox) prekeyOf(n uint64) (p *prekeyRecord, err error) {
	err = b.view(func(s store) error {
		raw := s.get(bucketPrekeys, serialKey(n))
		if raw == nil {
			return nil
		}
		p = &prekeyRecord{}
		if err := protocol.Unmarshal(raw, p); err != nil {
			return fmt.Errorf("the mailbox's state file keeps no statement of prekey %d it can read: %w", n, err)
		}
		return nil
	})
	return p, err
}

// prekeys is the serial of every statement this mailbox keeps, lowest first.
func (b *Mailbox) prekeys() (ns []uint64, err error) {
	err = b.view(func(s store) error {
		return s.each(bucketPrekeys, func(k, _ []byte) error {
			n, err := keySerial(k)
			ns = append(ns, n)
			return err
		})
	})
	return ns, err
}

// makePrekey makes prekey serial, a NEW key of type kt valid for the mailbox's
// prekey lifetime ([Mailbox.PrekeyLifetime]), and its statement, signed by a NEW
// working key under a new certificate, unless its statement is already
// signed. The number is recorded as the renewal under way before anything is
// made, and the statement, with when it was signed, once it is: so a key or a
// working key that no statement names was never sent, and a key an earlier
// attempt made and never signed is used, but never a working key, whose
// certificate began when that attempt ran (#197). A statement never outlives
// the certificate it is signed under.
func (b *Mailbox) makePrekey(serial uint64, kt protocol.KeyType) (*protocol.Prekey, error) {
	if rec, err := b.prekeyOf(serial); err != nil || rec != nil {
		if err != nil {
			return nil, err
		}
		return protocol.ParsePrekey(rec.Statement)
	}
	lifetime, err := b.PrekeyLifetime()
	if err != nil {
		return nil, err
	}
	if err := b.begin(serial); err != nil {
		return nil, err
	}
	// The working key and its certificate first: a mailbox that may sign nothing
	// more is stopped at the certificate, before any key is written.
	worker, cert, err := b.makeWork(serial)
	if err != nil {
		return nil, err
	}
	step("working key made")
	stem := b.path("prekeys", fmt.Sprint(serial))
	if !exists(stem+".agekey") || keyType(stem+".agekey") != kt {
		if err := newAgeKey(stem+".agekey", kt, b.now()); err != nil {
			return nil, err
		}
	}
	step("prekey made")
	recipient, err := ageRecipient(stem + ".agekey")
	if err != nil {
		return nil, err
	}
	made := b.now().UTC().Truncate(time.Second)
	notAfter := made.Add(lifetime)
	if cert.NotAfter().Before(notAfter) {
		notAfter = cert.NotAfter()
	}
	p := &protocol.Prekey{Address: b.id.Address(), Serial: serial, Key: recipient, NotAfter: notAfter}
	sig, err := worker.Signature(p.Statement(), protocol.PrekeyNamespace(b.id.Address()))
	if err != nil {
		return nil, err
	}
	rec, err := json.Marshal(prekeyRecord{Statement: p.Statement(), Signature: sig, Made: made.Format(protocol.TimeLayout)})
	if err != nil {
		return nil, err
	}
	if err := b.update(func(s store) error { return s.put(bucketPrekeys, serialKey(serial), rec) }); err != nil {
		return nil, err
	}
	step("statement kept")
	return p, nil
}

// begin records serial as the number of the renewal under way. A number an
// earlier attempt took and left unsigned, which this one passes over, leaves
// nothing: no statement named its key or its working key, so neither was
// ever sent.
func (b *Mailbox) begin(serial uint64) error {
	var old uint64
	if err := b.view(func(s store) error {
		var err error
		old, err = decimal(s.get(bucketIntent, "renewal"), "renewal")
		return err
	}); err != nil {
		return err
	}
	if old != 0 && old != serial {
		rec, err := b.prekeyOf(old)
		if err != nil {
			return err
		}
		if rec == nil {
			for _, name := range []string{b.path("prekeys", strconv.FormatUint(old, 10)+".agekey"), b.workStem(old), b.workStem(old) + ".pub", b.workStem(old) + "-cert.pub"} {
				if err := removeIfExists(name); err != nil {
					return err
				}
			}
		}
	}
	if err := b.update(func(s store) error {
		return s.put(bucketIntent, "renewal", strconv.AppendUint(nil, serial, 10))
	}); err != nil {
		return err
	}
	step("renewal begun")
	return nil
}

// ageRecipient returns the recipient an age key file's key is encrypted to.
func ageRecipient(name string) (string, error) {
	ids, err := readAgeKeys(name)
	if err != nil {
		return "", err
	}
	switch k := ids[0].(type) {
	case *age.HybridIdentity:
		return k.Recipient().String(), nil
	case *age.X25519Identity:
		return k.Recipient().String(), nil
	}
	return "", fmt.Errorf("%s holds an unknown key type", name)
}

// newAgeKey writes a new age key file as age-keygen writes one.
func newAgeKey(name string, kt protocol.KeyType, now time.Time) error {
	var key, recipient string
	switch kt {
	case protocol.PostQuantum:
		k, err := age.GenerateHybridIdentity()
		if err != nil {
			return err
		}
		key, recipient = k.String(), k.Recipient().String()
	case protocol.Classic:
		k, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		key, recipient = k.String(), k.Recipient().String()
	default:
		return fmt.Errorf("unknown prekey type %q", kt)
	}
	return writeFile(name, fmt.Appendf(nil, "# created: %s\n# public key: %s\n%s\n", now.Format(time.RFC3339), recipient, key))
}

// keyType returns the type of the key in an age key file, or "" if it holds
// none this client makes.
func keyType(name string) protocol.KeyType {
	ids, err := readAgeKeys(name)
	if err != nil || len(ids) == 0 {
		return ""
	}
	switch ids[0].(type) {
	case *age.HybridIdentity:
		return protocol.PostQuantum
	case *age.X25519Identity:
		return protocol.Classic
	}
	return ""
}

func readAgeKeys(name string) ([]age.Identity, error) {
	f, err := os.Open(name) //nolint:gosec // a path inside the mailbox's own directory
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return ids, nil
}

// prekeyIdentities returns every retained prekey, to decrypt with once
// oneNative has taken the file (decrypt).
func (b *Mailbox) prekeyIdentities() ([]age.Identity, error) {
	names, err := filepath.Glob(b.path("prekeys", "*.agekey"))
	if err != nil {
		return nil, err
	}
	var all []age.Identity
	for _, n := range names {
		ids, err := readAgeKeys(n)
		if err != nil {
			return nil, err
		}
		all = append(all, ids...)
	}
	if len(all) == 0 {
		return nil, errors.New("this mailbox holds no prekeys: publish a new one with dromas prekey renew")
	}
	return all, nil
}

// decrypt decrypts ct with ids, every retained prekey, once oneNative has
// taken it: age is given no identity before the stanzas are counted, so a
// file oneNative refuses reaches no key agreement.
func decrypt(ct []byte, ids []age.Identity) (io.Reader, error) {
	if err := oneNative(ct); err != nil {
		return nil, err
	}
	return age.Decrypt(bytes.NewReader(ct), ids...)
}

// oneNative takes an age file only with exactly one native recipient stanza,
// of a type a prekey has (protocol.PostQuantum, protocol.Classic), as every
// server takes a send (PROTOCOL.md §11.10 step 7, §12.3 check 1); a grease stanza
// and any other age ignores, as it does. age tries every identity on every
// stanza, up to 1,024, so a file of 1,024 native stanzas costs a mailbox about a
// thousand times what an honest message does, for each prekey it keeps (#49,
// measured; PRECEDENTS.md, Part 2, § 4), and only a server can serve one.
// The stanzas are read and counted once, before anything is decrypted, by
// protocol.ReadStanzas, the reading a server's check of a send shares. A
// file with none is a case of its own (§11.10 step 7): errNoNative.
func oneNative(ct []byte) error {
	st, err := protocol.ReadStanzas(ct)
	if err != nil {
		return err
	}
	switch len(st.Native) {
	case 1:
		return nil
	case 0:
		return errNoNative
	}
	return errNotOneNative
}

// errNotOneNative is a file of two native recipient stanzas or more, which
// oneNative refuses.
var errNotOneNative = errors.New("more than one native recipient stanza")

// errNoNative is a file with no native recipient stanza, which oneNative
// refuses.
var errNoNative = errors.New("no native recipient stanza")

func (b *Mailbox) mailboxPath(rest string) string { return "/v1/" + b.id.Address().String() + rest }
