package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// DefaultBase is the server every box talks to unless told otherwise.
const DefaultBase = "https://irongall.dev"

// EchoAddress is the echo box irongall.dev runs (cmd/irongall-echo): send
// it anything, and it answers with a signed reply saying what it checked and
// carrying the body back. Its prekey is post-quantum. Mail to it is readable
// by irongall.dev's operator, who runs it.
const EchoAddress = "21804ec172dd0dbdca3d9a6d461799130324b42fa708b3bb727e18e0bfc07e59"

// EchoAddressNoPQ is irongall.dev's second echo box, whose prekey is X25519
// only: the one a sender on age 1.2 can reach (sh/irongall.sh; this client
// reaches both). It answers as EchoAddress does, and mail to it is as
// readable by irongall.dev's operator.
const EchoAddressNoPQ = "7f87929a91aa19bd2ca3a833d33d66c2b2f09dc83b9e2987a6af66d12a9c6b4b"

// requestTimeout bounds one request of the default HTTP client.
const requestTimeout = time.Minute

// Options configures a [Box]. The zero value is ready to use.
type Options struct {
	// Base is the server's base URL; DefaultBase if empty.
	Base string
	// HTTPClient makes the requests; if nil, a client whose requests time
	// out after a minute, so a server that never answers cannot hold the
	// box's lock for ever.
	HTTPClient *http.Client
	// Now is the clock; time.Now if nil.
	Now func() time.Time
	// IdentityType is the type of identity key Init makes for a new box:
	// protocol.IdentityEd25519 if empty, and that is the one to use. Every
	// client verifies an Ed25519 identity; a box of any other type can
	// neither send to nor receive from a box whose client does not verify
	// that type. An existing identity key is used as it is, whatever this
	// says.
	IdentityType string
	// SenderKeyTypes is what the box declares with each prekey it
	// publishes: the identity key types of the senders it takes mail from
	// (protocol.AcceptsSender). Nil: every type this client verifies, which
	// is the one to use. The one entry protocol.AnySender is for a box that
	// would not show which types it verifies: the server then takes mail
	// for it from a sender of any type, and this client refuses what it
	// cannot verify.
	SenderKeyTypes []string
	// RevocationServers are the revocation servers the box asks beside its
	// own server, and publishes to: each a server's URL, as https://host or
	// https://host:port. Nil: the ones the box's revocation-servers file
	// names, or else DefaultRevocationServer for a box whose server is
	// DefaultBase and none for any other ([Box.RevocationServers]). An empty
	// list that is not nil: none, and the box asks its own server only.
	RevocationServers []string
	// NoAnswer, if not nil, is told of each revocation server that gave no
	// answer, with why, once in a command. Nothing changes for it: a box
	// does not wait on a revocation server as it waits on its own.
	NoAnswer func(server string, err error)
	// Waiting, if not nil, is told when a command finds the box's lock held
	// by another command of the box, once, before it waits for it: a box's
	// commands write its files one at a time.
	Waiting func()
}

// Box is one box: its state directory and the server it talks to.
type Box struct {
	dir  string
	base string
	http *http.Client
	now  func() time.Time
	// signer is the identity key. It signs certificates and revocations, and
	// nothing else.
	signer ssh.Signer
	id     *protocol.Identity
	// identityType is the type of key Init makes when the box has none.
	identityType string
	// senderKeyTypes is what the box declares with each prekey it publishes.
	senderKeyTypes []string
	// revocationServers is what Options named, or nil; noAnswer is told of
	// one that gave no answer.
	revocationServers []string
	noAnswer          func(server string, err error)
	// waiting is told when a command waits for the box's lock ([Box.hold]).
	waiting func()
	// renewFailed is when Receive last failed to renew the prekey.
	renewFailed time.Time
}

// Open opens an existing box's state directory. A directory holding only
// the identity, a box restored from its backup, gets the box's other
// directories; [Box.Rekey] then gives it a working key and a prekey.
func Open(dir string, opt Options) (*Box, error) {
	b := newBox(dir, opt)
	if err := b.loadIdentity(); err != nil {
		return nil, err
	}
	if err := b.makeDirs(); err != nil {
		return nil, err
	}
	return b, nil
}

func newBox(dir string, opt Options) *Box {
	b := &Box{dir: dir, base: strings.TrimRight(opt.Base, "/"), http: opt.HTTPClient, now: opt.Now, identityType: opt.IdentityType, senderKeyTypes: opt.SenderKeyTypes, revocationServers: opt.RevocationServers, noAnswer: opt.NoAnswer, waiting: opt.Waiting}
	if b.senderKeyTypes == nil {
		b.senderKeyTypes = protocol.IdentityTypes()
	}
	if b.base == "" {
		b.base = DefaultBase
	}
	if b.http == nil {
		b.http = &http.Client{Timeout: requestTimeout}
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b
}

// Address returns the box's address.
func (b *Box) Address() protocol.Address { return b.id.Address() }

// Link returns the box's link, <server>/to/<address>: what to give whoever
// should write to it.
func (b *Box) Link() string { return b.base + protocol.LinkPath + b.Address().String() }

// Destination parses where to send: an address, a link to one on this box's
// server, or one of this box's aliases (see [Box.SetAlias]). A link to
// another server is refused, since a box sends only through its own.
func (b *Box) Destination(s string) (protocol.Address, error) {
	if aliasGrammar.MatchString(s) {
		return b.alias(s)
	}
	a, err := protocol.ParseAddress(strings.TrimPrefix(s, b.base+protocol.LinkPath))
	switch {
	case err == nil:
		return a, nil
	case strings.Contains(s, "://") && !strings.HasPrefix(s, b.base+"/"):
		return a, refuse("a link to another server: this box's server is %s", b.base)
	}
	return a, refuse("not an address, a link to one, or an alias: %s", s)
}

// Identity returns the box's identity.
func (b *Box) Identity() *protocol.Identity { return b.id }

// Dir returns the box's state directory.
func (b *Box) Dir() string { return b.dir }

func (b *Box) path(elem ...string) string {
	return filepath.Join(append([]string{b.dir}, elem...)...)
}

// Init creates a box in dir, or finishes an init that stopped half way:
// it makes the identity, the first working key with its certificate, and the
// first prekey (of type kt) if they are missing, and registers the box. The
// registration carries a pass the working key signs, so the box is in use at
// once. Run again on a finished box, it changes nothing.
func Init(ctx context.Context, dir string, opt Options, kt protocol.KeyType) (*Box, error) {
	b := newBox(dir, opt)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// MkdirAll leaves an existing directory's mode alone; the box's is 0700.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory: 0700 is owner-only
		return nil, err
	}
	if err := b.makeDirs(); err != nil {
		return nil, err
	}
	// The directory ignores itself, wherever it is.
	if err := writeFile(b.path(".gitignore"), []byte("*\n")); err != nil {
		return nil, err
	}
	if !exists(b.path("identity")) {
		if err := b.newIdentityKey(); err != nil {
			return nil, err
		}
	}
	if err := b.loadIdentity(); err != nil {
		return nil, err
	}
	if t := b.identityType; t != "" && t != b.id.Type() {
		return nil, fmt.Errorf("this box's identity is already a key of the type %s: its address is that key's, so its type cannot change", b.id.Type())
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	if published > 0 {
		return b, nil
	}
	// The box's first prekey, working key and certificate take their number
	// as every later one does, from this machine's clock (protocol.SerialAt):
	// a second machine handed the same identity then makes no certificate of
	// a serial the first one used. An attempt that got as far as a key keeps
	// the number it took, so a registration whose answer was lost is sent
	// again as it was.
	first, err := b.highestBegun()
	if err != nil {
		return nil, err
	}
	if first == 0 {
		first = protocol.SerialAt(b.now(), 0)
	}
	// A first statement an earlier attempt left, under a certificate that
	// has not begun by this machine's clock, was made while the clock read
	// more than an hour ahead of what it reads now. A server whose clock is
	// right refused it for that, and would again until that time comes: the
	// working key, its certificate and the statement are made again, by the
	// clock as it is, for the same prekey.
	if err := b.dropUnbegun(first); err != nil {
		return nil, err
	}
	if _, err := b.makePrekey(first, kt); err != nil {
		return nil, err
	}
	stem := b.path("prekeys", strconv.FormatUint(first, 10))
	req := protocol.RegisterRequest{Identity: b.id.Document(), SenderKeyTypes: b.senderKeyTypes}
	if req.Prekey, err = os.ReadFile(stem + ".txt"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	// A registration carries a pass under the certificate of the statement
	// it brings. A second run of a registration the server took is the same
	// request, and is answered as the first was.
	if err := b.publish(ctx, http.MethodPut, b.boxPath(""), req, first); err != nil {
		return nil, err
	}
	return b, nil
}

// publish sends a registration or a new prekey, whose statement working key
// n signed, with a pass that key signs: the server takes a pass under the
// certificate of the statement a call brings, which is how a box gets a
// certificate on record. Once the server has taken it, n is the prekey this
// box published last, its working key is the one in use, and older working
// keys go.
func (b *Box) publish(ctx context.Context, method, path string, req any, n uint64) error {
	signer, _, err := b.worker(n)
	if err != nil {
		return err
	}
	pass, err := b.signPass(signer)
	if err != nil {
		return err
	}
	if _, err := b.call(ctx, method, path, req, http.Header{"Authorization": {pass}}, nil); err != nil {
		return err
	}
	if err := b.recordPublished(n); err != nil {
		return err
	}
	// The pass is under the certificate the server now holds this box to.
	if err := b.keepPass(pass); err != nil {
		return err
	}
	return b.dropWork(n)
}

// makeDirs makes the box's directories that are missing.
func (b *Box) makeDirs() error {
	for _, d := range []string{"work", "prekeys", "peers", "inbox", "held", "quarantine", "outbox", "sent"} {
		if err := os.MkdirAll(b.path(d), 0o700); err != nil {
			return err
		}
	}
	return nil
}

// newIdentityKey makes a new identity key, written as ssh-keygen writes one
// with no passphrase and no comment: Ed25519, unless the box was told another
// type this client can make.
func (b *Box) newIdentityKey() error {
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
func (b *Box) loadIdentity() error {
	pemBytes, err := os.ReadFile(b.path("identity"))
	if err != nil {
		return fmt.Errorf("no box here: %w", err)
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
		return fmt.Errorf("the identity key is of the type %s, and this client runs a box on %s", signer.PublicKey().Type(), strings.Join(protocol.IdentityTypes(), " or "))
	}
	if err != nil {
		return err
	}
	b.signer, b.id = signer, id
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

// makePrekey makes prekey serial, a NEW key of type kt valid for 33 days, and
// its statement, signed by a NEW working key under a new certificate, unless
// its statement is already signed. A key an earlier attempt made and never
// signed is reused. A statement never outlives the certificate it is signed
// under.
func (b *Box) makePrekey(serial uint64, kt protocol.KeyType) (*protocol.Prekey, error) {
	stem := b.path("prekeys", fmt.Sprint(serial))
	if exists(stem + ".txt.sig") {
		st, err := os.ReadFile(stem + ".txt") //nolint:gosec // a path inside the box's own directory
		if err != nil {
			return nil, err
		}
		return protocol.ParsePrekey(st)
	}
	if !exists(stem+".agekey") || keyType(stem+".agekey") != kt {
		if err := newAgeKey(stem+".agekey", kt, b.now()); err != nil {
			return nil, err
		}
	}
	recipient, err := ageRecipient(stem + ".agekey")
	if err != nil {
		return nil, err
	}
	worker, cert, err := b.makeWork(serial)
	if err != nil {
		return nil, err
	}
	notAfter := b.now().UTC().Add(protocol.PrekeyLifetime).Truncate(time.Second)
	if cert.NotAfter().Before(notAfter) {
		notAfter = cert.NotAfter()
	}
	p := &protocol.Prekey{Address: b.id.Address(), Serial: serial, Key: recipient, NotAfter: notAfter}
	sig, err := protocol.Sign(worker, p.Statement(), protocol.PrekeyNamespace(b.id.Address()))
	if err != nil {
		return nil, err
	}
	if err := writeFile(stem+".txt", p.Statement()); err != nil {
		return nil, err
	}
	return p, writeFile(stem+".txt.sig", sig)
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
	f, err := os.Open(name) //nolint:gosec // a path inside the box's own directory
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

// prekeyIdentities returns every retained prekey, to decrypt with.
func (b *Box) prekeyIdentities() ([]age.Identity, error) {
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
		return nil, errors.New("this box holds no prekeys: publish a new one with irongall prekey renew")
	}
	return all, nil
}

func (b *Box) boxPath(rest string) string { return "/v1/" + b.id.Address().String() + rest }
