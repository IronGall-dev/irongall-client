package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/protocol"
	"golang.org/x/crypto/ssh"
)

// DefaultBase is the server every box talks to unless told otherwise.
const DefaultBase = "https://crossbot.dev"

// EchoAddress is the echo box crossbot.dev runs (cmd/crossbot-echo): send
// it anything, and it answers with a signed reply saying what it checked and
// carrying the body back. Its prekey is post-quantum. Mail to it is readable
// by crossbot.dev's operator, who runs it.
const EchoAddress = "3ea2a2fdf19bf1092039ca8dd5ce6728bad8f871d3822a018d8375c42db4b0e8"

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
}

// Box is one box: its state directory and the server it talks to.
type Box struct {
	dir    string
	base   string
	http   *http.Client
	now    func() time.Time
	signer ssh.Signer
	id     *protocol.Identity
	// renewFailed is when Receive last failed to renew the prekey.
	renewFailed time.Time
}

// Open opens an existing box's state directory. A directory holding only
// the identity, a box restored from its backup, gets the box's other
// directories; [Box.Rekey] then gives it a prekey and a token.
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
	b := &Box{dir: dir, base: strings.TrimRight(opt.Base, "/"), http: opt.HTTPClient, now: opt.Now}
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

// Destination parses where to send: an address, or a link to one on this
// box's server. A link to another server is refused, since a box sends only
// through its own.
func (b *Box) Destination(s string) (protocol.Address, error) {
	a, err := protocol.ParseAddress(strings.TrimPrefix(s, b.base+protocol.LinkPath))
	switch {
	case err == nil:
		return a, nil
	case strings.Contains(s, "://") && !strings.HasPrefix(s, b.base+"/"):
		return a, refuse("a link to another server: this box's server is %s", b.base)
	}
	return a, refuse("not an address, or a link to one: %s", s)
}

// Identity returns the box's identity.
func (b *Box) Identity() *protocol.Identity { return b.id }

// Dir returns the box's state directory.
func (b *Box) Dir() string { return b.dir }

func (b *Box) path(elem ...string) string {
	return filepath.Join(append([]string{b.dir}, elem...)...)
}

// Init creates a box in dir, or finishes an init that stopped half way:
// it makes the identity and the first prekey (of type kt) if they are
// missing, registers the box, and activates it with one owner call. Run again
// on a finished box, it changes nothing.
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
	if _, err := b.makePrekey(1, kt); err != nil {
		return nil, err
	}
	if !exists(b.path("token")) {
		req := protocol.RegisterRequest{Identity: b.id.Document()}
		var err error
		if req.Prekey, err = os.ReadFile(b.path("prekeys", "1.txt")); err != nil {
			return nil, err
		}
		if req.PrekeySignature, err = os.ReadFile(b.path("prekeys", "1.txt.sig")); err != nil {
			return nil, err
		}
		var tr protocol.TokenResponse
		if _, err := b.call(ctx, http.MethodPut, b.boxPath(""), req, nil, &tr); err != nil {
			return nil, err
		}
		if err := b.storeToken(tr.Token); err != nil {
			return nil, err
		}
	}
	// The first owner call activates the box.
	if _, err := b.owner(ctx, http.MethodGet, b.boxPath("/messages"), nil, nil, nil); err != nil {
		return nil, err
	}
	return b, nil
}

// makeDirs makes the box's directories that are missing.
func (b *Box) makeDirs() error {
	for _, d := range []string{"prekeys", "peers", "inbox", "quarantine", "outbox"} {
		if err := os.MkdirAll(b.path(d), 0o700); err != nil {
			return err
		}
	}
	return nil
}

// newIdentityKey makes a new Ed25519 identity, written as ssh-keygen writes
// one with no passphrase and no comment.
func (b *Box) newIdentityKey() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
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
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		return fmt.Errorf("the identity key is a %T, not Ed25519", raw)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	id, err := protocol.NewIdentity(priv.Public().(ed25519.PublicKey))
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
// its signed statement, unless its statement is already signed. A key left
// by an attempt that never published is reused.
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
	ids, err := readAgeKeys(stem + ".agekey")
	if err != nil {
		return nil, err
	}
	var recipient string
	switch k := ids[0].(type) {
	case *age.HybridIdentity:
		recipient = k.Recipient().String()
	case *age.X25519Identity:
		recipient = k.Recipient().String()
	default:
		return nil, fmt.Errorf("%s holds an unknown key type", stem+".agekey")
	}
	p := &protocol.Prekey{
		Address:  b.id.Address(),
		Serial:   serial,
		Key:      recipient,
		NotAfter: b.now().UTC().Add(protocol.MaxPrekeyLifetime).Truncate(time.Second),
	}
	sig, err := protocol.Sign(b.signer, p.Statement(), protocol.PrekeyNamespace(b.id.Address()))
	if err != nil {
		return nil, err
	}
	if err := writeFile(stem+".txt", p.Statement()); err != nil {
		return nil, err
	}
	return p, writeFile(stem+".txt.sig", sig)
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
		return nil, errors.New("this box holds no prekeys: publish a new one with crossbot rekey")
	}
	return all, nil
}

// decryptToken decrypts an owner token sent encrypted to this box's prekeys.
func (b *Box) decryptToken(ciphertext []byte) ([]byte, error) {
	ids, err := b.prekeyIdentities()
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), ids...)
	if err != nil {
		return nil, refuse("the token does not decrypt with this box's prekeys")
	}
	tok, err := io.ReadAll(io.LimitReader(r, 1024))
	if err != nil || len(tok) == 0 {
		return nil, refuse("the token does not decrypt with this box's prekeys")
	}
	return tok, nil
}

func (b *Box) storeToken(ciphertext []byte) error {
	tok, err := b.decryptToken(ciphertext)
	if err != nil {
		return err
	}
	return writeFile(b.path("token"), tok)
}

func (b *Box) boxPath(rest string) string { return "/v1/" + b.id.Address().String() + rest }
