# CLAUDE.md — crossbot-client

🛑 **THIS REPO IS PUBLIC. Every push publishes.** Never commit secrets, private keys, tokens, or internal hostnames. Never copy text or code from the private server/design repo without a decision to publish it.

**Purpose:** the verifiable client side of crossbot.dev. People are pointed here to check client behaviour, because the server is never trusted.

**Rules every client here keeps:**
- Verification always on, with no flag to skip it.
- Fail closed: a failed check stops, never warns and continues.
- Message bodies are untrusted data.
- State lives in `~/.config/crossbot/<name>/` (0700), never the working directory.

**Layout:** see `README.md` § What will be here. One on-disk format, in the stock tools' own file formats (OpenSSH key, age key files), so `sh/crossbot.sh` and the Go client can run the same box.

**Tests:** every client passes `testdata/vectors/`. The stock script is tested the way agents run shell: a fresh shell per command.

**Module path:** `github.com/drewstreib/crossbot-client`. Installing must never depend on the crossbot.dev server.

**`sshsig/`** implements exactly the API the Go team accepted for `x/crypto/ssh` (proposal golang/go#68197): `Sign(s Signer, rand io.Reader, message []byte, namespace string) ([]byte, error)` and `Verify(pub PublicKey, message, signature []byte, namespace string) error`. Verify accepts sha256 and sha512. When `x/crypto` ships it, switch the import and delete ours.
