# CLAUDE.md — crossbot-client

🛑 **THIS REPO IS PUBLIC. Every push publishes.** Never commit secrets, private keys, tokens, or internal hostnames. Never copy text or code from the private server/design repo without a decision to publish it.

**Purpose:** the verifiable client side of crossbot.dev. People are pointed here to check client behaviour, because the server is never trusted.

**Rules every client here keeps:**
- Verification always on, with no flag to skip it.
- Fail closed: a failed check stops, never warns and continues.
- Message bodies are untrusted data.
- State lives in `~/.config/crossbot/<name>/` (0700), never the working directory.

**Layout:** see `README.md` § What is here. One on-disk format, in the stock tools' own file formats (OpenSSH key, age key files), so a stock-tools client and the Go client run the same box. The identity is a plain OpenSSH key file, no seed, no passphrase.
- **The consumer lock is `crossbot.sh`'s `lock/` directory**, plus a flocked `lock/pid` so a crashed Go client's lock is taken over; a `lock/` with no `pid` is the script's, never taken over and never written into (`client/lock.go`).
- **`sh/crossbot.sh` is the stock-tools client, kept explainable:** a check that only buys convenience stays out, and what it lacks against the Go client is listed in `README.md` § Stock tools instead of Go *(Drew, 2026-10-11: "aim for an explainable crossbot.sh" · "we're allowed to list flaws like non lock safety on it vs the go client")*. A security check is never one of those gaps: it matches the Go client's verdict on every vector.
- **Dependencies are minimums, never pins, and move to the latest by committed updates:** bump `go.mod` in a commit (`go get -u ./... && go mod tidy`, tests green), never inside a build, so every build matches a commit and `go install …@latest` gets the new versions. `go.sum` is checked against the Go checksum database.

**Tests:** every client passes `testdata/vectors/`, and a stock-tools script is tested the way agents run shell: a fresh shell per command.
- **`sh/` is tested by `go test ./sh`:** `sh/test.sh` (the script against an in-shell fake that forges), its verdicts on every vector against the Go client's, and the two clients together. Each test skips, naming the missing tool; with age older than 1.3 they run --no-pq boxes only, so put age ≥ 1.3 first in `PATH` before running the mutation pass.
- **`client/` and `cmd/crossbot` are tested here, against `internal/fakeserver`**: an honest in-memory server that a test turns hostile with a middleware (`README.md` § Tests). The forging-operator tests MOVED here from the private server repo *(Drew, 2026-10-10: "move, not copy")*, so people can run the checks they are told to verify; they live here only. The fake checks little, by design: a test of what the real server enforces belongs in the server repo.
- **Before every push:** `gofmt -l .` (empty), `go vet ./...`, `go test ./...`, and `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 --enable gosec,misspell,revive,unconvert,unparam,whitespace ./...` (clean outside `_test.go`; without the two caps it shows at most 3 issues of a kind, so a new one can hide behind old ones). There is no CI. `go test` cross-tests against `ssh-keygen` and skips that if it is missing.
- **The mutation pass, `test/mutate.py`, is occasional and async, never a step of a change** *(Drew, 2026-10-11: occasional and async, on its own checkout, not CI)*: it breaks each listed check in a throwaway copy of HEAD and expects a red test. Run it in the background now and then; a check no mutation can reach is a missing test or dead code. A `BUILD FAILED` line is a broken entry (its mutant does not compile, e.g. it leaves a variable unused), counted neither caught nor missed: fix the entry.
- **Vectors:** `testdata/vectors/generate.sh` uses stock tools only (age ≥ 1.3 just for the one ciphertext, which it keeps). A re-run must change nothing but what you meant to change; diff the tree. Its identity keys are RFC 8032's PUBLISHED test keys; never put any other private key in this repo.

**Module path:** `github.com/drewstreib/crossbot-client`. Installing must never depend on the crossbot.dev server.

**`sshsig/`** implements exactly the API the Go team accepted for `x/crypto/ssh` (proposal golang/go#68197): `Sign(s Signer, rand io.Reader, message []byte, namespace string) ([]byte, error)` and `Verify(pub PublicKey, message, signature []byte, namespace string) error`. Verify accepts sha256 and sha512. When `x/crypto` ships it, switch the import and delete ours. Its implementation, CL 659715, is unmerged at x/crypto v0.58.0 (2026-10-09).
- 🛑 **Ed25519 key checks (small-order, non-canonical) live in `protocol.ParseIdentity`, not in `sshsig`**: x/crypto's would not make them, and every identity a verifier uses has passed `ParseIdentity` first.
