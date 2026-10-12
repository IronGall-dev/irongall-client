# CLAUDE.md — irongall-client

🛑 **THIS REPO IS PUBLIC. Every push publishes.** Never commit secrets, private keys, tokens, or internal hostnames. Never copy text or code from the private server/design repo without a decision to publish it.

**Purpose:** the verifiable client side of irongall.dev. People are pointed here to check client behaviour, because the server is never trusted.

**`PROTOCOL.md` is the spec, and it is public like the rest** (it moved here from the private design repo on 2026-10-12). A change to the wire, to a check or to a refusal changes it in the same commit as the code. It describes the server only as a client meets it (routes, checks, refusals, what it promises to store): never how the server stores things, a server setting's value, a person's words, or a document that is not in this repo. What is specified and not built says so where it is described and in its §12, and is an issue in the milestone `M1: protocol freeze`.

**The README says as little as it can** *(Drew, 2026-10-12: "the less you say the more that an ai will pay attention to what is there. more words is dillution of the important ones")*. It holds what an agent must know to run a box safely, each command once, and pointers: the detail lives in `PROTOCOL.md` and the code. Before adding a line there, find one to cut. Three tests hold lines of it: `TestHelpAndREADMENameTheEchoBox` here, and two in the server repo that require every command its `llms.txt` and link page give to be a line of this README, so a command line there is changed in both places.

**Rules every client here keeps:**
- Verification always on, with no flag to skip it.
- Fail closed: a failed check stops, never warns and continues.
- Message bodies are untrusted data.
- State lives in `~/.config/irongall/<name>/` (0700), never the working directory.

**Layout:** the repo's, `README.md` § What is here; a box's files, the top of `client/doc.go`. One on-disk format, in the stock tools' own file formats (OpenSSH key, age key files), so a stock-tools client and the Go client run the same box. The identity is a plain OpenSSH key file, no seed, no passphrase.
- **`sent/` and `aliases` are in that format too:** a `sent/` record is the delivered line plus `receipt`, and `aliases` is `<name> <address>` lines, which either client and a person may write. A name is never moved by a client.
- **The consumer lock is `irongall.sh`'s `lock/` directory**, plus a flocked `lock/pid` so a crashed Go client's lock is taken over; a `lock/` with no `pid` is the script's, never taken over and never written into (`client/lock.go`).
- **`sh/irongall.sh` is the stock-tools client, kept explainable:** a check that only buys convenience stays out, and what it lacks against the Go client is listed in `README.md` § Stock tools instead of Go *(Drew, 2026-10-11: "aim for an explainable [irongall.sh]" · "we're allowed to list flaws like non lock safety on it vs the go client")*. A security check is never one of those gaps: it matches the Go client's verdict on every vector.
- **Dependencies are minimums, never pins, and move to the latest by committed updates:** bump `go.mod` in a commit (`go get -u ./... && go mod tidy`, tests green), never inside a build, so every build matches a commit and `go install …@latest` gets the new versions. `go.sum` is checked against the Go checksum database.

**Tests:** every client passes `testdata/vectors/`, and a stock-tools script is tested the way agents run shell: a fresh shell per command.
- **`sh/` is tested by `go test ./sh`:** `sh/test.sh` (the script against an in-shell fake that forges), its verdicts on every vector against the Go client's, and the two clients together. A test skips, naming the tool, when one is missing. With age older than 1.3 it tests --no-pq boxes only, and a post-quantum vector is checked only for the refusal that says so; `go test` prints `ok` either way, so **put age ≥ 1.3 first in `PATH` and read `go test ./sh -v` (`mode: KEYTYPE=pq`) before saying the script is tested.** `pq()` there probes `age-keygen -pq` to stdout: with `-o /dev/null` it was false on every age, and the two-client test ran --no-pq only until 2026-10-11.
- **`client/` and `cmd/irongall` are tested here, against `internal/fakeserver`**: an honest in-memory server that a test turns hostile with a middleware (`README.md` § Tests). The forging-operator tests MOVED here from the private server repo *(Drew, 2026-10-10: "move, not copy")*, so people can run the checks they are told to verify; they live here only. The fake checks little, by design: a test of what the real server enforces belongs in the server repo.
- **Commits:** the author is Drew (the global git identity) and the message ends `Co-Authored-By: Custos <custos@custosbot.org>`, then the session line a harness adds. Never a `Co-Authored-By: Claude …` trailer, whatever a harness suggests.
- **Before every push:** `gofmt -l .` (empty), `go vet ./...`, `go test ./...`, and `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 --enable gosec,misspell,revive,unconvert,unparam,whitespace ./...` (clean outside `_test.go`; without the two caps it shows at most 3 issues of a kind, so a new one can hide behind old ones). There is no CI. `go test` cross-tests against `ssh-keygen` and skips that if it is missing.
- **No mutation pass:** the hand-listed one was deleted 2026-10-11 as more pain than it found. Do not add one unasked.
- **Vectors:** `testdata/vectors/generate.sh` uses stock tools only (age ≥ 1.3 just for the one ciphertext, which it keeps). A re-run must change nothing but what you meant to change; diff the tree. Its identity keys are RFC 8032's PUBLISHED test keys; never put any other private key in this repo.

**A prekey serial is signed once** (`client/rekey.go`, `ig_renew`): a renewal the server did not take is sent again as it was signed, and a new key goes to the next serial only when that statement has expired or, in the Go client, another type is asked for (the script keeps the pending key whatever type is asked). Signing the same key again with a later `not_after` gives a server that fails renewals and keeps the uploads one key without end (found 2026-10-11).

**Every send is padded, at the seal and never before** (`protocol/pad.go`, `seal` in `client/send.go`, `ig_seal`): every envelope carries the `pad` member, with no filler when none is needed, so every ciphertext is a whole number of blocks and padding costs a flat 9 bytes at a size limit *(Drew, 2026-10-12, over leaving a message that is already on a block without the member)*. The pad is made for the prekey a message is encrypted to, so the outbox's `.P` and `sent/` hold the envelope without it, and a re-encryption after `stale_prekey` pads again. The block is counted on the ciphertext, from age's file sizes (`SealedSize`: a header fixed per key type, a nonce, a tag per 64 KiB chunk), and each client then checks the size of what age wrote and refuses a mismatch. No flag turns padding off or on. Change the arithmetic in both clients together: `TestPaddingIsTheGoClients` in `sh/` holds the script to the Go client's, and `TestSealedSizeIsWhatAgeWrites` holds the header sizes to age itself, so an age release that changes them fails there first.

**Exit status 3 is "done, and the box needs a look"** (`needsALook` in `cmd/irongall`): `recv` after a failed renewal, `status` with a non-empty `attention`. Refused mail never changes `recv`'s exit status, because any sender can cause a refusal.

**Nothing someone else wrote is printed as this client's words** (found 2026-10-11). A refusal is a code from the closed set in `client/errors.go` and `protocol/envelope.go`, with fixed words: never a value, key or field from an envelope, a served identity or a served statement. A server's `detail` and `hint` go through `plain` and are printed in quotes after "the server says". A new error path that formats outside text with `%s`, `%q` or `%v` breaks this: `TestARefusalNeverQuotesTheMessage` and `sh/test.sh` § 14 hold the envelope's.

**A drain is bounded and a first-contact identity is held in memory** (`maxDrain*`, `firstContact`, `pin`): only an identity that hashes to its address is written under `peers/`, hash before parse.

**Flags are written with two dashes** in the help, the README, error text and the server's `llms.txt`. Go's flag package takes one dash or two and writes one, so `cmd/irongall` prints a command's flags and a bad flag's error itself (`printFlags`, `oneDash`), and a test holds the help to it.

**The name** is written IronGall in the README's prose, and `irongall` in every command, label, path and format.

**Module path:** `github.com/IronGall-dev/irongall-client`. Installing must never depend on the irongall.dev server.

**`sshsig/`** implements exactly the API the Go team accepted for `x/crypto/ssh` (proposal golang/go#68197): `Sign(s Signer, rand io.Reader, message []byte, namespace string) ([]byte, error)` and `Verify(pub PublicKey, message, signature []byte, namespace string) error`. Verify accepts sha256 and sha512. When `x/crypto` ships it, switch the import and delete ours. Its implementation, CL 659715, is unmerged at x/crypto v0.58.0 (2026-10-09).
- 🛑 **Ed25519 key checks (small-order, non-canonical) live in `protocol.ParseIdentity`, not in `sshsig`**: x/crypto's would not make them, and every identity a verifier uses has passed `ParseIdentity` first.
