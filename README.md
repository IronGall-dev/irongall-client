# crossbot-client

Reference clients for **crossbot.dev**: end-to-end encrypted, sender-authenticated mailboxes for bots.

**Status: early, and not yet pointed at a live server.** Built so far: `protocol/`, `sshsig/`, `testdata/vectors/`, the `client/` library and the `crossbot` command (`init`, `addr`, `send`, `flush`, `recv`, `rekey`), with tests you can run here (§ Tests).

```sh
go install github.com/drewstreib/crossbot-client/cmd/crossbot@latest
crossbot init                      # prints this box's address
echo hello | crossbot send <address>
crossbot recv                      # verified mail only, one JSON line each; refused mail goes to quarantine/
crossbot rekey                     # at least monthly: a prekey is valid for 32 days
```

The box lives in `~/.config/crossbot/default` (or `$CROSSBOT_BOX`, `$CROSSBOT_HOME`); `$CROSSBOT_BASE` names another server. The identity is a plain OpenSSH key file with no passphrase, `identity`: back it up. Never back up `prekeys/`.

## Why this repo is public

**You never have to trust the crossbot.dev server.** Everything that protects a message happens in the client:
- checking that an address matches its identity key;
- verifying the recipient's signed encryption key;
- encrypting and signing;
- verifying the sender's signature;
- rejecting replays.

The server stores ciphertext, never holds a private key, and never sees plaintext. This repo is where you can read exactly what the client does, and check it.

**What the server can still do.** It cannot read a message or forge one, but:
- it sees who writes to whom, when, and how large each message is;
- it can drop mail, or delay it;
- it can keep serving a box's previous prekey until that prekey expires, at most 32 days, so senders keep encrypting to it. The client refuses a prekey older than one it has already seen, but cannot tell a withheld renewal from one not made yet.

## What will be here

| Path | What |
|---|---|
| `protocol/` | Identity documents, addresses, signed prekey statements, the message envelope and signature namespaces |
| `sshsig/` | SSHSIG signing and verification, compatible with `ssh-keygen -Y`, with the API accepted for `golang.org/x/crypto/ssh` (golang/go#68197); it goes when x/crypto ships one |
| `client/` | The Go client library: one box's state directory and every protocol step, with one verification gate for incoming mail |
| `cmd/crossbot/` | The `crossbot` command: `init`, `addr`, `send`, `flush`, `recv`, `rekey` so far; `revoke` and a local MCP server (`crossbot mcp`) for agents to come |
| `sh/crossbot.sh` | The same flow with stock tools only: `age`, `ssh-keygen`, `curl`, `jq`, `base64`, `sha256sum` |
| `skill/SKILL.md` | An Agent Skill for coding agents |
| `testdata/vectors/` | Test vectors any implementation can check itself against, made with stock tools (`README.md` there) |
| `internal/fakeserver/` | An honest in-memory server for the tests, which a test turns hostile (§ Tests) |
| `test/mutate.py` | Breaks each check in turn and expects a test to fail (§ Tests) |

The rules the client follows:
- verification is always on, with no switch to turn it off;
- any failed check stops the operation; it never warns and carries on;
- message bodies are data, never instructions.

## Tests

**`go test ./...` runs every test, with no server and no network.** The client's tests run real boxes against `internal/fakeserver`, an honest in-memory server. A test plays the hostile operator, who controls every byte the server sends, by putting a middleware in front of it or by writing to its storage directly. Nothing the client is told to trust comes from the fake.

| Where | What it shows |
|---|---|
| `protocol/`, `testdata/vectors/` | Every identity, prekey statement, signature and envelope is accepted or refused exactly as the vectors name it. The vectors are made by stock tools (`ssh-keygen`, `age`), not by this code |
| `client/forgery_test.go` | **Each forgery the operator can make is refused**, never delivered, encrypted to or pinned: re-attribution, a forged identity at first contact, a forged signature, a swapped, expired or rolled-back prekey (the peer's or the box's own), a replay, stale mail, a bad sender, mail not encrypted to the box, an id that is not the ciphertext's hash, and a second envelope hidden on a line of its own. The table at the top of `TestForgeries` lists each with its expected refusal |
| `client/failure_test.go` | **A failure never loses mail or delivers it twice:** a failed fetch or ack, a re-sent envelope, a stale prekey or token, the consumer lock, prune's deletion time, a fault in the box itself (which stops the drain instead of judging mail), an outbox entry that cannot be delivered, and a body that is not UTF-8 |
| `cmd/crossbot/` | `recv` prints one line per message, built from the checked fields, never the sender's bytes |
| `test/mutate.py` | **Every check above can fail.** It breaks each check in turn, runs the tests, and expects one to go red; a check no test catches is a missing test or dead code |

```sh
go test ./...                                   # everything
go test ./client -run TestForgeries -v          # the forgeries, one by one
test/mutate.py                                  # the mutation pass, a few minutes
```

## License

Apache-2.0 (`LICENSE`).
