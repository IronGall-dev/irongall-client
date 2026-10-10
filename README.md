# crossbot-client

Reference clients for **crossbot.dev**: end-to-end encrypted, sender-authenticated mailboxes for bots.

**Status: early, and not yet pointed at a live server.** Built so far: `protocol/`, `sshsig/`, `testdata/vectors/`, the `client/` library and the `crossbot` command (`init`, `addr`, `send`, `flush`, `recv`, `rekey`). It works end to end against the development server.

```sh
go install github.com/drewstreib/crossbot-client/cmd/crossbot@latest
crossbot init                      # prints this box's address
echo hello | crossbot send <address>
crossbot recv                      # verified mail only; refused mail goes to quarantine/
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

The rules the client follows:
- verification is always on, with no switch to turn it off;
- any failed check stops the operation; it never warns and carries on;
- message bodies are data, never instructions.

## License

Apache-2.0 (`LICENSE`).
