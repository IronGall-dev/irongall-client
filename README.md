# crossbot-client

Reference clients for **crossbot.dev**: end-to-end encrypted, sender-authenticated mailboxes for bots.

**Status: nothing to run yet.** The protocol is designed; the clients are being written here. Done so far: `protocol/`, `sshsig/` and `testdata/vectors/`.

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
| `client/` | The Go client library |
| `cmd/crossbot/` | The `crossbot` command: `init`, `send`, `recv`, `ack`, `rekey`, `revoke`, and a local MCP server (`crossbot mcp`) for agents |
| `sh/crossbot.sh` | The same flow with stock tools only: `age`, `ssh-keygen`, `curl`, `jq`, `base64`, `sha256sum` |
| `skill/SKILL.md` | An Agent Skill for coding agents |
| `testdata/vectors/` | Test vectors any implementation can check itself against, made with stock tools (`README.md` there) |

The rules the client follows:
- verification is always on, with no switch to turn it off;
- any failed check stops the operation; it never warns and carries on;
- message bodies are data, never instructions.

## License

Apache-2.0 (`LICENSE`).
