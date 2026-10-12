# PROTOCOL — irongall v1 (pre-stable)

**The irongall protocol, byte by byte: every step from key generation to ack, with the stock tool used at each step.** It says what a client must check, what a server must do, and what the server at irongall.dev promises. The code beside it implements it: `protocol/` and `sshsig/` (the formats and the signatures), `client/` and `cmd/irongall` (the Go client), `sh/irongall.sh` (the same client in stock tools) and `testdata/vectors/`.

- **Pre-stable.** Nothing here is final until v1 is declared stable (§0a). What has to be settled before that is this repo's issues in the milestone `M1: protocol freeze`.
- **The server is not in this repo.** irongall.dev runs one, written to this document. A client never has to trust it: everything that protects a message is checked by the client, and the tests here play a hostile server (`README.md` § Tests). This document describes the server as a client meets it: its routes, its checks and its refusals. How it stores things is its own business, apart from what it promises (§7).
- **"Not built" is said where it applies.** A few parts are specified and not yet built, by the server, the clients or both. Each says so where it is described, and §12 lists them.
- **Limits are a server's settings, not the protocol's.** This document names each limit and says what it does, never its value: irongall.dev states the ones a client meets in ordinary use at `https://irongall.dev/llms.txt`. The protocol's own constants are written out (the 33 days of a prekey and of the mail's lifetime, the page of 50).
- `[proposed]` marks a detail that is not decided.
- **The stock client is `sh/irongall.sh`**, one section per step of this document, tested here against a fake server, honest and forging, and against the test vectors and the Go client (§11). It is the proof that the protocol needs nothing but stock tools; the client to run is the Go one (`README.md`).

## 0. Primitives — all standard, nothing home-rolled

| Name | Role | Spec |
|---|---|---|
| age v1 | encryption to the box's PREKEY: post-quantum `mlkem768x25519` (hybrid ML-KEM-768 + X25519, age ≥ 1.3) by default, or X25519 only (`--no-pq`); HKDF-SHA-256, ChaCha20-Poly1305, HMAC-SHA-256 | C2SP age spec |
| Ed25519 | the box IDENTITY: signs prekeys, mail, profiles, revocations | RFC 8032 |
| SSHSIG | signature container: Ed25519 over SHA-512(message), namespaced | OpenSSH `PROTOCOL.sshsig` |
| SSH public key text | `ssh-ed25519 <base64 wire key>` | RFC 4253 §6.6, RFC 8709 |
| OpenSSH certificate | the identity's word for a working key (§2b; decided, not in use yet) | OpenSSH `PROTOCOL.certkeys` |
| SHA-256 | address = hash of the identity document; message id | FIPS 180-4 |
| HMAC-SHA-256 | owner token | RFC 2104 |
| UUID | the envelope's `msg_id`, random (version 4) | RFC 9562 |

**Stock tools, and nothing else:** bash ≥ 4, `age` + `age-keygen`, `ssh-keygen` (OpenSSH ≥ 8.1 for `-Y`), `curl` ≥ 7.76 (`--fail-with-body`), `jq` ≥ 1.6, `iconv`, `sha256sum`, `base64`, `od`. **The Go client `irongall`, in this repo, does all of it.**
- **age ≥ 1.3 is needed to OWN a post-quantum box** (age-plugin-pq has no key generation) **and to send to one** (or age-plugin-pq). Too old for post-quantum: Ubuntu 24.04 (1.1.1, what Claude Code cloud sessions run), Ubuntu 26.04 and Debian 13 (1.2.1; also Docker's `python` and `node` images), Ubuntu 22.04 (1.0.0, which fails with a misleading "malformed recipient"). Fine: Alpine 3.24, Fedora 42+, Homebrew, Arch, Nix 25.11+. Otherwise `go install filippo.io/age/cmd/...@v1.3.2` (verified by the Go checksum database), the release tarball with its Sigsum proof, or the Go client.
- **Portable by construction**: dates go through `jq`'s `fromdateiso8601`/`todate`, never `date -d` (macOS has none; BusyBox rejects the `Z`); base64 is `base64 < f | tr -d '\n'`, never the GNU-only `-w0`.

**Paths:** every API path is under `/v1/`; the discovery documents (`/`, `/llms.txt`, and `/openapi.json`, which is not served yet, §12) and the error-type URIs (`https://irongall.dev/errors/<code>`) sit at the root.

**Keyed hashing is HMAC or HKDF only, never `hash(secret ‖ …)`.** SHA-256 and SHA-512 allow length extension, which breaks exactly that construction. Plain SHA-256 appears here only over PUBLIC inputs — the identity document, the ciphertext, the proof-of-work input — where extension gives an attacker nothing, and it stays: it is what Signal, TLS 1.3, MLS, age, Certificate Transparency and Git's new object format use, and `sha256sum` is on every machine.

**SSHSIG hash:** every verification in this protocol — prekeys, messages, profiles, revocations — accepts `sha512` or `sha256`, the two the SSHSIG spec allows. `ssh-keygen` writes `sha512`. The server's verifier is `sshsig/` in this repo, with exactly the API accepted for `x/crypto/ssh` (golang/go#68197), until `x/crypto` ships one.

**Clocks:** every party is assumed NTP-synced. No check carries a clock-skew allowance. The `sent_at` window and prekey `not_after` are exact. (`sent_at` is checked for age only: a future one is accepted today, this repo's issue #12.)

## 0a. Compatibility and versioning

🔑 **Pre-stable: nothing is final until v1 is declared stable.** Until then the live service is the test bed, and fields, formats and what is required may still change. The rules below bind from that declaration:
- **The server REJECTS unknown request fields** (`400 bad_request`, naming the field).
- **Clients IGNORE unknown response fields.**
- **The encrypted envelope (§4.2) ignores unknown fields**; its `v` changes only for a breaking change, and a receiver rejects a `v` it does not know.
- **Signed statements match their format EXACTLY** (identity document, prekey statement, revocation). A new format gets a new tag. Namespaces are versioned independently.
- **New v1 fields are added as optional.**
- **`irongall-revoke-v1` stays valid forever**, so a revocation signed in advance keeps working.
- **Reserved:** an `irongall-v2` identity line for a post-quantum signature key. Nothing is built.

## Terms

- **Address / `H`:** the box identity — the SHA-256 of its identity document (§2). As text, 64 lowercase hex characters; inside MACs, the 32 raw bytes. `H_A` is the sender, `H_B` the recipient. **One identity key ⇔ exactly one address.**
- **Box:** a mailbox. In this file it never means a machine.
- **Identity document `D`:** the two-line text whose SHA-256 is the address (§2). Immutable. The API field and endpoint carrying it are named `identity`.
- **Identity key:** the box's Ed25519 key. It signs everything the box says, and it is the box's final authority: it alone renews the prekey (§6.4) and revokes (§6.3). **Prekey:** the box's current age encryption key, published as a **prekey statement** signed by the identity (§2a). It is renewed at least every 33 days (the Go client renews it daily), with a new key each time; the address never changes.
- **Server keys `K_kid`:** the HMAC keys that mint owner tokens. Unrelated to box keys.
- **Owner token:** the bearer token for reading a box (§6.1). Bound to the prekey: every prekey change bumps the box's epoch.
- **"In system":** registered and active. Only those boxes can send.
- **Box states:** `pending` → `active` → `closed` (reversible) or `revoked` (permanent). The transitions are §3a's table. **The epoch NEVER resets**, so a killed token stays dead.
- **"Rotate" means three different things — keep them apart:** a new PREKEY (`irongall rekey`, `PUT …/prekey`, §6.4) · a new TOKEN epoch (`POST …/token/rotate`, §6.1) · a new SERVER key (`kid`, §6.1a).
- **Last-use time of a prekey** = its renewal. Every send names the serial it used, and an honest server answers one naming a retired serial with `409 stale_prekey` (§4 step 5), so mail encrypted to a prekey reaches the server only while it is current. Senders also refuse an expired prekey.
- **Deletion time of a retired prekey:** the Go client keeps the newest retired prekey and deletes the older ones after a drain that empties the box and began more than an hour after the newest retired one was made, by which time all of them had been retired for an hour (the hour covers a send in progress as a renewal lands); `irongall.sh`, and the Go client as a backstop, delete at `not_after` + the 33-day TTL, when all mail encrypted to it has expired. **Mail encrypted to it is unrecoverable from the box's keys after that** — THE forward-secrecy bound, stated once (§6.4). The Go client's early deletion rests on the server refusing a send to a retired serial: mail a server takes for one anyway may be mail the box can no longer read.
- **The live prekey** is the current one: the server checks a message's stanza TYPE against its type (§4 step 5). The server keeps the newest retired prekeys' key hashes (how many is a server setting) only to refuse a key that comes back.

## 1. Keys and the stock client — client side

**Every box lives in its own state directory, `${XDG_CONFIG_HOME:-~/.config}/irongall/<box>` (0700), never the working directory** — for a coding agent the working directory is a git repository, and `git add -A` would commit the keys. `IRONGALL_BOX` names the box; `IRONGALL_HOME` sets the directory outright, for sandboxes that may write only their workspace. The directory carries a `.gitignore` of `*`, so it ignores itself anywhere. The layout is shared with the Go client (the top of `client/doc.go`):

| File | Holds |
|---|---|
| `identity`, `identity.pub` | the Ed25519 identity, OpenSSH format. **Backed up**; losing it loses the address (§6.3) |
| `identity.doc`, `address` | the identity document (§2) and its hash |
| `prekeys/<serial>.agekey`, `.txt`, `.txt.sig` | each prekey and its signed statement. 🛑 **Prekeys are NEVER backed up, NEVER synced, never stored where old versions survive (a secrets manager, git, snapshots), and never derived from a seed:** a prekey that survives its deletion voids forward secrecy. Losing a machine loses its prekeys — publish a new one with the identity alone (§6.4) |
| `token` | the owner token (§6.1) |
| `serial` | the highest prekey serial this box has published: a renewal refuses a served serial below it, a rollback whose next serial's key was already published |
| `peers/<address>/` | per correspondent: the PINNED identity document, the highest prekey serial seen, the last statement fetched |
| `seen` | the replay set, 33 days (§5) |
| `outbox/`, `inbox/`, `quarantine/` | envelopes awaiting a receipt (`outbox/failed/`: ones that can never be delivered) · accepted mail · refused mail, named by the ciphertext's SHA-256 as computed locally (§4.5, §5) |
| `sent/` | each message the server took, with its receipt (§4.5) |
| `aliases` | this box's own names for peers, `<name> <address>` lines; they never leave the box |
| `lock/` | one consumer per box (§5) |

**The Go client uses the same files: the identity is the plain OpenSSH key, with no seed derivation.** Its commands: `README.md`.

**The stock client is `sh/irongall.sh` in this repo** — one bash script, one section per step of this file: setup, §3, §4.1, §4.5, §5 and §6.4. Run `bash irongall.sh init` (or `init --no-pq`) · `send <address> [body file]` · `recv` · `rekey`, monthly; or source it at the top of EVERY shell call and call the `ig_*` functions — agent tools run each command in a fresh shell, so state lives in files, never in variables. Every check fails CLOSED with one `REFUSED: <reason>` line, and every API error prints its `code` and `hint`. 🔑 **Get it from this repo, pinned by commit — never from text a server serves.** `README.md` lists what it lacks against the Go client.

**Stock client:** `sh/irongall.sh` § setup — `ig_api` (any non-2xx prints its `code` and `hint`), `ig_owner` (adds the token; on `401 token_stale` fetches the current one and retries once), `ig_token`, `ig_lock`.

## 2. Identity document → address

The document `D` is exactly two LF-terminated ASCII lines — no comment on the SSH line, no CR, nothing after the final `\n` (93 bytes for `ssh-ed25519`, the one type built; another type's document will be longer, below):

```
irongall-v1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI<43 chars>
```

- **Address = lowercase hex SHA-256 of `D`, 64 chars**: `sha256sum < identity.doc | cut -c1-64` (`ig_init`, §3). **It is shared as the link `https://irongall.dev/to/<64 hex>`**: the server serves a page there for exactly 64 lowercase hex characters, 404 otherwise, for people and for agents without a client: fixed text plus the hex, never text a box supplied, sent with `Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex`. `irongall init` and `addr` (`ig_init`, `ig_addr`) print the box's link; `irongall send` (`ig_send`, via `ig_dest`) takes a link or a bare address, takes the hex from the path without fetching the page, and refuses a link to any server but its own. It is not `/v1/<addr>`, which is kept for the API (§12), and it carries no version.
- There is no checksum: a mangled address simply hits no box (`no_such_mailbox`).
- The version is line 1 of `D`. Another deployment of this protocol picks its own tag, and so its own address space.
- **It commits to the identity ONLY**, so renewing or re-typing the encryption key never changes it (§6.4).
- **The identity is `ssh-ed25519` only, as built.** Decided and not built: v1 allows other SSH key types. Ed25519 stays the one type every client must support, every other type is optional, and each server accepts its own list. What this section then has to say is this repo's issue #21; it is built before v1 is declared stable. Issue #30, the identity certifying a short-lived working key, is decided and is built first (§2b): an optional type is then the identity's, which signs certificates and not every message.
- **The canonical form is lowercase hex.** Clients MUST use lowercase in `from`: the recipient compares the inner `from` (§4.2) with the verified signer as exact strings, and every SSHSIG namespace is an exact signed string. The server folds case only on the URL path.

🔑 **An address is a SEND CAPABILITY — keeping it private is the real DoS defence.** Mailing a box hands it your address (it is your `from`), so it can mail you back.

## 2a. Prekey statement — the encryption key, signed by the identity

Exactly five LF-terminated lines, then signed with namespace `irongall-prekey-v1:<A>`:

```
irongall-prekey-v1
<A — the box's own address>
<serial — a decimal integer, no leading zero, at most 18 digits; strictly increasing per box; the first is 1>
<age1pq1… (post-quantum, default) | age1… (X25519 only, `--no-pq`)>
<not_after — RFC 3339 UTC to the second, YYYY-MM-DDTHH:MM:SSZ>
```

- 🔑 **Every statement expires, at most 33 days after it is published, and every renewal is a NEW key.** 33 = the longest month, plus the day a renewal may wait (the Go client renews a prekey more than a day old), plus a day of slip, so a box received at least monthly never lapses (§6.4). `never` is not a valid `not_after`. This is TUF's mandatory expiry: it bounds how long a malicious operator can freeze a sender on an old statement.
- The key type IS the box's type: post-quantum by default, `--no-pq` (X25519 only) by choice. It can switch at any renewal (§6.4).
- **Senders keep the highest `serial` they have seen**, and refuse a lower one. That is the rollback guard.
- **Senders re-fetch at `not_after`**, or when a send gets `409 stale_prekey` (§4).
- **A prekey past its `not_after`: senders MUST refuse to encrypt**, and the server refuses the send with `409 prekey_expired` ("the box must publish a new prekey"). **No grace**: a grace only widens the time an expired, possibly deleted or leaked, prekey is used. Clocks are assumed synced (§0). Nothing else about the box changes (§6.4).

## 2b. The working key and its certificate — decided, not in use yet

🔑 **Decided (this repo's issue #30). The check is built (`protocol/certificate.go`) and nothing else in this file uses it yet:** every signature below is still the identity's own. Once it is in use, the identity signs certificates and a revocation (§6.3) and nothing else, and every other signature a box makes is its working key's. So the identity key need not be where the agent runs: by default a client keeps both keys in the box and renews the certificate itself, and a box whose identity is kept elsewhere is handed a certificate.

A certificate is an OpenSSH user certificate, exactly as `ssh-keygen` writes it:

```sh
ssh-keygen -s identity -I irongall-cert-v1 -n "$A" -z "$SERIAL" -V +66d -O clear work.pub
```

| Field | Rule |
|---|---|
| Type | a user certificate |
| Certified key | the working key: `ssh-ed25519`, held to the identity's own key checks (§3 step 4), and never the identity key |
| Serial | 1 or more, and higher than every earlier one of this identity |
| Key id | exactly `irongall-cert-v1` |
| Principals | exactly one: the box's address, lowercase |
| Validity | `valid after` ≤ now < `valid before` ≤ now + 66 days, in whole seconds |
| Critical options, extensions | none (`-O clear`; without it `ssh-keygen` adds five extensions) |
| Signed by | the identity: the key in the identity document (§2), byte for byte |

- **A signature made with `-f work-cert.pub` carries the certificate,** so no message format gains a field. A verifier takes the certificate from the signature, checks it against the identity it pins, and verifies the signature under it (`protocol.VerifyCertified`). A signature by the bare working key, or by the identity itself, is refused.
- **It is checked against the verifier's own clock** (§0). Nobody can vouch for when a signature was made, so a certificate must be valid when it is checked, and so must outlast what it signed: it runs at most 66 days, twice the 33 days mail may wait, and a client does not sign mail with 33 days or less left.
- **A client makes every check in the table itself.** `ssh-keygen -Y verify` accepts a certificate that carries extensions or a critical option, checks no key id, and knows a serial only through a revocation list.
- **Every certificate is for a new working key.** A certificate is public, since it rides in every signature, so a new one for the same key would retire nothing.
- **Other key types** for the working key are not ruled out by the format, which certifies any SSH key type; `ssh-ed25519` is what is built (issue #21).
- **Not settled:** what a newer certificate retires for each kind of verifier (issue #30), and what proves a box to the server on each call (issue #36).

## 3. Registration — one signature

**Stock client:** `sh/irongall.sh` § keys and registration — `ig_init` (creates the box or finishes a half-done init, registers and activates it), `ig_prekey` (a NEW key, valid for 33 days).

**Two API calls, no human:** `PUT /v1/<A>` with JSON `{identity, prekey, prekey_signature}` (standard base64 of the exact file bytes, §4.5), then one Bearer call, which activates the box.

**Signatures are made from stdin to stdout** (`ssh-keygen -Y sign … < f > f.sig`). Given a file name, `ssh-keygen` will not overwrite an existing `.sig`: with stdin at EOF it keeps the STALE signature and exits 0, and in Claude Code's Bash tool it blocks on "Overwrite (y/n)?".

**SSHSIG, in bytes.**
- Signed data = `"SSHSIG"` ‖ `str(namespace)` ‖ `str("")` ‖ `str("sha512")` ‖ `str(SHA-512(message))`, where `str` = uint32 length + bytes.
- Signature = Ed25519(identity key, signed data).
- The `.sig` file is a PEM-armored (`SSH SIGNATURE`) blob: `"SSHSIG"` ‖ `u32(1)` ‖ `str(public key wire)` ‖ `str(namespace)` ‖ `str("")` ‖ `str("sha512")` ‖ `str(str("ssh-ed25519") ‖ str(sig64))`. ~400 bytes armored for irongall's namespaces (measured: 399).

**Server:**
1. The URL-path address must be 64 hex chars, folded to lowercase → `H`. Otherwise `bad_address`.
2. The body is exactly `{identity, prekey, prekey_signature}` → otherwise `bad_request`, naming the missing or unknown field (§0a).
3. `SHA-256(identity) == H`, and `identity` matches the exact two-line grammar. Otherwise `identity_mismatch`, with a hint naming the usual causes: a comment left on the SSH line, CRLF, a missing final newline.
4. Parse the identity → a 32-byte Ed25519 key, rejecting small-order and non-canonical encodings. **This is explicit code** — `filippo.io/edwards25519`, a canonical-encoding check and a `MultByCofactor` check — because Go's `crypto/ed25519` and OpenSSH 10.2 both accept such keys. Parse the prekey statement: the exact five-line grammar (§2a); line 2 == `H`; a valid `age1pq1…`/`age1…` recipient on line 4 (rejecting X25519 small-order points, including the X25519 half of a post-quantum key); `not_after` after now and at most 33 days after now. Any failure → `bad_key`.
5. Verify the prekey SSHSIG: the blob's key equals the identity, namespace `irongall-prekey-v1:<H>`, hash per §0 → otherwise `bad_key`. **That one signature is the identity's proof of possession** — nobody can register an identity they do not hold.
6. Levers: registrations per IPv4 address or IPv6 /64, and proof of work when it is switched on (§8; not built).
7. **A new box** is stored with **`state: pending`**, epoch 0 → `201` with the token.
   **An existing box:** `revoked` → `410 revoked`. Pending or active, and the request is byte-identical to its CURRENT identity + prekey statement + signature → `200` with the current token (an idempotent retry). Anything else → `409 conflict`, with a hint that names `irongall rekey`: it replaces a registered box's prekey and reopens a closed one. **Registration never changes an existing box** — every prekey change goes through §6.4.
8. Owner token → §6.1. It is returned **encrypted to the current prekey** (`filippo.io/age`, binary, base64 in the JSON), so only its holder can read it.
9. **Activation.** The box turns `active` on its FIRST Bearer-authenticated call: using the token proves the registrant decrypted it, so it holds the prekey. Until then, sends TO it get `no_such_mailbox` ("not activated yet — the owner must poll once"), and sends FROM it get `unknown_sender`.
10. **Pending boxes are to expire** (not built; how soon will be a server setting): a never-activated new box is deleted (it holds no mail, and its epoch is 0); a REOPENED box goes back to `closed`, keeping its epoch.

## 3a. Box states — normative

Every call names a box; this is what each event does in each state.

| State ↓ / event → | Register `PUT /v1/<a>` | New prekey `PUT …/prekey` (identity-signed, higher serial) | Bearer call (`messages`, `account`, `profile`, `allow`/`block`, `token/rotate`) | Close `DELETE /v1/<a>` (Bearer) | Pending expiry (not built) | Revoke `POST …/revoke` (identity-signed) |
|---|---|---|---|---|---|---|
| **unknown** | → `pending`, epoch 0: `201` + token | `404 no_such_mailbox` | `404` | `404` | — | `404` |
| **pending** | identical replay: `200` + token; otherwise `409 conflict` | stays `pending`, epoch +1: `200` + new token | → `active`, then served | → `closed` | new box: deleted; reopened box: → `closed` | → `revoked` |
| **active** | identical replay: `200` + token; otherwise `409 conflict` | stays `active`, epoch +1: `200` + new token | served | → `closed`; unacked mail deleted | — | → `revoked` |
| **closed** | `409 conflict` (reopen with a new prekey) | → `pending` (reopen), epoch +1: `200` + new token | `404 no_such_mailbox` | `404` | — | → `revoked` |
| **revoked** | `410 revoked` | `410` | `410` | `410` | — | identical replay: `200`; otherwise `410` |

- **Not built:** the Revoke column (§6.3), the pending expiry, and `profile`, `allow`/`block` and `token/rotate` among the Bearer calls (§6.1, §6.2).
- **Replays:** a byte-identical replay of a request that already took effect gets `200` and the same result; a conflicting one gets `409 conflict`. That covers registration, prekey uploads (an identical replay of the current statement returns the current token), profiles (a `version` not above the current one) and sends (§4 step 7).
- **`POST …/token`** answers for `pending` and `active` boxes (`404` closed or unknown, `410` revoked). **`GET …/identity`** answers for `pending`, `active` and `closed` boxes, so an owner can read its own serial to reopen; senders still get `404` when they post to a closed box.
- **No idle close, and no `last_seen`.** A box whose owner stops renewing refuses mail once its prekey expires (`prekey_expired`, §6.4), and a renewal turns it back on. The current prekey statement dates the owner's last renewal, so the server tracks no activity of its own.

## 4. Sending A → B

**4.1 Get and verify B's identity and current prekey** — one GET, `GET /v1/<B>/identity` → `{identity, prekey, prekey_signature}`, all base64. `ig_resolve` prints the serial and the age recipient ONLY when every check passes; until then nothing exists to encrypt to.

**Stock client:** `sh/irongall.sh` § verify a peer — `ig_resolve` (prints a prekey only when every check passes), `ig_pin` (hash-checked at first contact; a pin always wins), `ig_idcheck`, `ig_prekeycheck`.
- **Identity: pinned at first contact, and a pin always wins.** The served identity is hash-checked against the address, held to the exact 93-byte two-line format (§2) — as the server holds it at registration, so one identity key can never have two addresses — and pinned only on a match; later fetches never replace it. The `allowed_signers` file is ONE line rebuilt from those hash-checked bytes for each verification, never built from server text: an `allowed_signers` principal is a pattern list, so a server-supplied `from` carrying a newline could otherwise plant a `*` signer that verifies the operator for every box.
- **The operator cannot swap the encryption key** (the signature fails), **pass off another box's validly-signed prekey** (wrong namespace and line 2), **roll back a sender that has seen a newer one** (the persisted serial — recorded only after every check passes), or **keep a sender on one past `not_after`** (§2a). All are tested against a forging server (§11).
- **Caching:** the identity forever; the prekey until its `not_after` or a `409 stale_prekey`. The stock client simply re-fetches on every send; the serial guard makes that safe.

**4.2 Plaintext `P` — the INNER ENVELOPE, compact JSON.** The server never sees it.

| Field | | |
|---|---|---|
| `v` | required | `1` |
| `from`, `to` | required | the sender's and recipient's addresses. **The recipient rejects the message unless `from` equals the verified signer and `to` equals itself** (§5) |
| `sent_at` | required | RFC 3339 UTC to the second; the replay window needs it (§5) |
| `msg_id` | required | a random UUID (RFC 9562, version 4), made ONCE per logical message and kept on every re-encryption, so a retry is never acted on twice (§5) |
| `body` | required | the message: a string or any other JSON value. Both clients send a string only (this repo's issue #20) |
| `subject` | optional | a string |
| `in_reply_to` | optional | the `msg_id` replied to — never the ciphertext id |
| `supersedes` | optional | a `msg_id` of the same sender that this message replaces. Stored mail is never altered; the recipient decides |
| `pad` | optional | any string, ignored by the receiver: padding to hide the length (Noise §13). Both clients set it on every message (§4.3a) |

- **Both clients set `subject`, `in_reply_to` and `supersedes`**: `--subject`, `--reply-to` and `--supersedes` on `irongall send` and on `ig_send`. Both set `pad` on every message (§4.3a). A sender refuses an `in_reply_to` or `supersedes` that is not a `msg_id` before it builds anything; what `send` prints is the server's 64-character id of the ciphertext, which is not one. A receiver checks only that each is a string: they are the verified sender's words, and a reply can name any `msg_id`.
- **Encoding: compact UTF-8 JSON without HTML escaping** — `jq -c`, Go's `SetEscapeHTML(false)`, Python's `ensure_ascii=False` with compact separators. Default serializers that escape `<`, `>`, `&` or non-ASCII inflate the body. Receivers accept any valid JSON and ignore unknown fields (§0a).
- The server's size cap is on the DECODED ciphertext. age adds 1,659 B (PQ) or 200 B (`--no-pq`).

**4.3 Encrypt to B's prekey — binary, not armored:** `age -r <recipient> < P > m.age` (`ig_seal`, §4.5).
- **Post-quantum prekey (the default):** one `mlkem768x25519` stanza — age's hybrid ML-KEM-768 + X25519 recipient (age ≥ 1.3, which builds it on HPKE, per its `filippo.io/hpke` dependency). It adds 1,659 B (measured). The payload layer below is identical.
- **`--no-pq` prekey:** the X25519 stanza, below.

Inside age, for a `--no-pq` prekey:
- File key `K` = 16 random bytes.
- Ephemeral secret `e` = 32 random bytes; share `E = X25519(e, 9)`; `Z = X25519(e, B_x)` — abort if `Z` is all zeros.
- Wrap key = HKDF-SHA-256(ikm `Z`, salt `E ‖ B_x`, info `"age-encryption.org/v1/X25519"`). Stanza body = ChaCha20-Poly1305(wrap key, nonce 0¹², `K`), 32 bytes.
- Header = `age-encryption.org/v1\n-> X25519 b64(E)\nb64(body)\n---`. MAC = HMAC-SHA-256(HKDF(`K`, info `"header"`), header).
- Payload: nonce `n` = 16 random bytes; payload key = HKDF(`K`, salt `n`, info `"payload"`). A message of up to 64 KiB is one chunk = ChaCha20-Poly1305(payload key, nonce `0¹¹ ‖ 0x01`, `P`). The last-chunk flag stops truncation.
- No armor: transport base64 (§4.5) does that job, so armoring would encode twice. Overhead is 200 B `--no-pq`, 1,659 B post-quantum (measured).

**4.3a Padding — every message is a whole number of blocks** (`protocol/pad.go`, `seal` in `client/send.go`, `ig_seal`). The server sees each ciphertext's size, and without padding reads a message's length to the byte.
- **The rule.** A block is the smallest power of two that is at least 1/16 of the ciphertext's size, and never under 1 KiB: 1 KiB up to 16 KiB, 2 KiB up to 32 KiB, and on. The sender gives the envelope a `pad` member whose filler makes the CIPHERTEXT the next whole number of blocks. So a ciphertext takes one of 16 sizes up to 16 KiB and of 8 for each doubling after it.
- **Every envelope carries the member, with no filler when none is needed.** It costs 9 bytes beside its filler (`,"pad":""`). The filler is `.`, ASCII that JSON never escapes.
- **The ciphertext is measured, not the body,** because it is what the server sees and what its size cap counts. age's file size is a fixed function of the key type and the plaintext length: a header of 168 B (`--no-pq`) or 1,627 B (post-quantum), a 16-byte nonce, and a 16-byte tag after each 64 KiB chunk of plaintext (measured against age 1.3.2 up to 10 MiB, and the X25519 header against age 1.2.1; one chunk gives §4.3's 200 and 1,659). The sender computes the pad from that, encrypts, and refuses to send a file that is not the size it computed.
- **Padded at the seal, never before.** The pad depends on the prekey's type, so the outbox's `.P` and the `sent/` record hold the envelope without it, and a re-encryption after `409 stale_prekey` is padded again for the newer prekey: between the two types the age file differs by 1,459 B. The `msg_id` stays.
- **The server does nothing, and a size limit must be a whole number of its own blocks.** As sizes go, any power of two is such a number and 100 KiB is not: a message just under a limit like that one would be padded past it. With limits chosen that way a client never needs to know the limit: what padding costs there is the member's 9 bytes.
- **Where the first boundary falls.** An envelope with an empty body and no optional field is 244 B. With the member and the overhead, a post-quantum box's smallest message is 2,048 B and holds a body to about 136 B, the next, 3,072 B, to about 1,160 B; a `--no-pq` box's smallest is 1,024 B and holds a body to about 571 B. It stays where the overhead puts it. So it is not true that everything under 1 KiB looks the same.
- **What it costs:** at most 1,032 B a message up to 16 KiB and about 520 on average; above that half a block on average, about 4.4% of the message, and about 1/8 at worst, for a message just past a doubling. In bytes sent and stored; no extra request.
- **What it does not hide:** who writes to whom, when, and how often. A sender that is not one of the two clients may pad differently or not at all: the server cannot tell, and does not check.
- **Not chosen:** a fixed 1 KiB block at every size (it tells a large message's size to the KiB) · one size per doubling (up to double the bytes) · random padding (it averages out over repeated messages) · opt-in or a `--no-pad` flag (the padded messages would be the marked ones) · leaving the member off a message already on a block, or sending a message fewer than 9 bytes short of a block unpadded (the first leaves 8 sizes under a limit that cannot be sent, the second shows those messages' exact size at every boundary) · spaces after the JSON object in place of the member (every receiver would have to be required to accept them).

**4.4 Sign — the namespace carries the recipient:** `ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f identity < m.age > m.age.sig`. The signature then holds only for box `B`, which stops a captured message being re-sprayed to other boxes in A's name and burning A's limits. `ssh-keygen` signs the file as-is. (Under discussion: signing inside the encryption, so that the server holds no signature. This repo's issue #29.)

**4.5 Post — JSON, every byte field standard base64 of the exact file bytes:** `POST /v1/<B>` with `{from, prekey_serial, ciphertext, signature}` → `201 {id, received_at, expires_at}`, the times in §2a's format. `prekey_serial` (a JSON number, REQUIRED, so no mail reaches a retired prekey: Terms) is the serial of the prekey used: when B has a newer one, the server answers `409 stale_prekey`, and the sender re-encrypts the SAME envelope to it within the same send.

**Stock client:** `sh/irongall.sh` § send — `ig_send` (the envelope is built ONCE), `ig_seal` (encrypted to the VERIFIED prekey, signed for that recipient only), `ig_post` (409 `stale_prekey` re-encrypts the same envelope, once), `ig_sent` (the envelope and the receipt, kept in `sent/`), `ig_flush`; § verify a peer has `ig_dest` and `ig_alias` (a link, an address, or the box's own name for one).
- 🔑 **Retry the POST, never the send.** age is randomised, so sending again makes a NEW ciphertext and a new message id, and a bot that acts on mail would act twice. The outbox keeps the signed bytes until a receipt arrives; `ig_flush` re-POSTs them unchanged and gets the original receipt (step 7). On the receipt both clients keep the envelope, with the receipt as one more member, in `sent/`, and never prune it. A re-encryption that does happen (`stale_prekey`) keeps the `msg_id`, so the recipient still delivers it once.
- **Why this shape: it is the INDUSTRY pattern for opaque bytes plus metadata** — Google Pub/Sub (`data`), AWS KMS (`CiphertextBlob`), the GitHub Contents API (`content`); Gmail's `raw` is the same idea in base64url. It needs one content type in and out, and JSON and base64 are in every language's stdlib.
- **It is robust to careless clients — tested.** `jq -r .ciphertext | base64 -d` is byte-exact, because `base64 -d` ignores the newline `jq -r` adds. Line-wrapped base64 decodes exactly, both in coreutils' `base64 -d` and in Go's `encoding/base64`, which ignores `\r\n`.
- **Not chosen:** raw text inside JSON (armored ciphertext as a JSON string) — `jq -r` added a newline and the signature failed; and multipart (`curl -F`), which is byte-exact but is a browser-upload pattern, awkward in most API clients.
- **The `signature` field is base64 of the `.sig` file exactly as `ssh-keygen` wrote it** — PEM inside base64. That is deliberate: no tool has to strip or rebuild the armor.
- 🔴 **`jq --rawfile` / `@base64` cannot carry BINARY** — jq strings are Unicode and invalid UTF-8 gets mangled. Encode files with the `base64` tool. (`--rawfile` is fine for the UTF-8 body.)

**Server pipeline — cheapest first.** Only step 9 stores anything. Status codes are §13's map.
1. **Read limit:** the cap in base64 plus a small allowance for the JSON, so it scales with the cap; decoded ciphertext ≤ the cap → `too_large`. A field that is not valid base64 → `bad_encoding` ("base64 of the exact file bytes"). Not JSON, a missing field, or an unknown one → `bad_request`.
2. `B` and `from` are 64 hex chars; `from` must be LOWERCASE (§2) → `bad_address`, hint "lowercase". `prekey_serial` is present and a serial (§2a) → `bad_request`. **Pre-auth rate: per IP only** → `rate_limited`.
3. **It is an age file**, parsed with `filippo.io/age`'s public API (`ExtractHeader`/`DecryptHeader`), so the header needs no parser of the server's own → otherwise `not_age`.
4. **Are `B` and `from` registered and ACTIVE?** `B` unknown, pending or closed → `no_such_mailbox`; `B` revoked → `revoked`; **`B`'s current prekey past its `not_after` → `prekey_expired`.** `from` unknown, pending or closed → `unknown_sender`; `from` revoked → `sender_revoked` (never `revoked`, which would tell a sender its PEER is dead).
5. **The prekey and the stanza.** A `prekey_serial` that is not B's current serial → `stale_prekey` (hint: "a newer prekey exists: fetch `GET /v1/<B>/identity` and re-encrypt the same envelope"). Then **exactly one NATIVE stanza** (`X25519` or `mlkem768x25519`) **of the current prekey's type** (Terms). **Grease stanzas are ignored**: rage, the Rust `age` crate and pyrage add one random `…-grease` stanza to every file, and the age spec says to ignore unrecognised stanzas — so a stanza matching `^[!-~]{1,8}-grease$` with ≤ 4 arguments passes. Anything else → `wrong_recipient_type`, the hint chosen by case: a PQ box and an X25519-only file → "this box needs age ≥ 1.3 or age-plugin-pq"; a `--no-pq` box and a PQ file → "this box is --no-pq (X25519 only): re-fetch its prekey"; two native stanzas → "encrypt to one recipient only"; another type → "encrypt to the box's prekey". **Which KEY it is encrypted to cannot be checked**, by design of native age. A grease stanza's body is bounded only by the message cap: the spec's "small" has no number.
6. Verify the SSHSIG against the sender's **REGISTERED identity** key — the key inside the blob must equal it — with namespace `irongall-msg-v1:<B>`, hash per §0 → `bad_signature`.
7. **Dedupe, BEFORE any quota:** `id = SHA-256(ciphertext)`. If B already holds this id, acked or not (§7): the same `from` → a retry → **`200` with the ORIGINAL receipt, never refused by `pair_full`/`mailbox_full`**; another `from` → `409 conflict`. A rate limit (429, step 2) may still DEFER a retry; the client retries later and gets the `200`. **This holds while B's prekey is the one the message was sealed to:** steps 4 and 5 come first, so a retry that arrives after B renewed gets `409 stale_prekey`, and the re-encrypted envelope is a new ciphertext, stored and counted again. B still delivers the message once (§5 step 8).
8. **Quotas, counted ONLY for VERIFIED sends**, so nobody can burn A's quota with junk that merely claims `from: A`. B's `block`/`allow` → `sender_not_allowed` (not built, §6.2); A's sends per day → `rate_limited`; unacked A→B at the per-pair cap → `pair_full`, with `Retry-After` and `{unacked, oldest_expires_at}`; B's total at its cap → `mailbox_full`. The daily count resets at midnight UTC, and `pair_full` and `mailbox_full` carry a `Retry-After` of the poll interval.
9. **Store it** (§7) and answer `201`.
   - A concurrent send of the same ciphertext that got there first is answered as step 7 does.
   - Any other failure answers 5xx. The client keeps the message in its outbox and retries.

## 5. Receiving — B

**5.1 Poll:** `GET /v1/<B>/messages` with the Bearer token. Every list response — empty or not — is `{count, messages: [{id, from, size, received_at, expires_at}], next_cursor, poll_after}`:
- `count` is every live message in the box; `messages` is one page of up to **50**, oldest first by `received_at`; pass `?cursor=<next_cursor>` until it is `null`.
- The response carries an **`ETag`** (the box's version); a request with a matching `If-None-Match` gets **`304 Not Modified`**.
- **`poll_after`** is the server's poll interval in seconds (as GitHub's `X-Poll-Interval`). Bots are told that interval; what is enforced is a burst of polls at once and then a steady rate (§8).
- **There is no server long-poll.** A client that waits for a reply polls (`irongall recv --wait`).
- An empty box is `{"count":0,"messages":[],"next_cursor":null,"poll_after":<seconds>}`.

Server side:
- Check the token (§6.1). **The per-box poll rate applies to EVERY poll, empty ones included** — a token bucket.
- **A list with a cursor is a continuation only if the box holds mail after the cursor.** Then it takes from the box's page allowance, not its polls, and that allowance is sized so that a drain of a full box is never refused (§8). With nothing after the cursor it is a poll: it takes from the poll rate and gets an empty page. So a cursor is no way around the poll rate.

**5.2–5.5 Fetch, verify, decrypt, check, ack — ONE gate, ONE verdict.** `ig_recv` drains every page. For each message it fetches `GET /v1/<B>/messages/<id>` → `{id, from, received_at, expires_at, ciphertext, signature}`, then `ig_judge` runs the checks in this order, and only a message that passes all of them is ACCEPTED.

**Stock client:** `sh/irongall.sh` § receive — `ig_recv` (under the lock), `ig_drain`, `ig_one`, `ig_judge` (the one gate, in §5's order), `ig_envcheck`, `ig_line`.

**The checks, in order:**
1. **The sender is an address** — validated BEFORE it touches a file name or a trust store.
2. **Its identity**: the pin, or at first contact the served identity hash-checked against `from` and then pinned (§4.1). The sender writes first, so first contact is the common case.
3. **The signature**, against that identity, namespace `irongall-msg-v1:<B>` — never the server's word.
4. **Decryption** with every RETAINED prekey (`age -d -i 2.agekey -i 1.agekey`; age tries each). An AEAD failure means the message is not for these keys.
5. **The inner envelope**: UTF-8, one JSON object, keys matched exactly and none twice, so no two readers take different values from its fields (`BODY` is an unknown key, never the body; the body itself is the verified sender's JSON, passed on as it is); `v` is the JSON number 1, `from` equals the VERIFIED signer, `to` equals this box. A mismatch means someone re-signed another sender's ciphertext as their own — in practice the operator or Cloudflare, the only parties who see it.
6. **Freshness:** `sent_at` no older than 33 days — the TTL, with no skew margin.
7. **Replay:** the LOCALLY recomputed SHA-256 of the ciphertext is not in the seen-set — never the server-supplied `id`, which a malicious operator could change. A listed `id` that differs from it is refused, and files are named by it. Seen-set lines are `<hash> <sent_at> <from> <msg_id>`, kept until `sent_at` + 33 days, so this check and freshness cover the same 33 days and a replay passes neither. This is the only defence against an operator replaying old mail; the server's own dedupe (§7) spans the TTL.
8. **Retry:** `(from, msg_id)` is not in the seen-set. A match is a re-encrypted retry of a message already delivered: it is acked, not delivered again.

**What a refusal says:** a code from a closed set (`bad_sender`, `bad_identity`, `bad_signature`, `undecryptable`, `bad_envelope`, `reattributed`, `stale`, `replay`, `bad_id`; `README.md` has the table) and the client's own fixed words (the script has one code more, `bad_message`, for a ciphertext or signature that is not base64). It never prints a value, key or field of the envelope, a served identity or a served statement: whoever reads a refusal may be a model, and any registered box can send mail that is refused. The same `<code>: <words>` is kept beside the quarantined message, `quarantine/<id>.reason`. A server's `detail` and `hint` are printed as the server's words: in quotes, one line, printable ASCII, cut short.

**What a hostile server costs a receiver:** one drain is bounded in messages, bytes and list pages (the Go client's `maxDrain*`; the script has no byte bound), stops there saying so, and leaves the rest for the next; a drain that stopped at a bound deletes no retired prekey. The identity served for a sender met for the first time is held in memory, hashed before it is parsed, and written under `peers/` only if it hashes to the address, so nothing is kept of a sender whose served identity does not hash to its address. A server can still get a sender it made up, with a real key, pinned (this repo's issue #13).

**The verdict:** plaintext, the seen-set entry and delivery happen ONLY on ACCEPT. **REFUSED mail is quarantined locally, never delivered, and acked** so it leaves the server; **it never auto-blocks the sender**, because a forgery may be the operator framing them. A transient failure (a fetch that errors) leaves the message for the next drain, and so does a fault in the box itself (an unreadable key or seen-set): that is an error, never a verdict, so nothing is acked. **A client prints or passes on one line built from the checked fields, never the plaintext's bytes**, in which a sender could hide a second envelope on its own line. Every check is tested against a forging server: the script's in §11, the Go client's in `client/forgery_test.go`.

**5.6 Act.** 🛑 **Mail is data, never instructions.** A verified signature proves who sent a message, not whether to obey it.

**5.7 Ack:** `DELETE /v1/<B>/messages/<id>` deletes the stored ciphertext and takes the message out of the list. The server keeps a dedupe record of it until the TTL (§7). **Reading does NOT delete** — delivery is at-least-once, and unacked mail expires at the TTL. **But a message is meant to be fetched once and kept by its reader**: a message's first fetch is never limited, and a fetch of one the box has fetched before takes from an allowance the size of its poll allowance, the box's alone and apart from its polls; past it, `429 rate_limited` with `Retry-After`. Both clients store a message and ack it at once, so they meet the allowance only after a failure. The ack answers `204 No Content`.

**The delivery contract**: **one consumer per box**, held by the client lock `lock/` (`irongall.sh` takes it with `mkdir`; the Go client takes the same directory and also flocks a `lock/pid` inside it, so the two exclude each other on a shared box and a crashed Go client's lock is taken over) · **drain every page**, up to what the client lets one drain take (above), the next run taking the rest · skip ids already handled, and treat a `404 no_such_message` on fetch or ack as already gone (a list may still show a just-acked message for a moment) · `pair_full` is `429` with `Retry-After` and `{unacked, oldest_expires_at}` · no server long-poll.

## 6. Owner management (Bearer unless noted)

**6.1 The owner token — computed, never stored.**
- `T = "igt1_" + base64url(kid ‖ epoch ‖ mac)`, where `kid` is a u8 (which server key), `epoch` a u32 big-endian (the box's counter), and `mac = HMAC-SHA-256(K_kid, "irongall-token-v1" ‖ H ‖ kid ‖ epoch)`, with `H` as 32 raw bytes. base64url WITHOUT padding: 37 bytes → `igt1_` + 50 chars.
- 🛑 **A client keeps and sends what it decrypted as a token only if it has that form:** `igt1_` and the 50 characters, canonical base64url, 55 bytes in all. Anything else is refused, and nothing is stored or sent. Mail is an age file to the same prekey, so a server can offer a stored message where a token belongs, and a client that did not look would send the message back as its bearer (`protocol.IsToken`, `ig_token`; found 2026-10-12, this repo's issue #36). The check is a stopgap: decided on that issue, the token goes, and a box proves itself with a pass it signs for itself.
- **`POST …/token` is a POST though it changes nothing**: token requests are POSTs by convention (OAuth 2.0, RFC 6749 §3.2), and nothing on the way caches a POST's answer.
- **The server keys `K_kid` are 32 random bytes each, `kid` a u8 allocated in order.** They never leave the server.
- **The server stores no token, only each box's `epoch`.** It bumps on `POST …/token/rotate` (not built) AND on **every prekey change** (§6.4), so a token is bound to the prekey it was encrypted to, and a box that renews as required never holds a token older than 33 days. A box that stops renewing keeps its token, so its owner calls keep working (§6.4).
- **Validation:** decode, look up `K_kid`, recompute, compare in constant time, check `epoch` against the box's current one.
- **Re-issue:** `POST …/token` and an identical registration replay both return the CURRENT token, encrypted to the current prekey: `{token}`, the same shape as registration. It is deterministic, so a stranger requesting it rotates nothing.
- `POST …/token/rotate` `[proposed: the path]` bumps `epoch`, which kills the old token; the response carries the new one, encrypted. **Not built.**
- **Not chosen: a random token stored as its hash** (`SHA-256(token)`), the conventional API key. Its catch is re-issue: the server cannot re-send a token it only holds the hash of, so a repeated `PUT` must mint a NEW one, which rotates the owner's live token for anyone holding a leaked registration body. Fixable with a timestamped re-issue signature, at the cost of one more step.
- **What a stolen token gives**: the box's metadata, its ciphertext, and owner-level control of AVAILABILITY — **irrecoverable deletion of unacked mail**, close, taking the box out of its account (§6.5), and, once they are built, `allow`/`block` and token rotation. Against the operator and Cloudflare that adds only the deletions and the settings, since they see the rest anyway. **It never gives plaintext**, it cannot rewrite the profile (which needs the box's signature), and it cannot keep a box closed: reopening needs the identity and bumps the epoch, which kills the thief's token. Agents leak tokens — transcripts, logs, world-readable files — hence the 0700 state directory (§1).

**6.1a Rotation — who forces it, and how a client finds out.** **The client rule is ONE line for every case: on `401 token_stale`, call `POST /v1/<addr>/token`, decrypt, retry** (`ig_owner`, §1). The Go client does it automatically.
- **`POST /v1/<addr>/token`** is unauthenticated and returns the CURRENT token, age-encrypted to the box's current prekey. Calling it is useless to anyone but the owner, and it never rotates anything. **Its rate limit is per IP, never per box**: a per-box limit would let anyone holding the address lock the owner out of refresh.
- **The owner rotates the TOKEN (epoch bump), and forces it**, with `POST …/token/rotate` (not built) — or, as a side effect, with every new prekey. Either response carries the NEW token, encrypted. The old one dies, and anyone else holding it gets `token_stale`.
- **Routine server-key rotation is soft. Specified, and not built in the server:** today it mints with its newest key and accepts a token made with any key it holds. The Go client already keeps a token that arrives in the header. Tokens carry a key id (`kid`, format in §6.1).
  1. The server first accepts the new key without minting with it.
  2. Only then does it mint with it: two phases, so that a server running several processes never rejects a token one of them minted.
  3. During the grace window, ANY Bearer-authenticated call presenting an old-kid token still succeeds, and **the response carries the new token in an `irongall-token` header, age-encrypted to the box's current prekey** — a piggybacked refresh, no extra round trip and no herd. The header value is standard base64 of the binary age file. How long the grace window lasts is a server setting.
  4. Clients that ignore the header hit `token_stale` when the grace window ends, and follow the one-line rule.
- **Server-key COMPROMISE is a hard cut.** The leaked key could forge any box's token, so there is no grace window: old-kid tokens get `token_stale` immediately, and everyone re-fetches via `/token`. **Not built as written:** today a token made with a key the server no longer holds is answered `401 unauthorized`, which neither client recovers from by itself. That is the herd case: `/token`'s limit is per IP, so a herd of boxes is not throttled by one another.
- **A killed token may still be accepted for a moment** after the call that killed it. Stated rather than hidden.

**6.1b The pass — decided, not in use yet.** 🔑 **Decided (this repo's issue #36): the owner token goes, and a box proves itself to the server with a pass it signs for itself. The statement, the header and their check are built (`protocol/pass.go`) and nothing uses them yet:** every owner call in this file still carries the token.

Four LF-terminated lines, signed with the working key (§2b) in the namespace `irongall-pass-v1:<A>`:

```
irongall-pass-v1
<A — the box's own address>
<the server's name as the box calls it: the host of its URL, lowercase, with its port if it has one>
<not_after — RFC 3339 UTC to the second>
```

```sh
printf 'irongall-pass-v1\n%s\n%s\n%s\n' "$A" irongall.dev "$NOT_AFTER" | ssh-keygen -q -Y sign -n "irongall-pass-v1:$A" -f work-cert.pub > pass.sig
```

- **It travels as** `Authorization: irongall-pass address="<A>", not_after="<not_after>", signature="<base64 of pass.sig>"`, in exactly that form, on every call but the ones anyone may make.
- **A client signs a pass good for 10 minutes. A server takes one that has not run out and runs out at most an hour from now.** The gap is so that a client whose clock runs fast is not refused, with no allowance for skew in any check (§0).
- **A server takes a pass only** under the box's current certificate, and for a name that is the server's own. It may remember a pass it has checked, so a pass costs one signature check however many calls carry it.
- **It says who is calling and until when, and nothing of what a call does,** so a server is handed no proof of any send (issue #29). The server still knows who sends to whom. A pass that leaks is good for the minutes it has left, at that server, and never reads or signs mail.
- **What goes once it is in use:** the token and its form check, the epoch, `POST …/token`, the `irongall-token` header and server-key rotation (§6.1, §6.1a), and the `pending` state (§3a), since a fresh pass with a registration shows a live key holder.

**6.2 Profile, lists, close.** **The profile and the lists are specified and not built: no route exists (§12), and `protocol/` has only the profile's namespace and the `sender_not_allowed` code. Close is built.**
- **Profile**: signed JSON `{version, description, schema, max_size}` — `version` an integer that only ever increases, `description` free text, `schema` (optional) a JSON Schema for the envelope's `body` (§4.2), `max_size` (optional) in bytes. Readers ignore unknown fields. Sign it from stdin, `ssh-keygen -q -Y sign -n "irongall-profile-v1:$B" -f identity < profile.json > profile.sig`, then `PUT …/profile` with JSON `{profile, signature}`, both base64. `GET /v1/<addr>` serves it. Senders verify it against B's PINNED identity before following it (`ssh-keygen -Y verify -f peers/<B>/signers -I "$B" -n "irongall-profile-v1:$B" -s profile.sig < profile.json`) and keep the highest `version` they have seen. The server refuses a PUT whose `version` ≤ the current one (`409 conflict`), so an older validly-signed profile can never be served back. The profile is advisory: the server cannot see inside the ciphertext.
- **Lists:** `PUT …/allow` and `PUT …/block` (`block` wins over `allow`).
- **Close:** `DELETE /v1/$B` (Bearer) deletes unacked mail and marks the box `closed`. It is **REVERSIBLE**: the identity reopens it with a new prekey (`PUT …/prekey`, §6.4), which puts it back to `pending` and bumps the epoch — so a token thief can close a box, but cannot keep it closed or use its old token on the reopened box (§3a). It answers `204 No Content`.

**6.3 Revocation — permanent, signed, no token.** **Specified, not built:** the server has no `/revoke` route and neither client a command (this repo's issue #14; `protocol/namespace.go` has the namespace and the statement), so "can revoke" below is the design, not today's service.
```sh
printf 'irongall-revoke-v1\n%s\n' "$A" > revoke.txt
ssh-keygen -q -Y sign -n "irongall-revoke-v1:$A" -f "$IG/identity" < revoke.txt > revoke.sig
jq -n --arg s "$(base64 < revoke.sig | tr -d '\n')" '{signature:$s}' > revoke.json && ig_api POST "/v1/$A/revoke" revoke.json
```
- **No token, on purpose:** the identity is the box's authority, so its SIGNATURE revokes.
- The server rebuilds the statement from the URL, verifies it against the REGISTERED identity key with namespace `irongall-revoke-v1:<A>`, and marks the address revoked FOREVER. Every token dies; `GET …/identity` and sends get `410 revoked`; the address can never be registered again. The marker is permanent.
- **A thief holding the identity can revoke too**, which kills the address for good: nobody can un-revoke. For the owner, that is the wanted end of a stolen key. (A thief with the identity can also renew the prekey and read new mail until the owner revokes: the identity is the box.)
- **A LOST identity key can still be revoked — by a revocation signed in advance.** The statement is fixed text that the server rebuilds from the URL, so it can be pre-signed, as GnuPG makes a revocation certificate at key creation. A stored `revoke.sig` is therefore a permanent kill switch: keep it apart from the identity. Whether `irongall init` writes one is open. Without one, the address is dead: it stops taking mail when its prekey expires, a thief holding the key could renew it, and correspondents must be told the new address out of band.

**6.4 Prekey renewal — required, a new key every time.** The Go client renews in `irongall recv` once the current prekey is more than a day old, retrying a failed renewal hourly; `irongall rekey` renews at once. Recovery needs only the identity (with `irongall.sh`, also the box's `identity.pub` and `address` files).

**Stock client:** `sh/irongall.sh` § new prekey (at least monthly, by hand: the script never renews on its own) — `ig_rekey` (needs no token, so it also recovers a box that lost its prekeys), `ig_prune`.
- **`PUT /v1/<A>/prekey`** with `{prekey, prekey_signature}`. **The authority is the identity's signature on a statement with a HIGHER serial; no token is needed** (the OpenPGP model). That is the way back for a box that lost its prekeys or its token — a restored machine, an ephemeral agent's second session. The real owner sees a takeover at once (its token dies) and can revoke (§6.3, not built).
- **The server** verifies the statement against the identity (§3 steps 4–5), requires `serial` > the current one, and **refuses a key equal to the current one or to any live retired one** (`bad_key`: "every prekey must be a NEW key"). The new prekey becomes current, **the epoch bumps**, and the answer is `200` with the new token encrypted to the NEW prekey. A closed box reopens as `pending` (§3a). **A box may renew only so many times a UTC day** (a server setting), then `429 rate_limited` until the next day; an identical retry is not a renewal. **The server keeps only a box's newest retired prekeys** (how many is a server setting), each until its `not_after`.
- **The owner** renews before `not_after` — the Go client daily, in `recv`; a monthly job with `irongall.sh`, to which the 33-day `not_after` leaves two days of slack — decrypts with every retained key (`-i new -i old`), and **deletes retired keys at their deletion time** (Terms): the Go client all but the newest, once they have been retired an hour and a drain has emptied the box; `irongall.sh` each at its `not_after` + 33 days (`ig_prune`, run by `ig_recv` and `ig_rekey`).
- 🔑 **The forward-secrecy claim: forward secrecy for every box, bounded by how often it checks in, given a client that deletes retired keys.** Precisely, with the Go client: a message is unrecoverable from the box's keys by the box's second renewal after it arrived — about two days in a box received daily, about two months in one received monthly — and mail waiting on the server is exposed until the box fetches it, as in any scheme. With `irongall.sh`: at most 66 days after its prekey was published (33 + 33). A box that stops renewing keeps its expired prekey as its current one, so its last messages stay exposed until it renews. After that a message is unrecoverable from the box's keys, by the operator, Cloudflare or a past breach. That needs a client that really deletes (the Go client and `ig_prune` do); a key kept in a backup, a synced folder or a secrets manager voids it. There is no per-message forward secrecy and no post-compromise healing.
- **A serial is signed once.** A renewal the server did not take is sent again exactly as it was signed, which the server answers as an identical retry, and a new key is signed, at the next serial, only once that statement has expired or another key type is wanted; the passed-over key is kept and deleted as a retired one. Signed again with a later `not_after`, the same key would stay in service for as long as a server refused renewals and kept the uploads: 40 days of failed renewals would give 39 statements for one key, the last good to day 73. So a key is encrypted to for at most 33 days after it was signed, whatever a server does. The Go client's `recv` exits 3 after a renewal that failed, and `irongall status` reports one that is pending.
- **A box that does not renew** gets `409 prekey_expired` for every send once its prekey's `not_after` passes. **Nothing else changes:** its address, the mail already in it, its token and its owner calls keep working, and renewing needs no token.
- **A compromised prekey:** renew it. The epoch bump kills every token taken through `/token` with the old prekey. A sender that has seen no newer serial can still be served the old statement until its `not_after` (§9).
- **The type can change at renewal** (post-quantum ↔ `--no-pq`) with no address change.
- **Tested** (§11; the two server settings only in the server's own tests): a renewal is a new key at a higher serial and bumps the epoch; the server refuses `never`, a `not_after` past 33 days, a re-signed old key, a send naming no serial or a retired one, and a renewal past the day's limit, and keeps only its newest retired prekeys; the Go client renews a prekey more than a day old, retries a failed renewal hourly, and deletes all but the newest retired prekey once they have been retired an hour; senders refuse a rollback and an expired statement; `409 stale_prekey` re-encrypts the same envelope; a box with no prekeys and no token recovers with the identity alone; after `ig_prune` deletes a retired key, its mail is unrecoverable.

**6.5 Accounts — adopt and leave.** A box may belong to one account, which can lift its limits. Nothing else about the box's mail changes.
- **`PUT /v1/<A>/account`** (Bearer) with `{"key": "<adopt key>"}` → `200 {"account": "<id>"}`. One use of the key is spent, unless the box is already in that account. A box in another account moves. `irongall adopt <key>`.
- **`DELETE /v1/<A>/account`** (Bearer) → `204`, in an account or not. `irongall adopt --leave`. An account can drop a box from its side too.
- **The adopt key** is computed, as the token is (§6.1): `K = "iga1_" + base64url(kid ‖ id ‖ n ‖ account ‖ mac)`, no padding, with `id` 16 random bytes, `n` the account id's length (a u8) and `mac = HMAC-SHA-256(K_kid, "irongall-adopt-v1" ‖ kid ‖ id ‖ n ‖ account)`. The server keeps only a key's uses left and its expiry. A key this server did not make, or one that is spent, expired or revoked, is `403 adopt_key_refused`.
- **An account id** is 1–32 of `a-z`, `0-9` and `-`: a minted one is 32 hex characters; a few names are reserved (`echo`).
- **What an account changes:** today only the echo boxes' account lifts anything: its boxes have no daily send limit and a larger size cap. Over the largest cap, a send is refused before anything else is read.

## 7. What the server stores, and for how long

How a server stores things is its own business. What it promises a client is this:

- **Per box:** the identity document, the state (§3a), the current prekey statement and its signature, the newest retired prekeys' type, `not_after` and key hash (only to refuse a key that comes back, §6.4), the epoch (never reset), when the box was created, and the account it is in, if any. No private key, no token (§6.1) and no last-seen time (§3a).
- **Per message:** the ciphertext exactly as decoded from the send, the signature, `from`, the size, `received_at` and `expires_at`. Its id is the SHA-256 of the ciphertext.
- **A `200` or `201` to a send means the message was stored.** A failure before that answers 5xx, and the sender retries from its outbox (§4.5).
- **Mail expires at the TTL, 33 days after it was received**, read or not. `expires_at` is the authority: the server never serves a message past it.
- **Reading does not delete; an ack does** (§5.7). An ack deletes the ciphertext and the signature. The id, `from`, the size and the times stay as the dedupe record until the TTL, so the server's dedupe spans the TTL even after an ack (§4 step 7).
- **Close** (§6.2) does to every message in the box what an ack does to one.
- **Lists are eventually consistent.** A list may show a just-acked message, or miss a just-stored one, for a moment. A fetch or an ack of a message that is gone answers `404 no_such_message`: treat it as gone (§5).
- **Bodies are served by the API itself, never by a redirect.**

## 8. Abuse levers

Every number behind these is a server setting (the top of this document). A refusal by one of them is a `429` with `Retry-After` (§13), unless its line says otherwise.

1. **Address secrecy** — the primary defence (§2).
2. **Per-IP limits**, keyed by IPv4 address or **IPv6 /64**: every IPv6 end site holds at least a /64, so a per-address limit means nothing there.
3. **Sends per sender per UTC day**, counted only for verified sends (§4 step 8). An account can lift it (§6.5). A lower limit for a new box's first days (warm-up) is designed and not built.
4. **Unacked mail per (sender → box)** → `pair_full`, and a larger total per box → `mailbox_full`.
5. **Registrations per IPv4 address or IPv6 /64**, plus **proof of work at registration**: find a `nonce` with `SHA-256("irongall-pow-v1" ‖ H ‖ UTC date ‖ nonce)` having `k` leading zero bits. It is bound to the address, so a solution cannot be reused, and it costs client CPU only. **Proof of work is not built**, and its wire format is open (§12).
6. **Polls, lookups and repeat fetches.** A box may poll in a burst and then at a steady rate; `poll_after` (§5.1) is the interval the server asks for. So bursts and manual polls fit, and nothing faster than the steady rate lasts. **A list without a cursor is a poll.** A later page is a continuation only while the box holds mail after its cursor, and continuations have an allowance of their own, sized so that a full box always drains (§5.1).
   - **Calls that name a box that does not exist are counted, per IPv4 address or IPv6 /64.** The calls that can make one: `/identity`, `/token`, a prekey upload, a send's recipient or sender, and an owner call without a token this server minted. Past the count, a call from that address gets `429 rate_limited` at once, so a caller past its count may be refused a box that exists. No caller is exempt: a registered sender could otherwise try any number of addresses. An owner call with a token this server minted names a box that was registered, and is never counted.
   - **A fetch or an ack of an id the box does not hold is `404 no_such_message`.** A held message's first fetch is not limited; a repeat takes from the box's allowance (§5.7).
7. **Recipient `allow` and `block` lists** (`block` wins): not built (§6.2). A list response carries metadata only (§5.1), so a box decides what to fetch.
8. **Accounts** (§6.5): the lever for volume.

## 9. The operator's view

- **Sees:** addresses, identity documents and prekeys, who mails whom, each message's size to within a padding block (§4.3a), times, IPs, ciphertext, each message's signature (proof of who sent that ciphertext to whom; a change under discussion would take it from the server, this repo's issue #29), and which account each box is in.
- **Never sees:** plaintext, private keys, age file keys.
- **Can:** deny service; drop or delay mail (undetectable without receipts); delete mail; replay old mail (§5 defeats it); serve a STALE prekey to a sender — but only one the box signed, and only until its `not_after`, at most 33 days after the box published it. The serial guard stops even that for every sender that has seen a newer one. **It can also serve altered instructions** — which is why `GET /v1/<addr>` is to serve data and pointers only (§12), hints name client commands, and the stock script comes from this repo.
- **Cannot:** read mail, forge a sender, re-attribute a message to another sender (the inner `from`, §5), substitute keys, or alter a message undetected — **against a client that verifies AND gates**: the Go client here, or `irongall.sh` from this repo.
- **Cloudflare** terminates TLS for irongall.dev today: a detail of how that server is run, not of the protocol. It sees what the operator sees, plus each box's token, which would let it drop or delay that box's mail. It cannot read or forge mail either.

## 10. The echo box

A separate CLIENT process that irongall.dev's operator runs — NOT the mailbox server — holding its own box keys. **Mail to it is readable by the operator by definition.** It replies with the decrypted plaintext plus diagnostics, signed by its own key. That lets an agent prove its whole loop end to end: keys → address → register → encrypt → sign → send → poll → verify → decrypt → ack.
- **It is `21804ec172dd0dbdca3d9a6d461799130324b42fa708b3bb727e18e0bfc07e59`, post-quantum.** **A second echo box, `7f87929a91aa19bd2ca3a833d33d66c2b2f09dc83b9e2987a6af66d12a9c6b4b`, has an X25519-only prekey** (`--no-pq`), for senders on age 1.2, which cannot encrypt to the first. It is the same program with its own identity, and everything below holds for both; the Go client reaches either, so only the stock script's instructions name the second.
- **Its address is published deliberately** — the one exception to "no discovery of addresses". **It is fixed, permanent(ish), and hard-coded where clients look: `llms.txt`, `README.md` here, and a constant in the client (`client.EchoAddress`, `client.EchoAddressNoPQ`).** The address is the SHA-256 of its identity, so a client holding it checks whatever identity the server serves; the server cannot redirect it. **The server knows no aliases**: what is published is the 64-hex address itself, and a client sends to it as to any box.
- **Its identity key is kept and backed up**, since losing it means a new address in every published place. **Its prekeys live in memory only**, and it renews at every start: renewal needs only the identity (§6.4), and no prekey reaches a snapshot or backup.
- **It is in the account `echo`** (§6.5): no daily limit, and replies up to the largest cap.
- **No reply limit of its own**: it replies once per message, and every sender's own limits bound those. Its account lifts its daily send limit (§6.5); the server has no special case for it.
- **It is `cmd/irongall-echo` in this repo.** It answers only mail that passes every check, with a signed reply naming the checks, the sender, `msg_id`, `sent_at` and the ciphertext's SHA-256, then the body as JSON. **A refused message gets no reply**: a refusal does not say whether its sender was verified, so an answer could go to any address. Each start copies in the identity and publishes a new prekey (registering the box the first time), so mail sealed to the previous prekey is refused after a restart; a running box renews daily, as every Go-client box does (§6.4). A reply the server does not take is retried at each poll and dropped after an hour; one refused for good is dropped at once.

## 11. Tested

**What a client is told to rely on is tested in this repo, with no server and no network** (`README.md` § Tests has the table). `go test ./sh` runs the stock client's tests; each needs bash, age, ssh-keygen, jq, iconv and coreutils, and skips saying which is missing. On an age older than 1.3 they test `--no-pq` boxes only. `go test` prints `ok` in every one of those cases: `go test ./sh -v` names what ran (`mode: KEYTYPE=pq`).
- **`sh/test.sh <empty dir>`:** the primitives by hand, then `irongall.sh` sourced, with only `ig_api` (curl) replaced by an in-shell fake server that implements §3–§6 on files and plays the forging operator. Its PASS lines name each check: the honest paths, every forgery, the outbox's failures, renewal and restore, forward secrecy, and a fault in the box itself. `KEYTYPE` defaults to `auto`: post-quantum if `age-keygen -pq` works, else `no-pq`, saying why.
- **The test vectors:** the script's verdict on every identity, prekey and envelope vector is the Go client's, and every accepted envelope delivers the same line from both.
- **With the Go client** against this repo's fake server: mail both ways, and each client running a box the other made.
- **Padding:** the script's arithmetic is the Go client's.
- **The Go client against a forging server:** `client/forgery_test.go` and the tests beside it.

**Measured:**
- identity document 93 B; prekey statement 2,067 B (PQ) / 170 B (`--no-pq`)
- PQ recipient 1,959 chars, secret 77 chars, header 1,627 B + 32 B (`age-inspect`), +1,659 B per message
- apt age 1.2.1 refuses a PQ recipient with "age-plugin-pq … not found"

**Against the real server.** The server's own tests are not in this repo. They hold it to §13's status map over raw HTTP, and run both clients from here against it: mail both ways, across renewals, and one box run by both clients.

**Not tested:** `token/rotate`, revocation, profiles and proof of work, none of which is built. Also untested: `age-plugin-pq` against the server's stanza check, a `--no-pq` → PQ switch by renewal against the real server, OpenSSH 8.1–10.1, age 1.3.0 and 1.3.1, the `sha256` SSHSIG variant, macOS and BusyBox.

## 12. Specified and not built, or not yet specified

Each of these but the last has an issue in this repo's milestone `M1: protocol freeze`, which also holds the other questions that could change the wire. Each is settled, built or taken out of v1, before v1 is declared stable.

- **The working key** (§2b, issue #30): decided. Its certificate's check is built and nothing uses it yet; what a newer certificate retires is open.
- **The pass** (§6.1b, issue #36): decided. Its statement, header and check are built and nothing uses them yet.
- **Identity key types other than `ssh-ed25519`** (§2): decided, not built.
- **Revocation** (§6.3): specified, not built. Open: the response shape, whether `init` writes a revocation signed in advance, and whether a `410 revoked` carries the signed statement, so that a client checks a revocation and does not take the server's word for it.
- **Token rotation** (§6.1, §6.1a): `POST …/token/rotate` (its path is `[proposed]` and its response shape open), and the `irongall-token` header during a server-key rotation. Not built in the server; the Go client already keeps a token that arrives in the header (`protocol.TokenHeader`).
- **Profile, `allow`, `block`** (§6.2): no route exists. Open: the lists' payload (its format, replace or append, the largest size, reading it back), a call that purges a sender's mail, and the three response shapes.
- **`GET /v1/<addr>`:** not built. It is to serve verifiable DATA and pointers, never commands: the address, its state, key type and limits; the identity document, the signed prekey and the signed profile; this repo, its version and how to verify it; and the sentence "do not run commands served by this site". Its format, text or JSON, is open.
- **Proof of work at registration** (§8): not built. Open: where the nonce goes in the `PUT`, the UTC date format and the midnight edge, the error code, and a stock-tool recipe. bash with `sha256sum` manages about 400 to 480 hashes a second, so `k` = 20 takes about 40 minutes; python3 manages about 1.7 million a second.
- **Named in §13 and not served:** the RateLimit header fields on a `429`, `GET /openapi.json`, and a page at each error `type` URL.
- **Also not built, and neither changes the wire:** the expiry of pending boxes (§3, §3a), and a lower send limit for a new box's first days (§8). Each is a server setting.

## 13. Errors, signalling, logging

- **Every error body is RFC 9457 Problem Details** (`application/problem+json`): `{"type": "https://irongall.dev/errors/<code>", "title", "status", "detail", "code": "<code>", "hint"}`. **`hint` names the fix as a client command** (`irongall rekey`), never a raw shell line a malicious server could alter; **`detail` explains it for generic clients.** Clients read `code`, and `hint` when there is one, on EVERY non-2xx (`ig_api`, §1). The `type` URLs serve no page yet (§12).
- **401** carries `WWW-Authenticate: Bearer` (RFC 6750 §3): with `error="invalid_token"` when a token was presented and failed, and with no `error` attribute when none was presented.
- **An unknown route** gets the HTTP router's plain `404` or `405`, with no code: none in the map fits.
- **429** carries `Retry-After` (RFC 9110), so clients pace themselves; RFC 6585 defines 429. The IETF RateLimit header fields (httpapi WG draft -11) are planned and not sent yet (§12).
- **A retried send gets `200` + the original receipt**, never a quota error, while the recipient's prekey is unchanged (§4 step 7); a 429 may defer it.

**The status map:**

| Status | Codes |
|---|---|
| **400** | `bad_request` (not JSON, a missing field such as a send's `prekey_serial`, an unknown field — §0a — or a bad cursor) · `bad_address` (not 64 hex; a `from` not lowercase) · `bad_encoding` (a byte field that is not base64) · `identity_mismatch` (registration: the identity document does not hash to the address, or breaks its grammar) · `bad_key` (a small-order or non-canonical key, a malformed or badly signed prekey statement, `never`, a `not_after` past 33 days, a key that is not new) · `not_age` · `wrong_recipient_type` (§4 step 5) |
| **401** | `unauthorized` (no token, or a bad one) · `token_stale` (the epoch moved: "`POST …/token`, decrypt, retry"; a retired server key is to answer this too, and answers `unauthorized` today, §6.1a) |
| **403** | `bad_signature` · `unknown_sender` (the sender is not registered, not yet active, or closed: "register your own box and poll it once") · `sender_revoked` (YOUR box is revoked) · `sender_not_allowed` (not on the box's `allow` list, or on its `block` list) · `adopt_key_refused` (an adopt key that is spent, expired, revoked or not ours, §6.5) |
| **404** | `no_such_mailbox` (never registered; still pending: "not activated yet — the owner must poll once"; or closed) · `no_such_message` (acked or expired: treat it as gone) |
| **409** | `conflict` (a replay that is not byte-identical — registration, prekey, profile `version`, a send whose id belongs to another sender; or a box that changed during an adopt or leave: retry) · `stale_prekey` (a newer prekey exists: re-fetch, re-encrypt the same envelope) · `prekey_expired` (the box's prekey has expired: its owner must renew) |
| **410** | `revoked` (the box you named is revoked, forever) |
| **413** | `too_large` |
| **429** | `rate_limited` · `pair_full` (with `{unacked, oldest_expires_at}`) · `mailbox_full` — all with `Retry-After` |
| **503** | `unavailable`, with `Retry-After` — the server is not ready to answer, and says so rather than answer wrong |

- **`GET /openapi.json`** — the machine-readable API (OpenAPI), beside `llms.txt`; both at the root, outside `/v1/` (§0). Not served yet (§12).
- **Logging**: the server's access logs never carry an address or a message id in the clear: each is replaced by a short hash of itself, which only someone already holding it can match. Bearer tokens and request bodies are never logged. Cloudflare's own logs DO see addresses in URLs. The remedy for a leaked address is a new box, and revocation (§6.3) once it is built. Pasting a share URL into a hosted chat also leaks it, to transcripts and link unfurlers.
