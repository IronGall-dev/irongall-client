# PRECEDENTS — every design decision beside who else does it

**Why each choice in irongall is the usual one, or where it is not, and why.** Part 1 sets irongall beside whole systems. Part 2 sets each decision beside the established systems and published standards that make it, with their numbers, and says where irongall differs and why. Part 3 does the same for the reference server's own build choices, which are no part of the protocol. `§` is a section of `PROTOCOL.md`.

**Rules for this file:**
- **A row is added the day a big decision on the wire or in the security model is made,** with the decision. A client's own behaviour (its command line, its files, its lock) carries its precedent beside the code that does it.
- **A row holds the decision in a line with its section, each precedent with its numbers and its source, and where irongall differs and why.** Nothing else: not how the decision was reached, not the spec restated, not what a standard is, which its reader knows.
- **Every claim about another system says how it is known**, in one of three ways: `read <date>`, with the source, when it was read at its source that day · `review 2026-10-10`, when it comes from the design reviews of that day and the sources they cited (§ Sources), and has not been read again since · `from memory`, when it has not been looked up. A number is never quoted from memory as if it were read. A quotation is its source's words, a shorter one a part of them, and is kept only where the words are the norm. If a row is wrong, an issue is welcome.
- **A precedent is industry practice:** a major public API, a published standard, a widely deployed protocol.
- **This is the one place a comparison is kept.** `PROTOCOL.md` carries none, and points here.

---

# Part 1 — irongall beside whole systems

## 1a. Secure messaging systems

**In one line:** irongall is roughly Signal without the ratchets or sealed sender, plus self-certifying addresses and signatures that can be shown to others: a modern, post-quantum, verified-sender PGP. *(review 2026-10-10.)*

| System | Identity and key distribution | Encryption | Forward secrecy / post-compromise / post-quantum | Sender authentication | Hidden from the server |
|---|---|---|---|---|---|
| **Signal** | Phone number or username + identity key, from Signal's directory; safety numbers out of band | PQXDH, then the Double Ratchet; since October 2025 SPQR adds an ML-KEM-768 ratchet | yes / yes / yes | Implicit in the ratchet; deniable | Contents; the sender (sealed sender) |
| **WhatsApp** | Signal-style, plus key transparency (AKD, 2023) | Signal protocol | yes / yes / not documented | Implicit; deniable | Contents |
| **iMessage** | Device keys signed by a Contact Key Verification account key (2023) | PQ3 (2024): Kyber-1024, then a Kyber-768 ratchet | yes / yes / yes | Every message signed by a Secure Enclave P-256 device key: the closest deployed analogue of irongall's signed prekey plus a signature on each message | Contents |
| **Proton Mail** | Email address; keys served by Proton, private keys stored there under the user's password | OpenPGP | no / no / opt-in since 2026-05-05 | OpenPGP signatures, which can be shown to others | Body and attachments; NOT subject or addresses |
| **MLS** (RFC 9420) | Credentials sign one-time KeyPackages, but for a "last resort" one: irongall's reusable prekey | TreeKEM groups | yes / yes / by suite | Signatures inside the group | Contents; the sender within the group |
| **SimpleX** | No user identifiers: one-way queues whose addresses are capabilities, exchanged out of band | Double Ratchet + sntrup761 (default for direct chats since v5.7, 2024) + a NaCl layer per queue | yes / yes / yes | Implicit; deniable | Contents, sender, recipient, and their link |
| **Nostr DMs** (NIP-17) | A secp256k1 key is the identity | NIP-44, with a signed "seal" inside an ephemeral-key "gift wrap" (NIP-59) | no / no / no | A signature INSIDE the encryption | Contents; the sender |
| **Noise one-way X** (rev 34, 2018; 1b) | None: accepting a key is "up to the application" (§14) | `e, es, s, ss`, then AEAD | sender compromise only (§7.7) / no / no | Static-static DH: recipient-only, open to key-compromise impersonation, deniable, replayable | Contents; the sender's static key (§7.8) |
| **irongall** | A self-certifying address (the identity's hash) + a prekey signed under the identity's certificate: no directory to trust | age; ML-KEM-768 + X25519 by default, X25519 alone by choice | bounded by how often a box checks in (about two days for one read daily) / no / yes | Ed25519 by a certified working key, inside the encryption: checked by the recipient, unseen by the server, names its recipient, can be shown to others | Contents only, by design |

**Where irongall stands**

| Dimension | Verdict | Why |
|---|---|---|
| Getting the right key | **Ahead** of directory-based messengers; **level** with key-as-identity systems | Signal, WhatsApp, iMessage and Proton serve keys from their own directory and add safety numbers or key transparency against substitution. An irongall address IS the fingerprint, as in Nostr, did:key, Tor onion addresses and SimpleX's links. What irongall adds is that rotation and a change of key type never move the address |
| Content encryption | **On par** with Signal and iMessage; **ahead** of Proton | A post-quantum hybrid by default, through a reviewed format |
| Sender authentication | **Stronger for audit; not deniable** | Provable to others, and the server holds no signature (Part 2, § 3). iMessage also signs; Signal, WhatsApp, SimpleX and Noise's one-way patterns are deniable. Right for bots acting on mail; a privacy cost elsewhere |
| Forward secrecy, post-compromise security | **Behind** the ratcheting messengers; **level** with every non-interactive scheme; **ahead** of Proton and PGP | Per-message forward secrecy needs interaction, which no non-interactive scheme has (Noise one-way, HPKE, PGP); no self-healing, which is too much state for stateless bot mail |
| Metadata privacy | **Behind** Signal, SimpleX and Nostr; **ahead** of Proton on subjects | The server sees who sends, since verified senders are the product; the subject is inside the envelope |
| Operator trust | **Ahead** of Proton; roughly Signal-like | The server never holds a private key in any form; Proton stores them server-side behind a password |

## 1b. In Noise's terms

*(review 2026-10-10, against Noise rev 34 §7.4, §7.7, §7.8, §13 and §14, and PQNoise.)*

- **irongall is N made post-quantum** (age's HPKE with the X-Wing KEM) **plus an outer Ed25519 signature:** sender authentication others can check and that resists key-compromise impersonation, which no one-way pattern reaches (source property 2); destination property 2, replayable, which the recipient's seen-set handles; forward secrecy against a recipient's compromise, bounded by rotation.
- **X and K are not for stored bot mail:** a leaked prekey would let anyone forge any sender to that box; they are deniable; rev 34 has no post-quantum, and PQNoise shows an authenticated one-way K or X cannot be built from KEMs alone, so a post-quantum design needs a signature anyway; no stock command-line tool; and §14 keeps a Noise static key inside Noise.
- **The one deployed store-and-forward use found,** Bitchat's courier path (Noise X), states it has no forward secrecy.
- **Taken from Noise:** §13's padding, after the signature; payloads that ignore what they do not know; the vocabulary of security properties.

## 1c. Agent communication, October 2026

*(review 2026-10-10. The survey kept no links, and but for the Moltbook row none of it has been read again: each row is to be checked before it is leaned on.)*

| System | Model | End-to-end encrypted | Sender authentication | Relation to irongall |
|---|---|---|---|---|
| **A2A v1.0** (Linux Foundation / AAIF, March 2026) | Synchronous RPC; the callee hosts HTTPS | No (TLS) | Transport (OAuth, mTLS); Agent Card JWS optional | **Complementary:** it cannot connect agents with no endpoint; an Agent Card extension could advertise an irongall address |
| **MCP** (spec 2026-07-28, AAIF) | Agent-to-tool RPC | No | OAuth (remote); none (stdio) | **A distribution channel**: a local stdio server |
| **DIDComm v2.1 + Pickup 3.0** | Store-and-forward through mediators | Yes (JWE) | authcrypt: recipient-only, repudiable | **Closest prior art:** irongall adds senders a server can verify and nobody can repudiate, and stock tools |
| **AgentMail; Agentverse Mailbox; mcp_agent_mail** | Store-and-forward agent mail | **No**: the operator reads it | API keys / signed envelopes / project names | The bar for getting started (one call, MCP, a CLI, Skills) |
| **XMTP; SLIM (MLS); ANP** | End-to-end encrypted networks or fabrics | Yes (MLS) | MLS credentials / DIDs | Heavier: stateful SDKs, groups, live sessions |
| **SimpleX; Nostr NIP-17; Matrix; XMPP/OMEMO** | Store-and-forward | Yes | Deniable, or hidden from the relay | None lets the relay limit verified senders; all need a stateful client |
| **Moltbook** (exposure reported by Wiz, 2026-02-02) | Platform DMs | **None** | Platform keys | **Evidence for the premise:** agents' private messages exposed, some carrying third-party API keys. News reports read 2026-10-12 ([SecurityBrief](https://securitybrief.co.uk/story/moltbook-vibe-coded-flaw-exposed-ai-chats-keys)) differ on counts, so none is given |

Noise: 1b. **What the survey found:** nothing else offers an end-to-end encrypted, sender-verified, store-and-forward mailbox over HTTP with stock tools and no stateful SDK. irongall leaves out groups, discovery, deniability, metadata privacy and push on purpose.

---

# Part 2 — each decision beside its precedent

## 1. How a box proves itself to the server: a pass it signs for itself

**Ours** (§8): the working key signs a four-line pass (tag, address, server name, end), sent in `Authorization` on every call; a client asks 10 minutes, a server takes up to an hour, and issues and keeps nothing.

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **GitHub Apps** | The app signs a JWT with its own key, sent as `Bearer` | `exp` at most 10 minutes ahead; `iat` recommended 60 seconds back, "to protect against clock drift" | read 2026-10-12: [GitHub Docs, Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) |
| **Google service accounts** | The application signs a JWT with the account's key and sends it straight to the API, no authorization server | an hour | read 2026-10-12: [Google, Using OAuth 2.0 for Server to Server Applications, Addendum: Service account authorization without OAuth](https://developers.google.com/identity/protocols/oauth2/service-account) |
| **Web Push, VAPID** (RFC 8292) | The application server signs a JWT, sent as `Authorization: vapid t=…, k=…`, with the push service's origin as `aud` | `exp` "MUST NOT be more than 24 hours from the time of the request" | read 2026-10-12: [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292) |
| **Apple Push Notification service** | The provider signs a token with its own key | an hour; refreshed every 20 to 60 minutes | the hour: [the archived guide](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html); the 20 and 60: Apple's wording as quoted on [its forums](https://developer.apple.com/forums/thread/687789), search results read 2026-10-12, Apple's current page not loaded; algorithm and header from memory |

**Where ours sits:** 10 minutes asked is GitHub's ceiling, the shortest; an hour taken is Google's and Apple's. The gap does the job of GitHub's 60 seconds of backdating, from the other end (§ 3a). The server's name is VAPID's `aud`, and a scheme of its own with named parameters is VAPID's shape.

**Where ours differs, and why:**
- **SSHSIG, not a JWT:** stock `ssh-keygen` makes and checks a pass, and § 2's certificate travels inside the signature.
- **The key is certified, not registered:** the four hold the caller's key on file; a pass chains to the identity its address hashes.
- **A server reads the header as RFC 9110 §11 lets a recipient, but refuses two things a VAPID or RFC 9110 reader would take:** an unknown parameter, where VAPID's "MUST be ignored" (RFC 8292 §3), since an addition here is a new scheme (§14); and a quoted-pair, which RFC 9110 has a recipient unescape, where no value of ours needs one and a sender "SHOULD NOT generate a quoted-pair in a quoted-string except where necessary to quote DQUOTE and backslash octets" (§5.6.4). Go has no auth-param reader (`net/http` reads only `Basic`; `httpguts` "comes with no API stability promise"), so `ParsePass` is ours, held by `testdata/vectors/pass/` and `FuzzParsePass`. *Read 2026-10-20: RFC 9110, RFC 8292, Go 1.27.2's `net/http/request.go`, `httpguts` at x/net v0.60.0.*

**Considered and not chosen:** a server-issued bearer token (RFC 6750), which needs issuing, storing and rotating and lasts until replaced when it leaks *(review 2026-10-10)*; a signature over each request, as AWS Signature Version 4, HTTP Message Signatures (RFC 9421) and DPoP (RFC 9449) *(from memory)*, which for a send would bind the recipient and the ciphertext and hand the server a proof of who sent what to whom (§ 3).

## 2. The identity certifies a working key, and signs nothing else but a revocation

**Ours** (§5): the address is the identity's hash; the identity certifies a working key in an OpenSSH certificate, 64 days asked and 64 days and an hour taken, judged at the verifier's clock; the working key signs everything else.

| Who | What they do | How it is known |
|---|---|---|
| **OpenSSH certificates** | A CA key certifies a key with principals, a serial and validity; irongall uses the format unchanged, made by `ssh-keygen -s` | `draft-ietf-sshm-cert` (from `draft-miller-ssh-cert`, which replaced `PROTOCOL.certkeys` in 2025); measured on OpenSSH 8.1p1 and 10.2p1, 2026-10-12 |
| **OpenPGP** | A primary key certifies signing and encryption subkeys, so it can stay offline | from memory |
| **Matrix cross-signing** | A master key signs the device-signing and user-signing keys | from memory |
| **Signal, MLS** | A long-lived identity signs short-lived keys (signed prekeys, KeyPackages): irongall's prekey, one level down | review 2026-10-10 |
| **Short-lived certificates in place of revocation** | The web waives revocation at 10 days or less, 7 from 2026-03-15 (§ 3b) | read 2026-10-13 |

**Where ours differs, and why:**
- **Validity at the verifier's clock,** as X.509 without a trusted timestamp, where OpenPGP takes the signer's stated time (both from memory): nobody here can vouch for when anything was signed.
- **64 days is long for "short-lived":** a certificate covers the month, at most 31 days, that an identity held elsewhere may leave between certificates, and the last mail it signs may wait 33 more and must verify when read. So it is revocable, through a serial (§ 3b; §10.2).
- **A newer certificate does not retire an older one for mail already signed;** it does at the server and for prekey statements.

## 2a. A certificate's serial is taken from its maker's clock

**Ours** (§5): the serial is the maker's clock in seconds, or one above the highest the box knows when the clock gives nothing higher; a verifier compares serials and never reads one as a time. A box restored from its identity alone thereby numbers above every certificate made before.

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | A serial "MUST be unique for each certificate issued by a given CA", kept so by the issuer's records; nothing orders two | RFC 5280 §4.1.2.2, read 2026-10-14 |
| **The web's certificate authorities** | 64 or more random bits: unique without a count | from memory |
| **OpenSSH certificates** | The CA numbers as it chooses; a KRL revokes "by serial number or key ID" | `PROTOCOL.certkeys` at `V_9_9_P1` and `PROTOCOL.krl` on `master`, read 2026-10-14 |
| **BIND 9, a zone's serial** | `serial-update-method unixtime`: seconds since the epoch, "unless the serial number is already greater than or equal to that value, in which case it is simply incremented by one." The rule here | `doc/arm/reference.rst` on `main`, read 2026-10-14; that secondaries only compare: from memory |
| **PowerDNS, signing as it answers** | `SOA-EDIT` `EPOCH` sets the serial to the epoch seconds, for our reason: a live signer keeps no count to raise | `docs/dnssec/operational.rst` on `master`, read 2026-10-14 |
| **RFC 1912** | Recommends `YYYYMMDDnn` | §2.2, read 2026-10-14 |
| **WireGuard's handshake** | An encrypted TAI64N timestamp; the receiver keeps the greatest per client and drops anything not above it: a sender's clock held to an order by a receiver that only compares | wireguard.com/protocol, read 2026-10-14 |

**Where ours differs, and why:**
- **An identity is a key, not an issuer with records:** a box is restored from its key alone (§12.4), and the only record it could consult is its untrusted server's, which never saw a certificate made and not published.
- **The serial must order as well as be unique** (§5): a random one gives no order, and a clock is what a key with no records has that rises.
- **The serial carries the order, not `valid after`,** which every verifier reads as a time and so cannot go one above the last when a clock reads behind; and revocation runs through a serial, as a KRL's range does.
- **It rests on the identity holder's clock;** the spec names where that gives way (a clock that read ahead, a behind-clock restore against an older record, two machines in one second).

## 3. The server holds no signature that proves who sent what to whom

**Ours** (§9.2): sign, then encrypt: inside the ciphertext, the envelope's line, the signature block as `ssh-keygen` wrote it, then padding. The server knows who sends to whom, from the pass its limits need, and holds nothing signed that says so.

**The order: sign, then encrypt, with the signature inside.**

| Who | What they do | How it is known |
|---|---|---|
| **JOSE** | "normally producers should sign the message and then encrypt the result (thus encrypting the signature)": a Nested JWT | RFC 7519 §11.2 and §2, read 2026-10-13 |
| **OpenPGP** | A signed message inside the encrypted one | RFC 9580 §10.3, read 2026-10-13 |
| **S/MIME** | Either order: signing first hides the signers; enveloping first exposes them and lets the signature be checked without decrypting | RFC 8551 §3.7, read 2026-10-13 |
| **Nostr NIP-17** | A signed seal inside an ephemeral-key gift wrap | review 2026-10-10 |
| **Signal, WhatsApp** | Shared-key authentication: no signature exists to show | review 2026-10-10 (deniable); the mechanism from memory |
| **iMessage** | A device key signs every message, where its server sees it | review 2026-10-10 |
| **age's author** | Names the usual advice (age plus signify or OpenSSH) and each order's flaw; recommends no layout | words.filippo.io/dispatches/age-authentication, read 2026-10-13 |

**The layout: the signed bytes as they are, then the signature.**

| Who | How the signed bytes and the signature travel together | How it is known |
|---|---|---|
| **git** | A detached signature, SSH's among them, appended to a tag or in a commit's header; the payload not encoded | `gitformat-signature`, read 2026-10-13 |
| **OpenPGP, CMS** | Binary packets: the signed bytes as they are, beside the signature | RFC 9580 §10.3, read 2026-10-13; CMS from memory |
| **JWS, DSSE** | One JSON object, payload and signature as base64 members | RFC 7515 §7.2.1 and `secure-systems-lab/dsse` `envelope.md`, read 2026-10-13 |
| **JOSE, later** | An unencoded payload, where encoding is "unnecessary and/or an impediment to adoption" | RFC 7797, abstract, read 2026-10-13 |

All agree on the method, not the bytes. Ours is git's signed tag: the same signature format, a fixed overhead; JSON with base64 members makes the envelope a third larger in every ciphertext.

**What went wrong with that layout elsewhere, and the rule each gives a reader** (§9.2):

| What happened | The rule | How it is known |
|---|---|---|
| **gitsign** verified a re-encoded object, not its raw bytes; with a header given twice, git and gitsign read different trees | Verify the envelope's line exactly as decrypted, read members from those bytes, refuse a key given twice | GHSA-7rmh-48mx-2vwc (2026-05-08), read 2026-10-13 |
| **GitLab** took the signature header as a commit's last and counted what followed as signed | Each part has one place, nothing is searched for, nothing after the first END line is read | GitLab issue 407252 (2023-04-02), read 2026-10-13 |
| **git before 2.20** took two OpenPGP signatures, reading status lines and dropping the exit status | One signature, one identity, the verifier's exit status | M. Górny, "Attack on git signature verification via crafting multiple signatures" (2019-01-26), read 2026-10-13 |

None was a flaw in the layout: each was a verifier that read an object differently from its signer.

**Where ours differs, and why:**
- **The recipient is named in what is signed** (the namespace, the envelope's `to`), which git needs not: it stops a recipient passing a signed message on, the flaw age's author names for this order.
- **The sender's identity document rides in the envelope,** as a JWS may carry its key (RFC 7515 §4.1.3, from memory): a recipient checks a sender it has never met without asking the server.
- **A recipient decrypts before it verifies,** as every system above that signs inside; what is lost is S/MIME's signature checkable without the decryption key.

## 3a. Clocks: every check is exact, and whatever is made leaves an hour of room

**Ours** (§3.4): every check is exact at the checker's clock; the maker of a time-limited thing leaves an hour. A certificate starts an hour back, a server takes a prekey up to an hour past 33 days and a pass up to 60 minutes against the 10 asked, and a reader takes a `sent_at` up to an hour ahead; a server takes a box from under 10 minutes slow to 50 fast.

**The maker dates the start back, and the verifier's check is exact:**

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **X.509 path validation** (RFC 5280 §6.1.3) | Exact at the verifier | none | read 2026-10-13: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) |
| **OpenSSH `ssh-keygen`** | Backdates by default; `sshd` exact | 59 seconds, down to the minute | read 2026-10-13: `ssh-keygen.c` at `V_10_2_P1` |
| **Let's Encrypt** | Backdates `notBefore` | 58 minutes 30 seconds measured; 0.9 of the profile's largest backdate | measured 2026-10-13 with `openssl s_client -connect letsencrypt.org:443`; Boulder's `issuance/cert.go` |
| **CA/Browser Forum Baseline Requirements** | Permit backdating | up to 48 hours | read 2026-10-13: [`docs/BR.md`](https://github.com/cabforum/servercert/blob/main/docs/BR.md) |
| **HashiCorp Vault**, PKI and SSH | Backdates | 30 seconds (`not_before_duration`) | read 2026-10-13: [Vault API, PKI](https://developer.hashicorp.com/vault/api-docs/secret/pki) and [SSH](https://developer.hashicorp.com/vault/api-docs/secret/ssh) |
| **Kubernetes' certificate signer** | Backdates | 5 minutes | read 2026-10-13: `pkg/controller/certificates/signer/signer.go` |
| **OpenMLS** | Backdates a KeyPackage | an hour, "to adapt to skewed clocks" | read 2026-10-13: `openmls/src/key_packages/lifetime.rs` |
| **BIND `dnssec-signzone`** | Backdates a signature | an hour, "to allow for clock skew" | read 2026-10-13: its manual page, `-s` |
| **MLS** (RFC 9420 §7.2) | Expects synced clocks | clients "SHOULD maintain time synchronization" | read 2026-10-13: [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) |

**The verifier of a short-lived token gives leeway:**

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **JWT** (RFC 7519 §4.1.4, §4.1.5) | Optional leeway | "usually no more than a few minutes" | read 2026-10-13: [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| **Kerberos** (RFC 4120) | Leeway both ways | 5 minutes | read 2026-10-13: [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) §3.1.3, §8.2 |
| **DPoP** (RFC 9449 §11.1) | Leeway for an `iat` ahead, or a server nonce | seconds or minutes | read 2026-10-13: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) |
| **Mastodon's HTTP signatures** | Leeway both ways | an hour (`CLOCK_SKEW_MARGIN`) | read 2026-10-13: `app/lib/signed_request.rb` |
| **DKIM** (RFC 6376 §3.5) | Verifiers "MAY ignore signatures that have a timestamp in the future", and "MAY add a 'fudge factor'" at expiry | none set | read 2026-10-13: [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) |
| **GitHub Apps** | The maker backdates `iat` | 60 seconds | § 1 |

**Where ours sits:** exact checks with the room in what is made are X.509's and OpenSSH's shape, and nobody above checks exactly at both ends. An hour is what Let's Encrypt, OpenMLS and BIND backdate, each making things strangers verify; 30 seconds to 5 minutes (Vault, Kubernetes, OpenSSH) is for one operator's machines, and irongall's boxes are strangers to each other. The pass's 10 minutes slow is twice Kerberos's 5; a `sent_at` an hour ahead is Mastodon's margin.

**Where ours differs, and why:**
- **No leeway at any verifier,** where JWT and Kerberos put theirs: every check is one comparison with no number in it to disagree on.
- **A refusal for a time is final, quarantined and acked,** where SMTP would call it transient (a 4yz is for what "can be successful if repeated without any change", RFC 5321 §4.2.1, queued and retried, §4.5.4.1; greylisting delays on purpose, RFC 6647): a client with right clocks makes no such mail (§15.7), so what is left is a wrong clock or a hand-made certificate, and irongall does not try to deliver past a party that misbehaves: the reader keeps its findings for its owner to judge (§12.3). Read 2026-10-19: [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321), [RFC 6647](https://www.rfc-editor.org/rfc/rfc6647).

**Not read:** smallstep's default backdate.

## 3b. Revocation: the identity signs it, every client checks it, and nothing less revokes

**Ours** (§10.1, §10.2, §12.5): the identity signs a fixed statement with no date, reason or number; the record is that signature with the identity document, so it proves itself, and a client takes "revoked" only on a record that verifies, keeps it, and applies it to everything the address signed. Certificates are revoked the same way through one serial, everything up to it, the highest signed standing. Every server keeps a record of any address; a client asks and publishes at its own server.

**Who signs a revocation, and what it covers:**

| Who | What they do | How it is known |
|---|---|---|
| **OpenPGP** | A key revokes itself or a subkey, with a reason; only a compromise makes old signatures suspect: "if it was merely superseded or retired, old signatures are still valid" | read 2026-10-13, [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) §5.2.1.11, §5.2.1.12, §5.2.3.31 |
| **X.509** | The issuer lists revoked serials in a signed CRL under a rising number; an entry stays until a CRL past the certificate's end; only a hold is undone; an entry may date the compromise | read 2026-10-13, [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) §3.3, §5.2.3, §5.3.1, §5.3.2 |
| **CA/Browser Forum** | No revocation information only at 10 days or less, 7 from 2026-03-15; otherwise revoked within 24 hours of a key compromise | read 2026-10-13, [Baseline Requirements](https://github.com/cabforum/servercert/blob/main/docs/BR.md) §1.6.1, §4.9.1.1, §7.1.2.11.2 |
| **Let's Encrypt** | Six-day certificates carry no OCSP or CRL URL: revocation "has historically been unreliable" | read 2026-10-13, [its announcement of 2025-01-16](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs/) |
| **OpenSSH** | A KRL revokes by serial, serial range or key id, under a rising version, unsigned ("KRL signatures are not supported by OpenSSH"; SSHSIG recommended for one that travels); `ssh-keygen -Y verify -r` applies one (a range revoked those under it and passed the next, measured 2026-10-14, OpenSSH 10.2); git's `gpg.ssh.revocationFile` takes one | read 2026-10-13 and 2026-10-14, [`PROTOCOL.krl`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl), `ssh-keygen(1)`, git's [`gpg` settings](https://github.com/git/git/blob/master/Documentation/config/gpg.adoc) |
| **Go** | `x/crypto/ssh` reads no KRL (`CertChecker.IsRevoked` is the caller's); a KRL package was declined in 2019, and the library it pointed to, `stripe/krl`, is deprecated | read 2026-10-14, [golang/go#22741](https://github.com/golang/go/issues/22741), `go doc golang.org/x/crypto/ssh.CertChecker`, [`stripe/krl`](https://github.com/stripe/krl) |

**Revoking everything issued before a point:**

| Who | What they do | How it is known |
|---|---|---|
| **AWS IAM** | Denies credentials whose `aws:TokenIssueTime` is before a time | read 2026-10-14, [Revoking IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) |
| **Microsoft Entra ID** | `revokeSignInSessions` sets `signInSessionsValidFromDateTime` to now | read 2026-10-14, [Microsoft Graph, `user: revokeSignInSessions`](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) |
| **Firebase Authentication** | `revokeRefreshTokens` records `tokensValidAfterTime` | read 2026-10-14, [Manage user sessions](https://firebase.google.com/docs/auth/admin/manage-sessions) |
| **CA/Browser Forum** | No suspension: "The Repository MUST NOT include entries that indicate that a Certificate is suspended." | read 2026-10-14, [Baseline Requirements](https://github.com/cabforum/servercert/blob/main/docs/BR.md) §4.9.13 |

**A revocation made in advance:**

| Who | What they do | How it is known |
|---|---|---|
| **GnuPG** | Writes one with every key, unasked, in `openpgp-revocs.d` under its home, with no reason, guarded against accidental import; says to hide one made by hand | read 2026-10-13, the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html), `--generate-key`, and [`g10/revoke.c`](https://github.com/gpg/gnupg/blob/master/g10/revoke.c) |
| **Sequoia** | Writes one with every key, unasked, under `$HOME/.local/share/sequoia/revocation-certificates` | read 2026-10-13, [the Sequoia book](https://book.sequoia-pgp.org/sq_key_generation.html) |

**Who may serve a revocation, and what a client does with no answer:**

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | CRLs travel "via untrusted servers and untrusted communications"; the limit is time, until the next list | read 2026-10-13, RFC 5280 §3.3 |
| **X.509's repository** | Stores and need not be trusted, where a validation service that signs answers must be | read 2026-10-14, RFC 5280 §3, §3.3 |
| **X.509, a status not found** | UNDETERMINED, left to the relying party | read 2026-10-21, RFC 5280 §6.3.3 |
| **OCSP** | The answerer signs, so it is the issuer, its delegate, or one configured locally | read 2026-10-13, [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) §4.2.2.2 |
| **TLS** | The server staples the issuer's signed status | read 2026-10-13, [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) §8 |
| **IETF Token Status List** | The provider of a status list need not be its issuer | read 2026-10-14, [draft-ietf-oauth-status-list-12](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-12.txt) §3 |
| **keys.openpgp.org** | Serves revocations of every key, finds a key only by exact match, so nobody can easily list its addresses, and needs no proof to upload | read 2026-10-13, [its FAQ](https://keys.openpgp.org/about/faq) |
| **keys.openpgp.org, its limits** | Lookups by fingerprint or key id: five a second | read 2026-10-14, [its API page](https://keys.openpgp.org/about/api) |
| **The OpenPGP keyserver protocol** | Its `index` operation lists matching certificates | read 2026-10-14, [draft-gallagher-openpgp-hkp-08](https://www.ietf.org/archive/id/draft-gallagher-openpgp-hkp-08.txt) §1, §5.2.4 |
| **Sequoia** | Publishes to five keyservers by default, `--server` repeatable | read 2026-10-14, [`sq network keyserver publish`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-keyserver-publish.1.html), sq 1.5.0 |
| **GnuPG** | One `--keyserver` list, none shipped since 2.5.3 | read 2026-10-14, the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Dirmngr-Options.html), `--keyserver` |
| **OpenSSL** | `-crl_check` is an error when no valid CRL is found: an opted-into check fails closed | read 2026-10-21, [`openssl-verification-options.pod`](https://github.com/openssl/openssl/blob/openssl-3.5.4/doc/man1/openssl-verification-options.pod), OpenSSL 3.5.4 |
| **Mozilla CRLite** | A non-CA gathers every revocation and ships the set to browsers four times a day, for local lookups | read 2026-10-13, [Mozilla Security Blog, 2020-01-09](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) |
| **What went wrong on the web** | Soft fail is "completely useless" against whoever blocks the answer, and hard fail undeployable; Let's Encrypt ended OCSP in 2025 because the responder sees which site is visited | read 2026-10-13, [A. Langley, 2014-04-19](https://www.imperialviolet.org/2014/04/19/revchecking.html); [Let's Encrypt, 2024-12-05](https://letsencrypt.org/2024/12/05/ending-ocsp/) |
| **HTTP** | A `410` is heuristically cacheable; `no-store` forbids storing | read 2026-10-13, [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §15.5.11; [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) §5.2.2.5 |
| **An extension point nobody uses** | "Mechanisms that aren't used are the ones that fail most often." | read 2026-10-13, [RFC 9170](https://www.rfc-editor.org/rfc/rfc9170) §2.1, §3 |

**When a verifier asks, and how long an answer holds:**

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | Every CRL carries `nextUpdate`; a verifier caches and fetches after it | read 2026-10-13, RFC 5280 §5.1.2.5, §6.3.3 |
| **OCSP** | `nextUpdate` optional; without it "newer revocation information is available all the time" | read 2026-10-13, RFC 6960 §2.4, §4.2.2.1 |
| **OpenSSH** | `RevokedKeys` is a local file, fetched never; unreadable, "public key authentication will be refused for all users" | read 2026-10-13, and at `V_10_6_P1` 2026-10-21, [`sshd_config(5)`](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5) |

**What a revoked key or account may still do:**

| Who | What they do | How it is known |
|---|---|---|
| **GnuPG** | Uses no key its own keyring holds revoked | read 2026-10-18, [`g10/getkey.c`](https://github.com/gpg/gnupg/blob/master/g10/getkey.c) at master `e660a0e`, `finish_lookup` |
| **ACME** | A deactivated account's requests are refused `401` for good, with no reactivation; a certificate already revoked is `400 alreadyRevoked`, with no proof beside it | read 2026-10-18, [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) §7.3.6; §7.6 read 2026-10-22 |

**Where ours follows them:**
- **A box that holds its own revocation signs nothing more,** nor mail under a certificate it holds revoked (§12.5, §10.2), as GnuPG uses no key it holds revoked, whatever any server saw; the server refuses a revoked address every call, as ACME a deactivated account.
- **Revocation is the one, final way out of a server,** as ACME's deactivation: there is no delete of a box, since a pass is a credential of minutes and an end it could make would let a leaked pass end an address. A box pauses with its ACL (§11.14) and is forgotten when it stops renewing (§13).
- **Checks run against what the box holds, with no call,** as OpenSSH's file and CRLite's set; what a client verified it keeps (§12.5).
- **A client asks again when its answer says nothing about now:** a record stands for good, and "none held" is signed by nobody, OCSP's answer with no `nextUpdate`, so a client asks before every post and for each sender in a drain (§12.5).
- **The key revokes itself, and the record travels through untrusted servers,** as an OpenPGP key's and a CRL: a server can withhold one and never make one, so X.509's delegate question does not arise.
- **A revocation is the identity's, wherever used,** as an OpenPGP key's on any keyserver; nothing in an address names a server (§4.2), so every server keeps any address's record, filled by upload and trusted for nothing, as X.509's repository (§11.15).
- **A lookup is for an address the asker holds, and nothing is listed:** keys.openpgp.org's rule and reason, since an address lets anyone write to a box (§15.9); so servers are filled by upload, never by copying each other, where CRLite gathers everything.
- **A certificate is revocable** (§10.2): 64 days and an hour (§ 2) is past the web's 10-day waiver. By serial, the time its certificate was made (§5): everything made before, on any machine whose clock did not read ahead of the revoking one's, as AWS, Entra ID and Firebase revoke what was issued before a point and a KRL's range from 1; the highest one held is all a verifier needs, and nothing is suspended.
- **A revoked address stays revoked:** nothing above undoes one but a hold, and there is none here.
- **No cache may keep an API answer,** since a `410` is cacheable by default.
- **The proof travels with the refusal,** as TLS staples: every `410 revoked` carries the record in `record`, an extension member RFC 9457 §3.2 allows (read 2026-10-22).

**Where ours differs, and why:**
- **A revoked address is `410` with its record,** where ACME answers `401` or `400 alreadyRevoked` bare: ACME's server is the authority, and here none is, so the caller is shown the proof. A `401` here is a pass a box cures by signing another; nothing cures a revocation.
- **No reason and no date,** where OpenPGP and X.509 carry both: a fixed text can be signed years early and rebuilt by its verifier from the address, so nothing is parsed before it is trusted, and a date would be the signer's unprovable word. So there is one kind, OpenPGP's compromised. A box only retired stops renewing and is forgotten (§13).
- **No slot for a later field,** where OpenPGP, X.509 and KRLs have one with a critical flag: refusing what it cannot read makes a reader treat a revoked address as live, and without the flag a field is only a hint, the unused slot RFC 9170 says fails. A later addition is a second statement under a new tag, as GnuPG says to make a new revocation with a reason.
- **Three lines signed with SSHSIG, not a KRL,** OpenSSH's own format for this: Go reads no KRL and declined to, so each client would write a binary reader to say one number; SSHSIG is what `ssh-keygen(1)` recommends for a KRL that travels.
- **No list, no version, no way to revoke fewer,** where CRLs and KRLs are rising-numbered lists that a later one can shrink, giving two holders two verdicts; one serial cannot cover less than a lower one. The cost, sparing an earlier certificate while revoking a later, nothing here needs: a box holds one certificate at its server, and its next is numbered above every one revoked (§5).
- **No date on a revoked certificate,** for the same reason: everything it signed is lost, its owner's unread mail too, which is sent again.
- **Nothing is ever dropped from it,** where a CRL drops expired entries: one serial is fixed in size, replaced by a higher, kept for good.
- **Neither client writes a revocation unasked,** where GnuPG and Sequoia write one beside every key. Theirs covers a forgotten passphrase (our reading: neither says why); an irongall identity has none, so a copy beside it is lost and stolen with it, and a liability once the identity moves elsewhere. A passphrase is planned (#50), and with it their default applies. GnuPG's import guard is here the address written in full.
- **No answer stops a drain and holds a send; "none held" does neither:** neither of the web's two. A browser could not afford to refuse without an answer; a box can, since the server it waits on is the one its mail passes through. It is OpenSSH's rule for an unreadable file.
- **One source, the box's own server,** where Sequoia lists five keyservers and GnuPG ships none. A second server guards only against one withholding a record it holds, and only if the revoked box's owner and its reader chose the same one; none could be a default, since a lookup tells it whom its asker writes to. The box's server already fails closed, as OpenSSH's `RevokedKeys` and OpenSSL's `-crl_check` do (RFC 5280 leaves it to the relying party). What remains is §15.6, a hostile server withholding a revocation of a box it hosts; the norm against it is key transparency (WhatsApp's, Apple's, CONIKS, from memory), which this protocol does not have.
- **What costs a server is counted against its caller's address, and a flood of what it answers from memory on one budget** (§11.5), as keys.openpgp.org limits lookups and Let's Encrypt's per-endpoint limits run 5 to 1,000 a second (Part 2, § 4, Limits). Records kept for addresses with no box are not bounded yet (#139).
- **Nobody signs "none held",** where a CA signs "good" with a time: only the identity could, and it may be kept away from daily work (§5), and a working key's word for its own certificate is the thief's word too. So it has no lifetime to hold, and costs one call per post; a server that falsely answers none is believed, as on the web.

**Not read:** how Signal, Matrix and Keybase handle a compromised identity or device.

## 3c. Who may write to a box: the client holds, the server's ACL refuses

**Ours** (§12.3, §11.14): a server takes mail from every registered sender; the Go client holds a sender its box has not allowed in `held/`, acked and unprinted, until its owner allows or blocks it. A box may give its server an ACL, which refuses senders before they spend the box's budget.

| Who | What they do | How it is known |
|---|---|---|
| **Signal, message requests** | A stranger's message arrives and waits for accept, delete or block; nothing refuses it | [signal.org/blog/message-requests](https://signal.org/blog/message-requests/) (2020-08-12), read 2026-10-15 |
| **Matrix, a room's server ACL (`m.room.server_acl`)** | No ACL: allow; then an IP-literal rule, a `deny` match, an `allow` match, else deny; case-insensitive globs over server names; a missing `allow` is empty and shuts everyone out, the spec suggesting `[ "*" ]` | [`data/event-schemas/schema/m.room.server_acl.yaml`](https://github.com/matrix-org/matrix-spec/blob/main/data/event-schemas/schema/m.room.server_acl.yaml) on `main`, read 2026-10-15 |
| **Signal, blocking** | Silent: the blocked never learn of it, and their messages never arrive | [support.signal.org, Block numbers, usernames or groups](https://support.signal.org/hc/en-us/articles/360007060072-Block-numbers-usernames-or-groups), read 2026-10-21 through Zendesk's article API |
| **Matrix, a server its ACL denies** | `403 M_FORBIDDEN`; the ACL acts "purely at the network layer" and changes nothing stored | `matrix-org/matrix-spec` `cc56ef90`, `content/server-server-api.md` and `data/event-schemas/schema/m.room.server_acl.yaml`, read 2026-10-21 |
| **S3, a bucket's ACL** | Every bucket has one from creation, replaced by `PutBucketAcl`; a count past a limit is `400` | the S3 API Reference, `PutBucketAcl` and `Error`, and the User Guide, `acl-overview`, read 2026-10-21 |
| **Cloud Storage, a bucket's ACL** | The whole list replaced through `buckets.patch` under `ifMetagenerationMatch`, `412` when it fails | cloud.google.com, `json_api/v1/bucketAccessControls`, `buckets/patch` and `request-preconditions`, read 2026-10-21 |
| **HTTP** | `If-Match` against lost updates, `412` when false; a versioned `PUT` that conflicts with an earlier request "might use a 409 response"; `413` for content too large; a `PUT`'s answer carries a validator only for content saved untransformed | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §9.3.4, §15.5.10, §15.5.13, §15.5.14, read 2026-10-21; §8.8.1, §9.3.4, §13.1.1, §13.2.1, read 2026-10-22 |
| **Kubernetes, `resourceVersion`** | Server-set and opaque; a `PUT` naming a stale one is `409`, one naming none is not checked | `kubernetes/community` `440e496d`, `contributors/devel/sig-architecture/api-conventions.md`, read 2026-10-21 and 2026-10-22 |
| **Email** | Delivers from anyone; filtering is the receiver's (from memory). A refused sender is told, permanently: X.7.1, "Delivery not authorized, message refused" | [RFC 3463](https://www.rfc-editor.org/rfc/rfc3463) §3.8, read 2026-10-21 |

**Where ours differs, and why:**
- **The default is Signal's, not email's:** a stranger's mail is held, because a box's reader is often an agent that acts on what it reads, and a verified sender proves who wrote, not that the box wanted it. Holding is no refusal, so the sender is told nothing, as in Signal.
- **A sender the ACL refuses is told** (`403 sender_not_allowed`, §11.10), as Matrix's `M_FORBIDDEN` and email's X.7.1, where Signal's block is silent: silence would need the server to take and drop the mail, a receipt for mail never read, or the client to drop it, spending the box's caps. A box wanting silence leaves a sender unallowed.
- **Matrix's reading, with three changes:** no `allow` is refused, not read as nobody, so a writer that drops an empty list fails loudly; an entry is an address or `*`, since a pattern over part of a hash means nothing and would let in an address made to match, and an address has one lowercase form, so nothing is case-insensitive; and a deny deletes that sender's unacked mail (§11.14), where Matrix's acts only at the network layer, since that mail would hold the box's caps.
- **Writers are kept apart by `If-Match` on the server's opaque `ETag`, `412` when false** (RFC 9110 §13.1.1), as Cloud Storage's precondition and Kubernetes' `resourceVersion`; a bare `PUT` replaces. Never a number a writer picks: one that must rise lets a writer take the highest, and a leaked pass could freeze the §11.14 pause for good.
- **A `PUT` answers no `ETag`,** as RFC 9110 §9.3.4 requires: the server sorts and dedupes entries, so what it holds may not be what was sent.
- **Too many entries is `413`,** where S3 answers its count limits `400`: the entries bound the record's size.
- **No `DELETE`:** none means `{"allow":["*"],"deny":[]}`, as an S3 bucket always has an ACL.
- **The ACL sheds load and protects no reader:** Matrix's binds every server in a room; irongall's binds only the untrusted server, which by ignoring it can do only what it could already: drop mail, or deliver mail the box would hold. The client's hold is what a reader relies on.

## 3d. Errors: AEP-193's shape, and none of a server's words in front of a reader

**Ours** (§11.3): RFC 9457 bodies in AEP-193's form: a `code` from a closed list, every value it carries a typed member, `detail` and `hint` for a person. A code splits where a client acts differently. A client shows none of the words: its own sentence for the code, with the members it checked.

| Who | What they do | How it is known |
|---|---|---|
| **RFC 9457, Problem Details** | "Consumers SHOULD NOT parse the "detail" member for information" (§3.1.4) | rfc-editor.org, read 2026-10-16 |
| **RFC 9457, the `type`** | The primary identifier, not to be dereferenced automatically, and may be non-resolvable (a `tag:` URI), though resolvable ones are encouraged and moving to one later is "a breaking change" (§3.1.1); "A problem type URI SHOULD resolve to HTML [HTML5] documentation that explains how to resolve the problem." (§4) | rfc-editor.org, read 2026-10-17 |
| **Zalando, RESTful API Guidelines** (rule 176) | Types not meant to be resolved, documented in OpenAPI instead, written as relative references | `zalando/restful-api-guidelines` `19a1905a`, read 2026-10-17 |
| **RFC 4151, `tag:` URIs** | The date is a day the authority held the name, at 00:00 UTC; `2001-07` means 2001-07-01 (§2.2) | rfc-editor.org, read 2026-10-17 |
| **AEP-193 (aep.dev)** | AIP-193 on RFC 9457: every dynamic value in the detail also a property; detail not to be string-matched by clients; a problem named by its `type` | `aep-dev/aeps`, `aep/general/0193/aep.md.j2`, read 2026-10-16 |
| **AIP-193 (Google)** | A `google.rpc.Code` plus `ErrorInfo.reason`, since about twenty codes make errors difficult to tell apart; two errors are one if a client acts the same on both | `googleapis/aip`, `aip/general/0193.md`, read 2026-10-16 |
| **OAuth 2.0** | `error` from a closed list; `error_description` for the developer | RFC 6749 §5.2, read 2026-10-13 |
| **MCP, tools (2025-11-25)** | Errors with actionable feedback; a client SHOULD validate tool results before the model sees them | `modelcontextprotocol/modelcontextprotocol`, `docs/specification/2025-11-25/server/tools.mdx`, read 2026-10-16 |
| **OpenAI, agent-builder safety** | Structured outputs (enums, fixed schemas) remove freeform channels for injected instructions | platform.openai.com/docs/guides/agent-builder-safety, read 2026-10-16 |
| **Design patterns for securing LLM agents** (arXiv 2506.08837, June 2025) | Constrain what the model reads to a well-specified format | arxiv.org/html/2506.08837, read 2026-10-16 |
| **Anthropic, "Writing effective tools for agents"** | Errors that give specific, actionable improvements, not opaque codes | anthropic.com/engineering/writing-tools-for-agents, read 2026-10-16 |
| **OWASP Top 10 for LLM Applications, LLM01** | "Separate and clearly denote untrusted content" | `LLM01_PromptInjection.md`, read 2026-10-13 |

**Where ours differs, and why:**
- **No `reason` beside the code:** AIP-193 needs one because every Google API shares one code list; ours is this protocol's own, so a cause gets a code, AEP-193's way, by AIP-193's test of one error.
- **The words stay on the wire and no client of ours shows them,** where the API standards stop at "do not parse": the reader is often a model and the server is in the threat model, so a client takes only typed, checked values from it and gives its own sentence, as the agent guidance asks. curl still shows the words.
- **`type` is `tag:irongall.dev,2026-10-17:errors/<code>`, resolving to nothing,** where RFC 9457 §4 says a type URI SHOULD resolve to documentation: no client dereferences it, §11.3 documents the codes, and a URL would tie every server's errors to one site for the protocol's life. Zalando's relative types differ per server; a `tag:` does not. Its date is a whole day after the domain's registration, since `2026-10` would read as before it.
- **A code counts only under its own `type`,** RFC 9457's identifier: a body that names its problem twice and disagrees names none.
- **An unknown code, or one under another status, is no code:** any text fits a code's grammar, so the client prints the status alone.

## 3e. Output: JSON lines, each with its type first

**Ours:** every command prints JSON lines, `type` first, the same from the script: what it did and met to stdout, refusals included; to stderr only its failure, a wrong command line, or waiting. No `--json`, no switch on a terminal; help is the one text. A line nests the envelope whole as `envelope`, so what the envelope gains in v1 (§14) never meets the line's own names. The MCP server, when built, returns the same objects.

| Who | What they do | How it is known |
|---|---|---|
| **MCP, tools (2026-07-28)** | A tool with structured content "SHOULD also return the serialized JSON in a TextContent block", though its examples put a sentence there; SEP-2200, text as a representation for the model, was declined on 2026-05-13 | `modelcontextprotocol/modelcontextprotocol`, `docs/specification/2026-07-28/server/tools.mdx` and PR #2200, read 2026-10-16 |
| **GitHub's MCP server** | JSON by default; CSV and Markdown experimental, Markdown measuring 8 to 19% fewer tokens on 30-item lists and 3 to 13% more on one; dropping fields took 25 pull requests from about 180k tokens to 55k | `github/github-mcp-server` PRs #2450, #2985, #2016, read 2026-10-16 |
| **Anthropic, "Writing effective tools for agents"** | No format is best; evaluate, and return only high-signal information | anthropic.com/engineering/writing-tools-for-agents, read 2026-10-16 |
| **Claude Code, Codex, Gemini CLI** | Text by default; JSON Lines of typed events for programs (`claude -p --output-format stream-json`, `codex exec --json`, Gemini CLI `--output-format stream-json`) | code.claude.com/docs/en/headless, developers.openai.com/codex/noninteractive, geminicli.com/docs/cli/headless, read 2026-10-16 |
| **clig.dev** | Humans first; JSON when `--json` is passed; agents not named | clig.dev, read 2026-10-16 |
| **Arcjet's CLI** | Text to a terminal, JSON otherwise, errors as JSON on stderr when JSON output is on | blog.arcjet.com/designing-a-cli-for-ai-agents, read 2026-10-16 |
| **Google Workspace CLI, its author** | NDJSON by default off a TTY | justin.poehnelt.com/posts/rewrite-your-cli-for-ai-agents, read 2026-10-16 |
| **Kubernetes, API conventions** | Every object carries `kind` and `apiVersion`, defaultable from the path | `kubernetes/community`, `contributors/devel/sig-architecture/api-conventions.md`, read 2026-10-16 |
| **Kubernetes, watch events** | `{"type": …, "object": {…}}`: the event's `type` beside the object nested whole with its own `kind` | kubernetes.io/docs/reference/using-api/api-concepts/, § Efficient detection of changes, from `kubernetes/website`, read 2026-10-22 |
| **Notation Matters** (arXiv 2605.29676, May 2026) | Token-saving formats cost accuracy in agent loops: TOON saves up to 18% at about 9 points, and cascades on multi-turn parsing failures | arxiv.org/abs/2605.29676, read 2026-10-16 |

**Where ours differs, and why:**
- **One form, no switch on a terminal,** where Arcjet and clig.dev switch: the reader is an agent first, a harness may run it in a pseudo-terminal, and one form is one to test.
- **JSON where text or Markdown would do:** the guidance finds no format best; our lines are one record each, where Markdown saved nothing; and a stranger's text inside a JSON string can pass for no line of ours and write no control character to a terminal (§ 3d's rule).
- **What a command met is on stdout,** as agent CLIs stream their errors among their events: a reader of stdout alone misses no forgery.
- **A revocation record names its own `type`** (§10.3), as a Kubernetes object its `kind`: the line `revocation make` prints is the record that publishes with curl; readers take one without it and refuse another type.
- **MCP: the same JSON twice, not a sentence,** as the spec's rule asks, so a sender's text gets no prose around it.

## 4. The rest: one row a decision

**Keys and identity**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| The address is the SHA-256 of the identity document, held to its key's one encoding (§4.1) | **The key in the name:** Tor v3's onion address (refusing a key with a torsion component, which would give one key several addresses); did:key, each type's length fixed. **A hash of the key written back:** OpenSSH's fingerprint over the parsed blob (`sshkey_fingerprint_raw`); SSHFP over the RFC 4253 blob (RFC 4255; SHA-256 from RFC 6594); age names an SSH recipient by the first four bytes of `sha256.Sum256(pk.Marshal())` (`sshFingerprint`). **Where ours differs:** it hashes the document's text, which is refused unless it is the key's one encoding, so the two match one to one, and a client lacking the key's type can still hash it. IPFS CIDs, Nostr keys and SimpleX addresses as the review gave them | read 2026-10-21: GitLab `tpo/core/torspec` `dd82a2aa`, `spec/rend-spec/encoding-onion-addresses.md` and `deriving-keys.md`; `w3c-ccg/did-key-spec` `2cc490c3` (v0.9); openssh-portable `sshkey.c` at `V_10_6_P1`; RFC 4255 §3.1.3 and RFC 6594; age v1.3.2 `agessh/agessh.go`. IPFS, Nostr, SimpleX: review 2026-10-10 |
| Separate keys for signing and encryption | libsodium: "highly recommended"; one shared pair has a proof for the general construction (Thormarker, ePrint 2021/509), which age's SSH recipient varies. Ours: a prekey renewed under a fixed identity needs them apart | review 2026-10-10 |
| A certified-key-signed prekey, renewed under an unchanged address | Signal's signed prekeys; MLS's KeyPackages; Matrix cross-signing | review 2026-10-10 |
| Registration proves possession by the identity's certificate and a fresh pass | A certificate signing request; a short-lived assertion in place of a challenge (Part 2, § 1) | review 2026-10-10; §11.7 |
| Small-order and non-canonical Ed25519 keys are refused by explicit code | RFC 8032 §5.1.3 fails non-canonical encodings; libsodium refuses small order, OpenSSH's own code from 10.6p1 (`eab91661`); Go's `crypto/ed25519` takes both, as OpenSSH did before (from 10.4p1 refusing the neutral point, `7763a38b`). **Tor refuses more,** any torsion component. **Where ours differs:** small order only, as libsodium: a torsion component gives its holder no address other keys of its secret would not (2·A, −A: measured in the audit of #219, #277), and each is a box only that secret's holder can use | review 2026-10-10; libsodium's `open.c` and the OpenSSH commits read 2026-10-15; RFC 8032 and torspec read 2026-10-21; §4.1 |
| A P-256 identity's point is uncompressed only (§4.1) | RFC 5656 §3.1 allows both; OpenSSH reads and writes only uncompressed (`sshbuf-getput-crypto.c`, `get_ec`), as `x/crypto/ssh` reads (measured in the audit of #219, #277); did:key takes only compressed. Ours is the reference implementation's | read 2026-10-21: RFC 5656; openssh-portable at `V_10_2_P1` and `V_10_6_P1`; did:key v0.9 |
| An identity's key is in its one encoding, the wire key as OpenSSH writes it back, with no per-type pattern (§4.1) | OpenSSH names a key by the blob it rebuilds (`to_blob`), parses with no pattern (`sshkey_read`), and reads a type or curve name ending in a NUL as the same key (`sshbuf_get_cstring`); SSHFP hashes the blob (RFC 4255 §3.1.3); an Ed25519 key is 32 octets with its length prefix (RFC 4251 §5, RFC 8709 §4), any other length refused by OpenSSH 10.2p1, `x/crypto/ssh` v0.58.0 and age 1.2.1. Git's allowed signers, age's SSH recipients, Tor v3 and did:key each name a key by the key or its re-encoding (#276). A format two readers must judge alike is taken only in its standard encoding, as Bitcoin's BIP 66 made DER strict "to make the consensus rules not depend on OpenSSL's signature parsing" | OpenSSH 10.6p1's source (`V_10_6_P1`) and RFC 4255 read 2026-10-21; `ssh-keygen -l` (10.2p1) run 2026-10-21 on the `*-ending-in-nul` vectors; RFC 4251, RFC 8709, BIP 66, and OpenSSH 10.2p1's and x/crypto v0.58.0's source read 2026-10-19; `ssh-keygen -l` and `age -r` run 2026-10-19 on lengths 33 to 35; the rest read 2026-10-20 in the audit of #219 (#276) |
| Small-order X25519 points are refused at registration | age refuses an all-zero shared secret | review 2026-10-10 |
| One identity key type mandatory to implement, the rest optional, each server listing what it registers | TLS 1.3's mandatory algorithms (RFC 8446 §9.1); JOSE's Required, Recommended and Optional (RFC 7518 §3.1) | read 2026-10-13; §4.1, §11.7 |
| A box declares the sender key types it verifies, and the server refuses a sender it rules out | TLS 1.3's `signature_algorithms` and `signature_algorithms_cert` (RFC 8446 §4.2.3); SSH's `server-sig-algs` (RFC 8308 §3.1): each sent on its own connection. **Where ours differs:** the server keeps it for two boxes that never connect, unsigned (§7 says why that suffices) | read 2026-10-13; §7 |
| A P-256 key is held to OpenSSH's EC check from 10.3p1, the Go SSH library's: on the curve, uncompressed, not infinity; no check of its own | OpenSSH 10.2p1's `sshkey_ec_validate_public` also checked coordinate sizes and the order; 10.3p1 dropped those (`9bea0818`), taking a short coordinate as Go does. So the script on OpenSSH up to 10.2p1 refuses a key the protocol takes: a known variance (Appendix A) | read 2026-10-13 at `V_10_2_P1` and 2026-10-15 at `V_10_6_P1` with `9bea0818`; measured 2026-10-13 (`golang.org/x/crypto` v0.58.0, OpenSSH 10.2), 2026-10-15 (10.6p1, OpenSSL 3.5.7), and 2026-10-22 (10.2p1 refuses both `identity/ok-p256-*` vectors); §4.1 |
| Nothing rests on a certificate's signature having one encoding | An ECDSA signature has several (n − s; leading zeros up to OpenSSH's 2,049 bytes, which Go and every OpenSSH build cap). Bitcoin mandated one form because ids hashed signatures (BIP 62, BIP 66, BIP 146); SSH and TLS have no such rule, and here a certificate's hash names it only to the server that checked it | from memory, for the BIPs; measured 2026-10-13: the Go SSH library and OpenSSH 10.2 take n − s and a padded r; §5 |
| A certificate is read by its format's rule: a critical option refused, an extension and the reserved field ignored; a writer writes none (§5) | draft-ietf-sshm-cert-01, replacing draft-miller-ssh-cert-06: an unknown option "MUST refuse to accept the certificate", an unknown extension "MUST ignore it", the reserved field ignored (§2.1.1, §2.3). **A deviation:** an extension's value is only empty or one non-empty string, each name once: every OpenSSH extension's form, and the only ones `x/crypto/ssh` round-trips; the draft leaves values to each extension (§2.2) and `ssh-keygen` writes other forms, so refusing those gives one verdict in both clients, and a later extension of ours is written in the forms read. A vector carries an undefined extension, so readers keep ignoring one (RFC 9170 §3) | ietf.org, both drafts read 2026-10-17; RFC 9170 read 2026-10-17 |
| Revocation is permanent, signed by the identity, signable in advance | § 3b | read 2026-10-13; §10.1 |
| Certificates are revoked through a serial the identity signs; the address goes on | § 3b | read 2026-10-13 and 2026-10-14; §10.2 |
| A box's prekey statements are ordered by certificate serial, then their own: a later certificate passes any serial under an earlier | DTLS's epoch, raised on new keying material, with sequence numbers per epoch: the certificate is the epoch. **Where ours differs:** neither number is bounded, since the highest certificate serial takes the identity's signature, which can end the address anyway | read 2026-10-13, [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) §4.2 (DTLS 1.3); [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) §4.1 (DTLS 1.2); §5 |
| Post-quantum by default | TLS's X25519MLKEM768, OpenSSH 10, Signal, iMessage PQ3 | review 2026-10-10 |

**Encryption and signing**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Standard primitives unmodified, our composition: age v1, Ed25519, SHA-256, HMAC-SHA-256, HKDF | The C2SP age specification; RFC 8032; RFC 2104; RFC 5869 | review 2026-10-10 |
| The vectors are the contract, and standard-format ones are checked by that standard's tools | C2SP CCTV's age testkit, for "any age implementation"; B's and C's prekeys are its published test identities | read 2026-10-20 |
| A namespace per purpose naming its box, `irongall-<purpose>-v1:<address>` | SSHSIG namespaces (`PROTOCOL.sshsig`). **Ours names no domain,** where `ssh-keygen(1)` advises `NAMESPACE@YOUR.DOMAIN`: the purpose and address already disambiguate, and an identity belongs to no server (§11.15) | review 2026-10-10; `ssh-keygen.1` at openssh-portable `325d965d`, read 2026-10-17 |
| A signature is read as OpenSSH reads it: armour whitespace skipped, nothing after END, `reserved` skipped and signed empty, version 0 or 1, one trailing NUL taken where no signature covers it | `sshsig_dearmor`, `sshsig_wrap_verify` and their parsers (`sshbuf_dup_string`, `sshbuf_get_cstring`, `sshsig_parse_preamble`); `PROTOCOL.sshsig` ignores a non-empty reserved field and rejects higher versions. RFC 4251 §5's no-NUL rule binds writers, and every OpenSSH build reads one | `sshsig.c` and `PROTOCOL.sshsig`, read 2026-10-14; the parsers at `V_10_6_P1` and RFC 4251, read 2026-10-15; `sig/` and `revoke/` vectors, measured with OpenSSH 10.2p1 and 10.6p1 |
| **A deviation:** a signature is bounded per key type (4,096 bytes for both today), at every verifier, a server's included | `sshsig_dearmor` sets none. A server keeps and serves signatures for good, so with no bound the bytes a signer chose (after the END line, in `reserved`, in a certificate's nonce) are what it stores: the OpenPGP keyservers bounded no signatures attached to a key, and in 2019 keys flooded with tens of thousands broke the clients that fetched them; keys.openpgp.org serves no third-party signatures. A bound per key type lets a later type with larger signatures take its own, and no two verifiers hold one type to different bounds | `sshsig.c`, read 2026-10-14; the keyservers from memory |
| **A deviation:** the Go client takes a file only with exactly one native stanza, `X25519` or `mlkem768x25519`, as every server takes a send, and refuses any other as `undecryptable` before any key agreement (§11.10 step 7, §12.3 check 1) | **age** takes up to 1,024 stanzas and tries every identity on each (`filippo.io/age` v1.3.2, `maxRecipientStanzas = 1024`). Measured, one arm64 core, 2026-10-22: refusing a 1,024-stanza file cost a two-prekey box 202 ms (X25519) or 262 ms (ML-KEM-768 + X25519), against 0.22 ms or 0.28 ms to decrypt an honest file and 0.17 ms to verify it; a 66-prekey box, the most one renewing daily keeps when no drain empties it, 6.6 s or 8.6 s, against 6.5 ms or 8.4 ms; with the check, 0.45 ms or 2.3 ms, whatever the box keeps. No honest server serves one, and age reads every file the check passes, grease included | read 2026-10-22, age v1.3.2's source; measured 2026-10-22 |
| Ed25519's S below L, by explicit code where a verifier skips it | RFC 8032 §5.1.7; Go refuses S + L, as OpenSSH from 10.3p1 on OpenSSL (`266647c5`) and from 10.4p1 on its own (`7763a38b`); older `ssh-keygen` takes it, so the script checks S | RFC 8032 §5.1.7, read 2026-10-14; `ssh-keygen` measured 2026-10-14 (`sig/bad-s-plus-l`); the commits read 2026-10-15 |
| Where OpenSSH builds disagree on Ed25519, RFC 8032's cofactorless equation, as Go and OpenSSL: neutral R taken, R plus a small-order point refused | RFC 8032 §5.1.7 allows either equation, so verifiers "need not agree on whether signatures are valid", which ZIP 215 settles with the cofactored one. OpenSSH 10.6p1's libsodium Ed25519 (`eab91661`) refuses a small-order R and takes R plus order 2 or 4 (not 8, measured 2026-10-20), OpenSSL's opposite; OpenSSH says "SSH doesn't depend on these properties" (`7763a38b`). **Why Go's verdict:** a library verifier can gain a refusal but not a wider equation, and the script proves interoperation, so a differing build is a named known variance; ZIP 215's rule is in neither library | RFC 8032, ZIP 215, libsodium's `open.c` and the OpenSSH commits, read 2026-10-15; measured with OpenSSH 10.2p1, and 10.6p1 with OpenSSL 3.5.7 and without (`sig/ok-r-small-order`, `sig/bad-r-plus-order-2`); §3.2 |
| A signature covers exact bytes, never re-serialized JSON | JWS's and XML-DSig's canonicalization lesson, and git verifiers that checked a rebuilt object (Part 2, § 3) | review 2026-10-10 |
| The envelope inside carries `from` and `to`; a mismatch is refused | Davis, "Defective Sign & Encrypt" (USENIX 2001); Nostr NIP-17's signed seal | review 2026-10-10 |
| `body` is a JSON value carried as itself, typed by no member: a string is text | CloudEvents' JSON format: `data` stored "directly as a JSON value", and with no `datacontenttype`, read as `application/json`; a type member can come later, ignored by readers that lack it | CloudEvents, `cloudevents/formats/json-format.md` (main), read 2026-10-16; §9.1 |
| The recipient is bound into the signature | The other half of Davis's fix | review 2026-10-10 |
| A keyed hash is HMAC or HKDF, never `hash(secret ‖ …)`; plain SHA-256 over public inputs, and as the form a server keeps an adopt key in (§11.16) | Signal, TLS 1.3, MLS, age, Certificate Transparency and Git's newer object format. NIST hashes a look-up secret of 112 bits or more unsalted, reserving salted password hashing for shorter ones; RFC 6819 has an OAuth server store hashes, not credentials | review 2026-10-10; §3.1; NIST SP 800-63B-4 §3.1.2.2 at pages.nist.gov/800-63-4 and RFC 6819 §5.1.4.1.3, read 2026-10-18 |
| Every message padded to whole blocks, after its signature | Noise §13; OpenPGP's padding packet after a signed message, outside what is signed (RFC 9580 §10.3) | review 2026-10-10; RFC 9580 read 2026-10-13; §9.3 |
| No ratchet in v1: forward secrecy per prekey, bounded by renewal | age and OpenPGP have none; Signal, WhatsApp, iMessage and SimpleX ratchet (Part 1). A ratchet is joint state stock tools cannot keep and a restored box would lose | Part 1's sources; §15.3 |

**Expiry, rollback, retries**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Prekeys last 33 days by default, which fits a box checked monthly, and down to a day and three hours by the owner's choice, narrowing how long a stolen or stale prekey is usable (§12.4) | Let's Encrypt offers six-day certificates by opt-in beside its 90-day default. **Where ours differs:** a box renews once its prekey is a day old, whatever its lifetime, where Let's Encrypt advises renewing at a third left, or halfway under 10 days: the day is for forward secrecy, and the shortest lifetime leaves an hour each for `recv`'s slip, the renewal's calls and a sender's clock. A lifetime is written as sshd writes times (`2d1h`) | read 2026-10-18: [Let's Encrypt, 2025-01-16](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs/), its [integration guide](https://letsencrypt.org/docs/integration-guide/); sshd_config(5), TIME FORMATS |
| Every prekey statement expires, at most 33 days on, never "never" | TUF's mandatory expiry, bounding how long a hostile operator holds a sender on an old statement | review 2026-10-10; §6 |
| A serial or version only rises | TUF's rollback protection | review 2026-10-10 |
| The outbox keeps the envelope and seals it afresh, dated at the post, at every attempt, for 33 days; a post whose answer was lost goes again as new mail, delivered once by `msg_id` (§12.2, §13) | **Encrypted again each attempt:** Signal's send loop (`getEncryptedMessages` in `RETRY_COUNT`, `SignalServiceMessageSender.java`; plaintext kept for resends, `MessageSendLogTables.kt`); Matrix's send queue (matrix-rust-sdk `room/futures.rs`), with a transaction id for idempotency. **SQS** delivers at least once; **ACME** re-signs after `badNonce` (RFC 8555 §6.5). **The other way:** SMTP retries the same bytes for 4 to 5 days (RFC 5321 §4.5.4.1). **A signed request is dated when signed, each attempt:** AWS, in most cases within five minutes, with aws-sdk-go-v2 retrying before signing; DPoP's proof unique per request, retries included (RFC 9449 §4, §4.2, §7.3); RFC 9421's `created` (§2.3). Email's `Date:` marks composition, not transport (RFC 5322 §3.6.1). **Where ours differs:** no transaction id, as Matrix has: a lost answer costs one send and a copy the reader acks; an id would cost a field, per-sender server state with its own lifetime, and a refusal for a reused id | Signal-Android and matrix-rust-sdk `main`, read 2026-10-16; Matrix Client-Server API § Transaction identifiers, the SQS Developer Guide, RFC 8555, RFC 5321, read 2026-10-16; the [IAM User Guide, SigV4 for API requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html), aws-sdk-go-v2 `main` (`aws/retry/middleware.go`, `internal/auth/smithy/v4signer_adapter.go`), RFC 9449, RFC 9421, RFC 5322, read 2026-10-18; §12.2 |
| The same ciphertext posted again gets the original receipt, whatever changed since: the dedupe precedes every new-mail check (§11.10 step 6) | Stripe's idempotency: a retry with the same key returns the saved response, a `500` included; the IETF Idempotency-Key draft, expired at rev 07 | review 2026-10-10; Stripe's page and datatracker read 2026-10-14 |
| A duplicate post arriving while the first is being stored waits for the first's answer, receipt or refusal | **A deviation.** Stripe saves no result for a concurrent conflict and has the client retry; the Idempotency-Key draft "SHOULD reply with an HTTP 409". Both answer an error because the first may run long. **The reason here:** the duplicate's answer is the first's by definition, and the wait is bounded by the first's store calls; a 409 would need a new code, since `409 conflict` already means another sender holds those bytes (§11.10 step 6), and a retry path in every client, for a SHOULD in an expired draft | Stripe's page and the draft's text read 2026-10-22, each quotation matched against its raw text |
| Replay is refused by the recipient: an id from the ciphertext, a seen-set, a window on `sent_at`, and a floor a prune raises (§12.3 check 9) | **Kerberos** keeps a replay cache over the clock skew, and one that lost it "MUST reject all requests until the clock skew interval has passed" (RFC 4120 §3.2.3); **TLS 1.3** 0-RTT records ClientHellos within a window and rejects outside it (RFC 8446 §8.2). **Where ours differs:** the window is the reader's clock, which may step, where theirs is the server's; so the set is kept an hour longer, and the floor is Kerberos's refusal kept on disk for ids a prune let go, with every copy dated up to 33 days after the first | read 2026-10-18: [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446); the id and the window, review 2026-10-10 |
| A box that stops renewing is kept until its certificate and last mail have ended, then forgotten; revocations are kept for good | X.509 keeps a CRL entry until past its certificate's validity (RFC 5280 §3.3); a box's record is kept at least that long, revocations longer | RFC 5280 read 2026-10-18; §11.6, §13 |

**The API**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| JSON in and out, byte fields standard base64 (RFC 4648) | Google Pub/Sub's `data`, AWS KMS's `CiphertextBlob`, GitHub Contents' `content`; Gmail's `raw` in base64url | review 2026-10-10; §3.3 |
| **But a ciphertext is the raw body** (`application/octet-stream`) on send and fetch, serials in the query: base64 in JSON is a third larger, and an overhead is fixed bytes, never a share (§11.10) | **Raw:** S3's `PutObject`; Matrix's media upload, `POST /_matrix/media/v3/upload`; Signal's multi-recipient send (`application/vnd.signal-messenger.mrm`); Wire's MLS send (`message/mls`). **Base64 in JSON:** Signal's single-recipient send; Matrix's events, by policy. Neither gives a reason of size | read 2026-10-17: AWS's S3 API reference; matrix-spec `cc56ef90`; Signal-Server `ccc22f9a`; wire-server `367f3609` |
| Every JSON text is I-JSON, read one way by every reader: one object, exact names, none twice, JSON's number grammar, no byte-order mark (§3.3) | RFC 7493 (I-JSON), whose §3 has a security protocol distrust a text that breaks it; RFC 8259 §8.3 and §8.1; JWS refuses duplicate names or takes the last (RFC 7515 §4). Go's `encoding/json/v2` refuses duplicates and invalid UTF-8, citing parser differentials | RFC 7493, RFC 8259 and RFC 7515 read 2026-10-14; `encoding/json/v2` (Go 1.27.2) read 2026-10-14; jq 1.7.1 and 1.8.1 measured 2026-10-14 (they take `NaN` and `01`, skip a BOM, keep the last duplicate); `json/` vectors |
| A byte field is base64 in its one encoding: padded, unbroken, zero pad bits (§3.3) | RFC 4648 §3.1, §3.2, §3.3, §3.5, each leaving the choice to "the specification referring to this document" | RFC 4648 read 2026-10-14; `answer/` vectors |
| Integers from 0 to 2^53 − 1, serials included | RFC 7493 §2.2 and RFC 8259 §6: exact only in that range | both read 2026-10-14 |
| An integer member is digits alone: `1.0` and `1e0` are none, `v` included (§3.3) | **Typed decoders read so by default:** Go's `encoding/json/v2` and `encoding/json`; Matrix's signed canonical JSON. **Schema standards judge the value and take both:** JSON Schema 2020-12 (from draft-06), ProtoJSON, OpenAPI 3.1, RFC 8927. The Go client reads as its library; the script takes `1e0`, which jq writes back as digits and none of the script's five outcomes turns on (`AGENTS.md` § The shell client) | Go 1.27.2's `encoding/json/v2` source, spec.matrix.org's appendices, json-schema.org and protobuf.dev read 2026-10-15; Go's two decoders measured 2026-10-15; OpenAPI 3.1 and RFC 8927 from a second reader's notes, 2026-10-15 |
| No number beyond binary64's magnitude; one too small for it is taken (§3.3) | RFC 7493 §2.2 says SHOULD NOT for magnitude and precision alike. **Ours makes magnitude a rule and takes precision:** past it, Go's `strconv` (`ErrRange`), Python and JavaScript read infinity, and jq the largest binary64 | RFC 7493 read 2026-10-19; Go 1.27.2, Python 3.14.4, Node 22.22.1 and jq 1.8.1 measured 2026-10-19 |
| A text nests at most 32 deep | RFC 8259 §9 lets an implementation limit depth; jq 1.7.1 refuses 257, Go's `encoding/json/v2` 10,001: a limit under both gives one verdict | RFC 8259 read 2026-10-14; both measured 2026-10-14 |
| A null member is one left out | ProtoJSON: null "leaves the field unset" | protobuf.dev, "ProtoJSON Format", read 2026-10-14 |
| A server refuses an unknown member in what it is sent; every other reader ignores one | RFC 7493 §4.2, Must-Ignore; ProtoJSON's parser "should reject unknown fields by default" | RFC 7493 and protobuf.dev read 2026-10-14; §3.3 |
| Errors are Problem Details; a 401 carries a challenge; a 429 carries `Retry-After`, seconds only | RFC 9457; RFC 6750 §3; RFC 9110 and RFC 6585. RFC 9110 §10.2.3 allows a date too; a date is read on the client's clock, which §3.4 expects may be off. The IETF RateLimit fields, a draft at rev 11 not sent to the IESG, are left out of v1 | review 2026-10-10; datatracker read 2026-10-14; RFC 9110 read 2026-10-17; §11.3 |
| A list's first page has an `ETag`, a poll returning it is `304` while unchanged, and every list answer gives the poll interval in `Retry-After` (§11.11) | **GitHub** notifications: `304` that leaves the rate limit untouched, `X-Poll-Interval`; **GitLab**'s ETag polling with `Poll-Interval`; **Google Calendar**'s `If-None-Match` and `304`; **RFC 9773 §4.3**: `Retry-After` as the poll interval on a `200`. RFC 9110 §13.1.2 answers in full on any `If-None-Match` that is not `*` or a tag list, and a client takes no `304` about a tag it did not send (§12.3), as RFC 9111 §4.3.4 bars a cache from updating on another validator's `304`. **Ours differs twice:** a `304` spends the poll rate, since the rate is how a box learns it will see nothing sooner and a free poll is one a bot makes every second; and the interval is RFC 9773's registered `Retry-After`, not an `X-` name (RFC 6648 §3) | github/docs `content/rest/activity/notifications.md` and `content/rest/using-the-rest-api/best-practices-for-using-the-rest-api.md`, gitlab-org/gitlab `doc/development/polling.md` and `fe_guide/performance.md`, the Calendar API's "Version resources", RFC 9773, RFC 6648, read 2026-10-18; RFC 9110 §13.1.2 and RFC 9111 §4.3.4, read 2026-10-20 |
| A server's order of refusals is its own, but for three rules (§11.4): box state before the pass; what changes nothing answered from what is kept, never refused by a count; `If-Match` and `If-None-Match` once the target's state is known and before acting, before a send's dedupe | **RFC 9110 orders only preconditions** (§13.2.2): a recipient evaluates them after its normal request checks and "just before it would process the request content (if any) or perform the action associated with the request method" (§13.2.1), and states no other precedence but media ranges' (§12.5.1); §13.1.1 lets a change that appears applied answer 2xx on a false `If-Match`. **Ours fixes two orders more, each one a client acts on:** state before pass, so a forgotten or revoked box learns it whatever pass it carries (§12.4, §12.5, §12.6); and a retry answered from what is kept. **And differs twice:** a registration's and a renewal's statement is verified before its pass, which is under the certificate it brings, and their conditions after both, where §13.2.1 evaluates them before the content is processed; and a send takes no §13.1.1 MAY, since its dedupe is one call shared by in-flight posts of the same bytes | read 2026-10-24, [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §13.1.1, §13.1.2, §13.2.1, §13.2.2, the whole searched for any other order it fixes; §11.4 |
| A cut fetch resumes with `Range: bytes=N-`, answered `206`, any other `Range` the whole body; no `If-Range`; the whole held to the listed size and to the id, its SHA-256; a post restarts whole (§11.12) | **RFC 9110 §14.2:** "A server MAY ignore the Range header field." **curl `-C -`** resumes from the file's size; HTTP uploads by POST or PUT cannot be resumed. **apt** sends `If-Range`, refuses an unreadable `Content-Range`, and hashes the partial file with the rest (`methods/http.cc`, `methods/basehttp.cc`). **Chromium's downloads** resume with an `If-Range` of the `ETag` or `Last-Modified` (`download_utils.cc`). **Ours differs twice:** no `If-Range`, which apt and Chromium need because a URL's content can change, where a message's id hashes its whole; and no `416`, since a server takes only `bytes=N-` inside the ciphertext. Resuming a post is draft-ietf-httpbis-resumable-upload, for when a measured uplink needs it | RFC 9110 §13.1.5, §14.2, §14.4; curl `docs/cmdline-opts/continue-at.md` at `3bda050a`; apt at salsa.debian.org's `main`; Chromium `download_utils.cc` at `1d59c45e`; the draft at datatracker.ietf.org; each read 2026-10-23 |
| A list's cursor is opaque and URL-safe, `[A-Za-z0-9_-]+`, refused otherwise | AEP-158: "opaque (but URL-safe) strings" | `aep-dev/aeps` `619650cd`, read 2026-10-17; §11.11 |
| A box's link puts the address in the path, `https://<server>/to/<address>` | **In the path:** WhatsApp's `wa.me`, Telegram's `t.me`, Threema's `threema.id`. **After `#`:** Signal's `signal.me`, whose username link carries key material; matrix.to, one redirector for every server, hiding the link from the server. Ours is the box's own server's page, which sees every send anyway, served with `Referrer-Policy: no-referrer` | read 2026-10-17: WhatsApp's Help Center, core.telegram.org/api/links, threema.com's FAQ, Signal-Android `e9b569ed`, matrix.to `562a5e27`; §4.3 |
| The HTTP layer is OpenAPI 3.1 in this repo (`api/openapi.yaml`), held to servers by a test and served by nobody; the cryptography is prose (§1) | **Matrix:** hand-written OpenAPI 3.1 (`data/api/client-server/` in `matrix-org/matrix-spec`), encryption in prose; Signal-Server generates one at build (`api-doc`); Proton publishes none found | GitHub, read 2026-10-17 |
| A send creates a message in its recipient's collection, `POST /v1/<B>/messages`, `201` with `Location` (§11.10) | RFC 9110 §9.3.3 (a creating POST "SHOULD send a 201 (Created) response containing a Location header field") and §15.3.2 | read 2026-10-17 |
| No `Link` headers to a description | RFC 8631's `service-desc` and `service-doc` find descriptions; every path here is fixed, and a server may add them later as headers a v1 client ignores | RFC 8631 read 2026-10-17 |
| One read of a box, `GET /v1/<B>`, carries all a sender needs: identity, prekey, key types, the revocations held, and a revoked address is `410` with its record (RFC 9457 §3.2); writes stay one route per thing (§11.8) | **Signal:** one `GET /v2/keys/…` for identity key and prekeys, uploads separate, no revocation to carry. **ActivityPub:** look up the actor, post to its inbox, the key Mastodon's added `publicKey`. **OCSP stapling** sends status with the certificate (RFC 6066 §8); Let's Encrypt dropped OCSP on 2025-08-06 over Must-Staple's browser support, the deployment and not the idea, and here the record proves itself (§10.3) | Signal-Server `KeysController.java` (`ccc22f9a`), the W3C ActivityPub Recommendation, Mastodon's documentation, RFC 6066, letsencrypt.org: read 2026-10-17 |
| An address in a URL is a capability, hashed in logs | W3C TAG, "Good Practices for Capability URLs" | review 2026-10-10 |
| Proof of work at registration: a lever a server may add, which v1 does not carry | Tor's onion services add theirs under load, publishing seed, effort and expiry first | Tor's `hspow-spec`, v1-equix, read 2026-10-14; §11.5 |
| https only, but for a server on the client's own machine by loopback address (`127.0.0.0/8`, `[::1]`); no flag allows more (§11.1) | RFC 6750 §5.3: bearer tokens over TLS "or equivalent transport security", and a pass is one for its minutes. Secure Contexts takes the loopback ranges as "Potentially Trustworthy", and `localhost` only where the agent resolves it to loopback itself; RFC 8252 §8.3 calls `localhost` "NOT RECOMMENDED" beside the literal, so the name is not taken | read 2026-10-18: [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.txt), [Secure Contexts](https://w3c.github.io/webappsec-secure-contexts/) § 3.1, [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.txt) |
| No redirect is followed: a `3xx` is not the API's answer (§11.1) | curl follows none without `-L` (the script passes `-q`, so no `.curlrc` adds one), and with it sends credentials only to the first host; Go's `http.Client` follows 10 and keeps `Authorization` for the same host or a subdomain, any scheme or port (`shouldCopyHeaderOnRedirect`). **Where ours differs:** none, even same-origin, since the API redirects nowhere and a redirect could carry a pass or a lookup's address elsewhere | read 2026-10-18: curl 8.18.0's man page (`-q`, 2026-10-20); Go 1.27.2's `net/http/client.go` |
| A box joins an account with an adopt key its server makes, `iga1_` plus base64url, limited in uses and time, read on stdin and spent at `PUT …/account` (§11.16) | **Tailscale's auth keys** join a device to a network, one-off or reusable, expiring; **GitHub's token formats** prefix a secret (three letters and an underscore, outside base64) for secret scanning. **Where ours differs:** the key joins an existing box and proves nothing after; every later call is the box's pass (§8). How a server keeps it: the keyed-hash row (Encryption and signing) | read 2026-10-21: tailscale.com/docs/features/access-control/auth-keys; github.blog, "Behind GitHub's new authentication token formats" (2021-04-05); §11.16 |
| A public test box at a published address answers every message it can verify with a signed report and the body | **RFC 862**'s echo service; **Amazon SES's mailbox simulator**, whose `ooto@simulator.amazonses.com` sends an automatic response, though not to mail from outside sources. **Where ours differs:** it answers anyone, its address the one published on purpose (§15.9), and only mail that passes every check, since an answer to a refused message could go to any address. Its operator reads what it is sent | read 2026-10-21: [RFC 862](https://www.rfc-editor.org/rfc/rfc862); the SES Developer Guide, "Send an email from the console" |

**Limits**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| A call is counted against the box whose pass it carries, without one its IPv4 address or IPv6 /64; the read of a box takes no pass and is counted by address; the poll keeps its pass (§11.8) | **RFC 9773:** renewal information is read unauthenticated, not being confidential, and IP-based limits guard it (§4.1, §6). **GitHub's REST API** counts unauthenticated calls by IP. **Where ours differs:** GitHub takes a token there too and counts the user; here a pass on the read is never read, so it lifts nothing and spends nothing | read 2026-10-22: [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773) §4.1, §6; [GitHub Docs, Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api); §11.5 |
| A registration is also counted by IPv6 /48, fifty times the /64 count; nothing else is | **Let's Encrypt:** 10 accounts per IP and 500 per /48 every 3 hours, a /48 being "typically assigned to a single subscriber"; its failure and order limits have no /48 key, and a miss here has none, since a /48 count of failures would refuse a site's boxes for a neighbour's | read 2026-10-19, [Rate Limits](https://letsencrypt.org/docs/rate-limits/) and `letsencrypt/boulder` `ratelimits/README.md` at `48d5ad3c19`; §11.5 |
| A count is taken before the work, and given back if the work does not happen | PortSwigger's limit overrun: counting after the work lets simultaneous requests all pass | PortSwigger Web Security Academy, "Race conditions", read 2026-10-14; §11.10 |
| A count given back is one interval off its key's time, never before now, so one returned after a refill gives back a token a later call took | **Let's Encrypt** refunds a failed new account's or order's count exactly so (`newTAT := max(tatUnix-refundIncrement, nowUnix)`), partial refunds counting as success, and gives back the same token a later call took | read 2026-10-22, `letsencrypt/boulder` `ratelimits/gcra.go`, `ratelimits/limiter.go` and `wfe2/wfe.go` at `f6d71764d4`; §11.5 |
| A limit is a budget, a burst then a steady refill, for polls, calls, new mail, registrations and the numbers a day, which refill over the day: no window empties at midnight | **Let's Encrypt:** a token bucket, kept as GCRA's theoretical arrival time, as the reference server's buckets are | read 2026-10-19, [Rate Limits](https://letsencrypt.org/docs/rate-limits/) and `letsencrypt/boulder` `ratelimits/README.md` at `48d5ad3c19`; §11.5 |
| Renewals under the current certificate are counted apart from those under a later one, and a raise of the revocation of certificates on its own count: the identity's acts apart from a working key's | OWASP, of a count that locks an account: "care must be taken to prevent it from being used to cause a denial of service by locking out other users' accounts"; ours makes the way it gives one the lockout does not close | read 2026-10-16, [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) § Account Lockout; §11.9, §11.5 |
| A renewal under a revoked current certificate spends none of the box's counts; a revocation is counted against its caller's address | **Let's Encrypt** exempts from every limit an ARI renewal of a certificate not already replaced; revoking resets no limits, and its revocation endpoint has only the per-IP limits. **Ours differs three times:** fewer renewals are exempt, since every renewal under a later certificate replaces one never replaced, so Let's Encrypt's condition would exempt them all and the count of certificates would count nothing; the one exempt is the renewal after a revocation, whose taker may have spent the box's calls; it still spends the address's flood budget, since only its body shows what it replaces (§11.5); and a raise of the revocation of certificates has a count of its own, since it can rise without end, so every exempt renewal follows a counted raise | read 2026-10-19, [Rate Limits](https://letsencrypt.org/docs/rate-limits/); read 2026-10-22, § Limit Exemptions for Renewals (`letsencrypt/website` `content/en/docs/rate-limits.md` at `225986dfb2`, lastmod 2026-08-05); §11.9, §11.15 |
| A box's budget of new mail is shared by all its senders; its ACL refuses a sender before it spends any | **Let's Encrypt's** per-domain limits are shared across accounts too. **Ours differs in who can spend it:** Let's Encrypt counts only issued certificates (`countCertificateIssued`), to whoever proved control of the names; any registered box that knows an address spends ours, so a published box defends with an allow list (§15.9, §11.14; the server's `LIMITS.md`, weakness 2) | read 2026-10-19, [Rate Limits](https://letsencrypt.org/docs/rate-limits/) and `letsencrypt/boulder` `ra/ra.go` at `cf6406dd86`; §11.5 |
| A failed check, and a read that finds no box, are counted against the caller's address, and nothing is paused | **Let's Encrypt** pauses an account and identifier after many failed authorizations. **Ours differs twice:** a failure here proves no box, so the address is the only key; and nothing is paused, since a failure costs a signature check or one remembered miss, where each of Let's Encrypt's costs a validation over the internet, and the reference clients' loops end on their own, and an address's count bounds how fast any other client runs | read 2026-10-19, [Rate Limits](https://letsencrypt.org/docs/rate-limits/); §11.5 |
| Every limit that changes nothing a client does is one code, `rate_limited`, naming the limit in `quota_id` and its subject in `subject` | **RFC 8555 §6.6:** one `rateLimited` type, the limit named only in `detail`'s prose or a link to its documentation. **Google's** error model names it in `subject` and `quota_id` fields. **Where ours differs:** `subject` is the kind, `box` or `ip`, without the value the caller knows; and a client shows neither unless it knows the value (§11.3) | read 2026-10-19, [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and `googleapis/googleapis` `google/rpc/error_details.proto` at `ebd1d23ac6`; §11.5, §11.3 |
| A refusal's `Retry-After` is when every limit readable without the call's work lets it through, under that limit's name | **RFC 8555 §6.6:** the time "where all rate limits allow access again for the current request with exactly the same parameters"; Let's Encrypt names the limit that resets last, Boulder the strictest decision in a batch. **Where ours differs:** a limit behind work (storage, a signature, the recipient's counts) is not read ahead of that work, so a caller may meet it after the first wait, at one more refused call; a send's daily count is one, shown only by the dedupe after the body (§11.10 step 6). Boulder too reads storage before some limits, to tell a renewal (`wfe2/wfe.go`, `NewOrder`) | read 2026-10-19, [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555), [Rate Limits](https://letsencrypt.org/docs/rate-limits/) and `letsencrypt/boulder` `ratelimits/limiter.go` at `cf6406dd86`; `wfe2/wfe.go` at `7d6dd30d33`, read 2026-10-20; §11.5 |
| Every request, but one carrying a pass the server has already checked on a route that takes it, spends an IP budget sized for floods before anything is done (the read of a box, whatever it carries, among them), and is refused `429 rate_limited` past it | **Let's Encrypt:** per-endpoint per-IP limits at its load balancers, ahead of signature checks, 5 to 1,000 a second, answered `503`; **nginx**'s rate limits (`NGX_HTTP_PREACCESS_PHASE`) before its access checks; **RFC 9773 §6** asks such protection for unauthenticated reads. **Where ours differs:** a checked pass spends none of it, as GitHub counts authenticated calls by user, since it costs a hash and a memory lookup, not Let's Encrypt's per-request signature check, and spends its box's budgets; new passes have no count of their own, as Let's Encrypt's /48 count is for accounts alone and OpenSSH's `PerSourceMaxStartups` is off by default; and the answer is RFC 6585's `429`, not `503` | read 2026-10-19, [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773); read 2026-10-20, [Rate Limits](https://letsencrypt.org/docs/rate-limits/) § Overall Requests Limit (`letsencrypt/website` `rate-limits.md`, lastmod 2026-08-05), nginx's [development guide](https://nginx.org/en/docs/dev/development_guide.html) § HTTP phases, GitHub's [rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) (`github/docs`), OpenSSH's `sshd_config.5` (`openssh/openssh-portable`, master); §11.5 |
| The server reads a request's head only as far as its longest call needs, refusing more before any handler | **nginx:** a line or field within one `large_client_header_buffers` buffer, `4 8k`, else `414` or `400`; **Apache:** 8,190 bytes a line or field, 100 fields; **Go**'s net/http: 1 MiB by default. **Where ours differs:** one bound on the whole head, net/http's only kind, set by a send with the longest pass, answered `431` | read 2026-10-20, nginx's [`ngx_http_core_module`](https://nginx.org/en/docs/http/ngx_http_core_module.html), Apache's [core](https://httpd.apache.org/docs/2.4/mod/core.html), `go doc net/http.DefaultMaxHeaderBytes` (Go 1.27); §11.5 |
| No limit's number is in the protocol: a server publishes its own | **RFC 8555 §6.6** names no limit; **Let's Encrypt** publishes its own | read 2026-10-19, [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and [Rate Limits](https://letsencrypt.org/docs/rate-limits/); §11.5 |

**What a client shows its reader, and the secrets it takes** (a client's other behaviour carries its precedents beside the code that does it)

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| A printed or kept line escapes every `Default_Ignorable_Code_Point` and each line break but LF, as JSON escapes them, value unchanged | Unicode's `DerivedCoreProperties.txt` defines the set; GitHub's MCP server deletes the same kinds before a model reads them (`FilterInvisibleCharacters`). Here they are escaped, not deleted, since the line is the mail's only copy once acked | Unicode 18.0's file and `github/github-mcp-server` `pkg/sanitize/sanitize.go` (at `25f11e629c`) read 2026-10-16; §12.3 |
| A secret is read on stdin, never an argument: `account adopt`'s key, checked for form before anything is sent | clig.dev: "Do not read secrets directly from flags."; `docker login --password-stdin`, `gh auth login --with-token` | clig.dev read 2026-10-16; docker and gh from memory; §11.16 |

**Designs considered and not chosen:** Signal's one-time prekeys and Double Ratchet, too much per-pair state and server-managed key pools for stateless bot mail; HPKE's Auth mode (RFC 9180), which a server cannot verify, lets a leaked recipient key forge any sender, and has no stock tool; libsodium's sealed box, with no command-line tool or pasteable key format; one key for both signing and encryption (the separate-key row); Noise's X and K (1b).

---

# Part 3 — the reference server's own choices

## 1. A store write has three outcomes

**Ours** (irongall-server's `ARCHITECTURE.md` § The store): each backend write is applied, refused as the store stated, or unknown, which may have applied, read by one function; a count reserved for it is given back only on a stated refusal.

**The precedent** (read 2026-10-24; § Sources). Go's `database/sql/driver`: "ErrBadConn should NOT be returned if there's a possibility that the database server might have performed the operation." (`driver.go`, Go 1.27.3). The MongoDB Go driver labels a commit of unknown outcome `UnknownTransactionCommitResult`, apart from a failure (`x/mongo/driver/errors.go`, `x/mongo/driver/operation.go` at `v2.9.2`), and `WithTransaction` retries on it (`mongo/session.go`).

## 2. What the server counts, on a listener of its own

**Ours** (irongall-server's `ARCHITECTURE.md` § Metrics): what the server does and refuses is counted on a listener apart from the API, off unless set, so limits are tuned and attacks seen without logs, which carry no caller's address.

**The precedent** (read 2026-10-19). Prometheus: "instrument everything", and for a request-serving system, queries, errors and latency (`prometheus/docs`, `docs/practices/instrumentation.md` at `410443d27b`). Let's Encrypt's Boulder serves `client_golang` metrics with the Go and process collectors on a separate listener, none when unset (`cmd/shell.go`, `newStatsRegistry`, at `cf6406dd86`).

---

# Sources

For rows marked `review 2026-10-10`, and for Part 3. A row of Part 2 marked `read` carries its own link.

- [Signal — SPQR and the Triple Ratchet (2025-10-02)](https://signal.org/blog/spqr/)
- [WhatsApp — deploying key transparency (2023-04-13)](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/)
- [Apple — iMessage PQ3](https://security.apple.com/blog/imessage-pq3/) · [Apple — iMessage Contact Key Verification](https://security.apple.com/blog/imessage-contact-key-verification/)
- [Proton — how Proton Mail messages are encrypted](https://proton.me/support/proton-mail-encryption-explained) (subject and addresses not end-to-end encrypted) · [Proton — private key stored encrypted with your password](https://proton.me/blog/email-password) · [Proton — post-quantum encryption (2026-05-05)](https://proton.me/blog/introducing-post-quantum-encryption)
- [RFC 9420 — MLS](https://www.rfc-editor.org/rfc/rfc9420), §10 and §16.3
- [SimpleX Chat v5.6 — quantum resistance in the double ratchet (2024-03-14)](https://simplex.chat/blog/20240314-simplex-chat-v5-6-quantum-resistance-signal-double-ratchet-algorithm.html) (default for direct chats from v5.7, 2024-04-26)
- [Nostr NIP-17 — private direct messages](https://github.com/nostr-protocol/nips/blob/master/17.md), with NIP-44 and NIP-59
- [The Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise.html) (§7.4 one-way patterns, §7.7 payload security properties, §7.8 identity hiding, §13 and §14) · [PQNoise, Angel et al., ACM CCS 2022 (ePrint 2022/539)](https://eprint.iacr.org/2022/539)
- [Thormarker, "On using the same key pair for Ed25519 and an X25519 based KEM" (ePrint 2021/509)](https://eprint.iacr.org/2021/509) · [libsodium — Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519)
- Davis, "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP, and XML", USENIX Annual Technical Conference, 2001
- [W3C TAG — Good Practices for Capability URLs](https://www.w3.org/TR/capability-urls/)
- [RFC 9457 — Problem Details](https://www.rfc-editor.org/rfc/rfc9457) · [RFC 6750 — Bearer tokens](https://www.rfc-editor.org/rfc/rfc6750)
- The agent-communication survey of 1c names its systems with the dates it found. That review kept no links for them.
- Part 3 § 1: [Go 1.27.3, `src/database/sql/driver/driver.go`](https://github.com/golang/go/blob/go1.27.3/src/database/sql/driver/driver.go) · the MongoDB Go driver at `v2.9.2`: [`x/mongo/driver/errors.go`](https://github.com/mongodb/mongo-go-driver/blob/v2.9.2/x/mongo/driver/errors.go), [`x/mongo/driver/operation.go`](https://github.com/mongodb/mongo-go-driver/blob/v2.9.2/x/mongo/driver/operation.go), [`mongo/session.go`](https://github.com/mongodb/mongo-go-driver/blob/v2.9.2/mongo/session.go)

# Open in this file

- **To read at the source:** every row marked `from memory`; Apple's current page for § 1; the survey of 1c; and the systems of 1a whose designs move fastest (Signal, iMessage, Proton, SimpleX), last read 2026-10-10.
