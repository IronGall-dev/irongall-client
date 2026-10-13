# PRECEDENTS — every design decision beside who else does it

**Why each choice in irongall is the usual one, or where it is not, and why.** Part 1 sets irongall beside whole systems. Part 2 takes each decision and names the established system or published standard that does the same, with its numbers, where irongall differs, and what was not chosen. `§` is a section of `PROTOCOL.md`; an issue number is this repo's.

**Rules for this file:**
- **A row is added the day a big decision is made,** with the decision, not after.
- **Every claim about another system says how it is known**, in one of three ways: `read <date>`, with the source, when it was read at its source that day · `review 2026-10-10`, when it comes from the design reviews of that day and the sources they cited (§ Sources), and has not been read again since · `from memory`, when it has not been looked up. A number is never quoted from memory as if it were read. If a row is wrong, an issue is welcome.
- **A precedent is industry practice:** a major public API, a published standard, a widely deployed protocol.
- **This is the one place a comparison is kept.** `PROTOCOL.md` keeps a mention where it helps a reader at that step, and points here.

---

# Part 1 — irongall beside whole systems

## 1a. Secure messaging systems

**In one line:** irongall is roughly Signal without the ratchets or sealed sender, plus self-certifying addresses and signatures that can be shown to others: a modern, post-quantum, verified-sender PGP. This sets a DESIGN beside deployed, audited systems. *(review 2026-10-10; rows corrected and the Noise row added that day.)*

| System | Identity and key distribution | Encryption | Forward secrecy / post-compromise / post-quantum | Sender authentication | Hidden from the server |
|---|---|---|---|---|---|
| **Signal** | Phone number or username + identity key; keys from Signal's own directory; safety numbers to check out of band | PQXDH (X25519 + ML-KEM) setup, then the Double Ratchet; since October 2025 the SPQR "Triple Ratchet" adds an ML-KEM-768 ratchet | yes / yes / yes | Implicit in the ratchet; deniable | Contents; the sender (sealed sender) |
| **WhatsApp** | Signal-style, plus key transparency (AKD, 2023) against key substitution by the server | Signal protocol | yes / yes / not documented | Implicit; deniable | Contents |
| **iMessage** | Device keys signed by a Contact Key Verification account key (2023); device keys sign the encryption keys, with a validity timestamp | PQ3 (2024): Kyber-1024 initial key establishment, Kyber-768 ratchet | yes / yes / yes | Every message individually signed with ECDSA P-256 by a Secure Enclave device key: the closest deployed analogue of irongall's signed prekey plus a signature on each message | Contents |
| **Proton Mail** | Email address; keys served by Proton; private keys stored on Proton's servers, encrypted with the user's password | OpenPGP | no / no / opt-in since 2026-05-05, rolling out | OpenPGP signatures; they can be shown to others | Body and attachments only. Subject, sender and recipient addresses are NOT end-to-end encrypted |
| **MLS** (RFC 9420) | Credentials sign KeyPackages. They are one-time, except a "last resort" KeyPackage, which is what irongall's reusable prekey corresponds to | TreeKEM groups | yes / yes / depends on the suite | Signatures inside the group | Contents, and the sender within the group (PrivateMessage encrypts sender data) |
| **SimpleX** | No user identifiers: one-way queues whose addresses are capabilities, exchanged out of band | Double Ratchet + hybrid post-quantum (sntrup761: opt-in beta in v5.6, default for direct chats since v5.7, 2024) + a NaCl layer for each queue | yes / yes / yes | Implicit; deniable | Contents, sender, recipient, and the link between them |
| **Nostr DMs** (NIP-17) | A secp256k1 public key is the identity | NIP-44; a signed "seal" encrypted inside an ephemeral-key "gift wrap" | no / no / no | A signature INSIDE the encryption | Contents; the sender |
| **Noise one-way X** (rev 34, 2018: a handshake framework, not a messaging system) | None built in: the recipient's static key is a pre-message, and whether to accept a key is "up to the application" (§14) | One-way DH pattern `e, es, s, ss` (25519/448), then AEAD | Sender compromise only: a later leak of the recipient's static key decrypts every past payload (§7.7, destination property 2) / no / no. Rev 34 has no post-quantum, and PQNoise shows that an authenticated one-way K or X cannot be built from KEMs alone | Static-static DH: only the recipient can check it; it is open to key-compromise impersonation (§7.7, source property 1), deniable and replayable | Contents; the sender's static key is encrypted to the recipient (§7.8). A relay can verify nothing |
| **irongall, as built** | A self-certifying address (the hash of the identity) + a prekey signed under a certificate of the identity: no directory to trust, and substitution by the server is impossible without a hash break or a forgery | age; post-quantum hybrid (ML-KEM-768 + X25519) by default, X25519 alone by a box's choice | Bounded for every box by how often it checks in (about two days for one received daily), through mandatory renewal and deletion / no / yes | Ed25519, by a working key the identity certifies, over the envelope and inside the encryption: checked by the recipient, never seen by the server; it names its recipient; the recipient can show it to others | Contents only, by design |

**How it came to this** (Part 2, § 1 to § 3): until 2026-10-13 the identity signed everything, a box held a token the server issued, and the server was handed each message's signature. Now a working key the identity certifies signs in its place; a box proves itself to the server with a pass it signs for itself; and the message's signature is inside the encryption, as in Nostr's NIP-17 and OpenPGP, so the recipient still holds proof of the sender and the server holds none.

**Where irongall stands**

| Dimension | Verdict | Why |
|---|---|---|
| Getting the right key | **Ahead** of directory-based messengers; **level** with key-as-identity systems | Signal, WhatsApp, iMessage and Proton hand out keys from a directory they control, then add safety numbers or key transparency to catch a substitution. An irongall address IS the fingerprint, and the prekey is signed by it. Key-as-identity systems (Nostr, did:key, Tor onion addresses) and SimpleX's capability links share that. What irongall adds is that rotation and a change of key type never move the address |
| Content encryption | **On par** with Signal and iMessage; **ahead** of Proton | A post-quantum hybrid by default, through a reviewed format |
| Sender authentication | **Stronger for audit; not deniable** | Checked by the server and the recipient, and provable to others. iMessage also signs every message. Signal, WhatsApp, SimpleX and Noise's one-way patterns are deniable. A signature also resists key-compromise impersonation, which Noise's one-way DH patterns do not. Right for bots that act on mail, which want an audit trail; a privacy cost elsewhere, and the pages a reader meets say so |
| Forward secrecy, post-compromise security | **Behind** the ratcheting messengers; **level** with every non-interactive scheme; **ahead** of Proton and PGP | Bounded for every box by how often it checks in. Forward secrecy for each message needs interaction (a ratchet or a handshake), which no non-interactive scheme has: not Noise's one-way patterns, not HPKE, not PGP. No self-healing either: too much state for stateless bot mail |
| Metadata privacy | **Behind** Signal, SimpleX and Nostr; **ahead** of Proton on subjects | Senders the server has verified are the product, so the server must see who sends. Proton leaves subjects outside the end-to-end encryption; irongall keeps the subject, and everything else, inside the envelope |
| Operator trust | **Ahead** of Proton; roughly Signal-like | The server never holds a private key, in any form. Proton stores them server-side behind a password |

## 1b. In Noise's terms

*(review 2026-10-10, checked that day against the text of Noise rev 34, §7.4, §7.7, §7.8, §13 and §14, and against PQNoise.)*

- **Noise is a framework for handshakes, mostly interactive ones, not a messaging system.** Its one-way patterns N, K and X are for "files, database records, or other non-interactive data streams".
- **In its vocabulary irongall is N made post-quantum** (age's HPKE with the X-Wing KEM) **plus an outer Ed25519 signature.** That gives sender authentication that resists key-compromise impersonation (no one-way Noise pattern reaches source property 2), that others can check and a server can check; destination property 2, which is replayable and is handled by the recipient's seen-set; and forward secrecy against a recipient's compromise, bounded by rotation.
- **Why not Noise X or K for stored bot mail:**
  - the sender check is a static-static DH that only the recipient can do, so a server could neither apply limits to verified senders nor refuse a forgery before storing it;
  - it is open to key-compromise impersonation: a leaked prekey would let anyone forge any sender to that box;
  - it is deniable, where bots that act on mail want an audit trail;
  - rev 34 has no post-quantum, and PQNoise shows that an authenticated one-way K or X cannot be built from KEMs alone, so a post-quantum design needs a signature anyway, which is irongall's shape;
  - there is no stock command-line tool;
  - §14 says a Noise static key should not be used outside Noise.
- **The one deployed store-and-forward use found,** Bitchat's courier path (Noise X), states that it has no forward secrecy.
- **Taken from Noise:** §13's padding, as bytes after the message's signature; payloads that must ignore what they do not know; its vocabulary for security properties.

## 1c. Agent communication, October 2026

*(review 2026-10-10. That survey kept no links, and but for the last row none of it has been read again: each row is to be checked before it is leaned on.)*

| System | Model | End-to-end encrypted | Sender authentication | Relation to irongall |
|---|---|---|---|---|
| **A2A v1.0** (Linux Foundation / AAIF, March 2026) | Synchronous RPC; the callee must host HTTPS; push needs the client reachable | No (TLS) | Transport (OAuth, mTLS); an Agent Card JWS is optional | **Complementary.** It cannot connect two agents that have no endpoint. The cheapest interop is an Agent Card extension that advertises an irongall address |
| **MCP** (spec 2026-07-28, AAIF) | Agent-to-tool RPC | No | OAuth (remote); none (stdio) | **A distribution channel** irongall lacks: a local stdio server |
| **DIDComm v2.1 + Pickup 3.0** | Store-and-forward through mediators | Yes (JWE) | authcrypt: checkable by the recipient only, repudiable | **Closest prior art.** irongall is about a mediator plus pickup, plus senders a server can verify and nobody can repudiate, plus stock tools |
| **AgentMail; Agentverse Mailbox; mcp_agent_mail** | Store-and-forward agent mail | **No**: the operator can read it | API keys / signed envelopes / project names | They set the bar for getting started (one call, MCP, a CLI, Skills). No substitute when the operator must not read |
| **XMTP; SLIM (MLS); ANP** | End-to-end encrypted networks or fabrics | Yes (MLS) | MLS credentials / DIDs | A heavier weight class: stateful SDKs, groups, live sessions |
| **SimpleX; Nostr NIP-17; Matrix; XMPP/OMEMO** | Store-and-forward | Yes | Deniable, or hidden from the relay | None lets the relay apply limits to verified senders. All need a stateful client |
| **Noise** (rev 34) | Handshake framework | Depends on the deployment | DH; one-way patterns open to key-compromise impersonation | The right tool for live channels, the wrong one for stored bot mail (1b) |
| **Moltbook** (exposure reported by Wiz, 2026-02-02) | Platform DMs | **None** | Platform keys | **Evidence for the premise:** private messages between agents were exposed, some carrying third-party API keys in plaintext. News reports of it read 2026-10-12 ([SecurityBrief](https://securitybrief.co.uk/story/moltbook-vibe-coded-flaw-exposed-ai-chats-keys)); they differ on the counts, so none is given here |

**What the survey found:** no other system offers an end-to-end encrypted, sender-verified, store-and-forward mailbox over HTTP with stock tools and no stateful SDK. What irongall leaves out on purpose is groups, discovery, deniability, metadata privacy and push.

---

# Part 2 — each decision beside its precedent

## 1. How a box proves itself to the server: a pass it signs for itself

**Ours** (decided 2026-10-12; issue #36): the box signs a four-line statement with its working key: a tag, its address, the server's name, and when the pass runs out. That signature goes in `Authorization` on every call until it runs out. The client makes a pass good for 10 minutes. The server takes none that runs out more than an hour on. The server issues nothing and keeps nothing for it.

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **GitHub Apps** | The app signs a JWT with its own private key (RS256) and sends it as `Authorization: Bearer` | `exp` at most 10 minutes ahead. `iat` recommended 60 seconds in the past, "to protect against clock drift" | read 2026-10-12: [GitHub Docs, Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) |
| **Google service accounts** | The application signs a JWT with the service account's key (RS256) and sends it straight to the API as `Authorization: Bearer`, with no request to an authorization server | expires 3600 seconds after `iat` | read 2026-10-12: [Google, Using OAuth 2.0 for Server to Server Applications, Addendum: Service account authorization without OAuth](https://developers.google.com/identity/protocols/oauth2/service-account) |
| **Web Push, VAPID** (RFC 8292) | The application server signs a JWT with its own key (ES256) and sends it as `Authorization: vapid t=<JWT>, k=<public key>` | `exp` "MUST NOT be more than 24 hours from the time of the request". `aud` "MUST include the Unicode serialization of the origin" of the push service | read 2026-10-12: [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292) |
| **Apple Push Notification service** | The provider signs a token with its own key and sends it on each request | a token is valid for one hour; refreshed no more than once every 20 minutes and no less than once every 60 | The hour: [Apple, Communicating with APNs (archived guide)](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html). The 20 and 60: Apple's current wording as quoted on [its developer forums](https://developer.apple.com/forums/thread/687789). Search results read 2026-10-12; Apple's current page did not load. Its algorithm and header: from memory |

**Where ours sits among them:**
- **10 minutes from the client** is GitHub's ceiling, the shortest of the four.
- **An hour at the server** is Google's and Apple's figure.
- **The gap between the two** does the job of GitHub's 60 seconds of backdating: a client whose clock is off is not refused. Here it is on the far end, since irongall's checks carry no allowance for skew.
- **The server's name in the statement** is VAPID's `aud`: a pass made for one server is no pass for another.
- **A scheme of its own with named parameters** is VAPID's shape, not `Bearer`.

**Where ours differs, and why:**
- **SSHSIG, not a JWT.** Every signature in irongall is an OpenSSH signature, so stock `ssh-keygen` makes and checks a pass, and the certificate of § 2 travels inside the signature.
- **The key that signs is certified, not registered.** The four above hold the caller's public key on file. Here the pass carries a certificate that chains to the identity the address is a hash of.

**Considered and not chosen:**
- **A token the server issues,** as OAuth 2.0 access tokens are (bearer tokens, RFC 6750) and as irongall had until 2026-10-13. It needs issuing, storing and rotating, and one that leaks lasts until it is replaced. The OAuth 2.0 Security BCP (RFC 9700) is why that token is bound to the prekey, so that none outlives 33 days *(review 2026-10-10)*.
- **A signature or a MAC over each request,** as AWS Signature Version 4, HTTP Message Signatures (RFC 9421) and DPoP (RFC 9449) do *(from memory; none read for this row)*. Each binds the method, the target and often the body. For a send that is the recipient and the ciphertext, which would hand the server a proof of who sent what to whom (§ 3).

## 2. The identity certifies a working key, and signs nothing else but a revocation

**Ours** (decided 2026-10-12; issue #30): a box's address is the hash of its identity key. The identity signs an OpenSSH certificate for a working key, valid at most 66 days (a client asks for 65), and the working key signs prekey statements, mail and passes. A certificate is checked against the verifier's own clock.

| Who | What they do | How it is known |
|---|---|---|
| **OpenSSH certificates** | A CA key signs a certificate naming a key, its principals, a serial and a validity window. irongall uses this format unchanged, made by `ssh-keygen -s` | OpenSSH `PROTOCOL.certkeys`. The behaviour irongall relies on was measured on OpenSSH 8.1p1 and 10.2p1, 2026-10-12 |
| **OpenPGP** | A primary key certifies subkeys that do the signing and decrypting, so the primary can be kept offline | from memory |
| **Matrix cross-signing** | A master key signs the keys that sign devices and other users | from memory |
| **Signal, MLS** | A long-lived identity signs the shorter-lived keys others encrypt to: Signal's signed prekeys, MLS's KeyPackages. It is what irongall's prekey already does, one level down | review 2026-10-10 |
| **Short-lived certificates in place of revocation** | Web PKI and workload-identity systems issue certificates that live for days or hours and are simply not renewed | from memory |

**Where ours differs, and why:**
- **Validity is judged at the verifier's clock,** as X.509 validation is without a trusted timestamp, where OpenPGP judges a signature at the time the signer states (both from memory). Nobody in irongall can vouch for when a signature was made, so a stated time proves nothing.
- **66 days is long for "short-lived".** Mail may wait 33 days and must still verify when it is read, so a certificate has to outlast the mail it signed.
- **A newer certificate does not retire an older one for mail already signed.** It does at the server and for prekey statements.

## 3. The server holds no signature that proves who sent what to whom

**Ours** (decided 2026-10-13; issue #29): the sender signs the envelope and encrypts it with the signature after it. The server knows who sends to whom, from the pass a send carries, since its limits depend on it, and holds nothing signed that says so. What is encrypted is the envelope as one line, the signature block exactly as `ssh-keygen` wrote it, then padding.

**The order: sign, then encrypt, with the signature inside.**

| Who | What they do | How it is known |
|---|---|---|
| **JOSE** | "normally producers should sign the message and then encrypt the result (thus encrypting the signature)": it keeps a signature from being stripped, and gives the signer privacy. A Nested JWT is a signed JWS carried whole as the plaintext of a JWE | RFC 7519 §11.2 and §2, read 2026-10-13 |
| **OpenPGP** | An encrypted message holds an OpenPGP message, which may be a signed one: a one-pass signature packet, the message, the signature packet | RFC 9580 §10.3, read 2026-10-13 |
| **S/MIME** | The signed and the enveloped formats nest, in either order. Signing first hides the signatories inside the envelope; enveloping first leaves them exposed, and lets a signature be verified without removing the envelope | RFC 8551 §3.7, read 2026-10-13 |
| **Nostr NIP-17** | A signed "seal" is encrypted inside an ephemeral-key "gift wrap": the signature is inside | review 2026-10-10 |
| **Signal, WhatsApp** | Messages are authenticated with keys both sides share, so no signature exists for anyone to show | review 2026-10-10 (deniable); the mechanism from memory |
| **iMessage** | Every message is signed by a device key, where its server sees it | review 2026-10-10 |
| **age's author** | Names the usual advice, to combine age with a signing tool such as signify or OpenSSH, and the flaw of each order; recommends no layout | words.filippo.io/dispatches/age-authentication, read 2026-10-13 |

**The layout: the signed bytes as they are, then the signature.**

| Who | How the signed bytes and the signature travel together | How it is known |
|---|---|---|
| **git** | A detached signature, the SSH format among them, is embedded in the object it signs: appended to a tag, a header of a commit. The payload is not encoded | `gitformat-signature`, read 2026-10-13 |
| **OpenPGP, CMS** | Binary packets: the signed bytes as they are, between or beside the signature | RFC 9580 §10.3, read 2026-10-13; CMS from memory |
| **JWS, DSSE** | One JSON object with the signed bytes and the signature as base64 members | RFC 7515 §7.2.1 and `secure-systems-lab/dsse` `envelope.md`, read 2026-10-13 |
| **JOSE, later** | An option not to encode the payload, for cases where the encoding is "unnecessary and/or an impediment to adoption, especially when the payload is large and/or detached" | RFC 7797, abstract, read 2026-10-13 |

They agree on the method and not on one byte layout: each puts its own signed-message object, whole, inside the encryption. Ours is git's, for a signed tag, because the signature is the same format and the layout costs a fixed number of bytes. The JSON object with base64 members was not taken: it makes the envelope a third larger inside every ciphertext.

**What went wrong with that layout elsewhere, and the rule each gives a reader** (`PROTOCOL.md` §4.4):

| What happened | The rule | How it is known |
|---|---|---|
| **gitsign** verified a commit or tag as go-git encoded it again, and not its raw bytes. For an object with a header given twice, git read one tree and gitsign's verifier another | The signature is checked over the envelope's line exactly as decrypted, its members are read from those same bytes, and a key given twice is refused | GHSA-7rmh-48mx-2vwc (2026-05-08), read 2026-10-13 |
| **GitLab** took the signature header to be a commit's last, and counted what followed it as signed, so a signed commit could be altered and still be shown as signed | Each part has one place and nothing is searched for: line 1, then a signature block from line 2 to the first END line, and nothing after it is read | GitLab issue 407252 (2023-04-02), read 2026-10-13 |
| **git before 2.20** took a commit carrying two OpenPGP signatures: it read the verifier's status lines, where a later one overrode an earlier, and discarded its exit status | One signature, verified against one identity, and the verdict is the verifier's exit status | M. Górny, "Attack on git signature verification via crafting multiple signatures" (2019-01-26), read 2026-10-13 |

None of the three was a flaw in the layout: each was a verifier that read an object differently from its signer.

**Where ours differs, and why:**
- **The recipient is named in what is signed** (the namespace, and the envelope's `to`), which git has no need of. It is what stops a recipient passing a signed message on to a third box, the flaw age's author names for this order.
- **The sender's identity document rides in the envelope,** as a JWS may carry its signer's key in its header (RFC 7515 §4.1.3, from memory). The address is its hash, so a recipient checks a sender it has never met without asking the server.
- **A recipient decrypts before it can verify,** as with every row of the first table that signs inside. What is lost is what S/MIME's text names: a signature that can be checked without the key that decrypts.

## 4. The rest: one row a decision

**Keys and identity**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| The address is the SHA-256 of the identity document: a self-certifying name | Tor v3 onion addresses; content-addressed identifiers (IPFS CIDs); Nostr public keys; did:key; SimpleX's capability addresses | review 2026-10-10 |
| A separate key for signing and for encryption | libsodium calls separate keys "highly recommended". Joint use of one key pair has a proof for the general construction (Thormarker, ePrint 2021/509), of which age's SSH recipient is a variant | review 2026-10-10 |
| A prekey the box signs, with a key its identity certified, renewed, with the address unchanged | Signal's signed prekeys; MLS's KeyPackages; Matrix cross-signing | review 2026-10-10 |
| Registration proves possession by two signatures: the identity's certificate for a working key, and a pass minutes old that the working key signs | The certificate signing request, for the first; a fresh, short-lived assertion in place of a challenge, for the second (Part 2, § 1) | review 2026-10-10; §3 |
| Small-order and non-canonical Ed25519 keys are refused by explicit code | libsodium's practice. Go's `crypto/ed25519` and OpenSSH accept them | review 2026-10-10; §3 |
| Small-order X25519 points are refused at registration | age itself refuses an all-zero shared secret | review 2026-10-10 |
| One identity key type is mandatory to implement, the rest optional, and each server lists what it registers | TLS 1.3's mandatory-to-implement algorithms, which name the signature algorithms an application must support and leave the rest optional (RFC 8446 §9.1); JOSE, where `HS256` is Required and the other algorithms Recommended or Optional (RFC 7518 §3.1) | read 2026-10-13; §2, §3 |
| A box declares the sender key types its client verifies, and the server refuses a sender it rules out | TLS 1.3's `signature_algorithms` and `signature_algorithms_cert` extensions, in which a peer lists the signature algorithms it will verify in a handshake and in a certificate (RFC 8446 §4.2.3); SSH's `server-sig-algs`, in which a server lists the public key algorithms it accepts (RFC 8308 §3.1). Each is a list an endpoint sends on its own connection. Ours is kept by the server for two boxes that never connect, and is not signed: §2c says why that is enough | read 2026-10-13; §2c |
| A P-256 identity key is held to what OpenSSH requires of an EC public key, by explicit code where a library does not | OpenSSH's `sshkey_ec_validate_public` (`sshkey.c`): not the point at infinity, each coordinate longer than half the bits of the group's order, the order times the point at infinity, each coordinate below the order less one. The Go SSH library checks the curve and the encoding, and takes a point with a short coordinate | read 2026-10-13 at OpenSSH `V_10_2_P1`; measured that day with `golang.org/x/crypto` v0.58.0 and OpenSSH 10.2; §2 |
| Nothing rests on a certificate's signature having one encoding | An ECDSA signature has several: s and n − s, and either number written with leading zero bytes. Bitcoin made one form mandatory because a transaction's id hashed its signatures (BIP 62, BIP 66, BIP 146); SSH and TLS have no such rule. Here a certificate's hash names it only to the server that checked it, and no recipient trusts one | from memory, for the BIPs; measured 2026-10-13: the Go SSH library and OpenSSH 10.2 both take n − s and a padded r; §2b |
| Revocation is permanent, signed by the identity, and can be signed in advance | OpenPGP revocation certificates, which GnuPG makes when a key is created; X.509 CRLs | review 2026-10-10; §6.3, not built |
| Post-quantum by default | TLS's X25519MLKEM768, OpenSSH 10, Signal, iMessage PQ3 | review 2026-10-10 |

**Encryption and signing**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Standard primitives and nothing home-made: age v1, Ed25519, SHA-256, HMAC-SHA-256, HKDF | The C2SP age specification; RFC 8032; RFC 2104; RFC 5869 | review 2026-10-10 |
| A signature namespace for each purpose, each naming the box it is about | SSHSIG's own namespace mechanism (OpenSSH `PROTOCOL.sshsig`) | review 2026-10-10 |
| A signature covers exact bytes, never JSON serialized again | The canonicalization lesson of JWS and XML-DSig, and of git verifiers that checked a rebuilt object (Part 2, § 3) | review 2026-10-10 |
| The envelope inside carries `from` and `to`, and the recipient refuses a mismatch | Davis, "Defective Sign & Encrypt" (USENIX 2001); Nostr NIP-17's signed seal | review 2026-10-10 |
| The recipient is bound into the signature | The other half of Davis's fix for composing a signature with encryption | review 2026-10-10 |
| A keyed hash is HMAC or HKDF, never `hash(secret ‖ …)`; plain SHA-256 only over public inputs | Signal, TLS 1.3, MLS, age, Certificate Transparency and Git's newer object format use SHA-256 the same way | review 2026-10-10; §0 |
| Every message is padded to a whole number of blocks, with bytes after its signature | Noise §13, padding to hide a payload's length. OpenPGP has a padding packet for the same purpose, which follows a signed message inside the encryption, outside what is signed (RFC 9580 §10.3) | review 2026-10-10; RFC 9580 read 2026-10-13; §4.3a |
| No ratchet in v1: forward secrecy is per prekey, bounded by how often a box renews | age and OpenPGP have none; Signal, WhatsApp, iMessage and SimpleX ratchet (Part 1). A ratchet is state two parties advance together, which stock tools cannot keep and a box restored from its identity would lose | Part 1's sources; decided 2026-10-13, issue #31; §6.4 |

**Expiry, rollback, retries**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Every prekey statement expires, at most 33 days on, with no "never" | TUF's mandatory expiry: it bounds how long a hostile operator can hold a sender on an old statement | review 2026-10-10; §2a |
| A serial or a version only goes up, and a lower one is refused | TUF's protection against rollback | review 2026-10-10 |
| A retried send gets the original receipt, never an error | Stripe's idempotency keys; the IETF Idempotency-Key draft | review 2026-10-10 |
| Replay is refused by the recipient: an id recomputed from the ciphertext, a set of ids seen, a window on `sent_at` | no outside system was cited for it | review 2026-10-10 |

**The API**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| JSON in and out, every byte field standard base64 (RFC 4648) of the exact bytes | Google Pub/Sub's `data`, AWS KMS's `CiphertextBlob`, the GitHub Contents API's `content`; Gmail's `raw` is the same in base64url | review 2026-10-10; §4.5 |
| Error bodies are Problem Details; a 401 carries a challenge; a 429 carries `Retry-After` | RFC 9457; RFC 6750 §3; RFC 9110 and RFC 6585; the IETF RateLimit header fields are planned | review 2026-10-10; §13 |
| A list answer says how often to poll | GitHub's `X-Poll-Interval` | review 2026-10-10; §5.1 |
| A machine-readable description of the API, and pages | OpenAPI | review 2026-10-10; `/openapi.json` is not served yet |
| An address in a URL is a capability, so it is hashed in logs | W3C TAG, "Good Practices for Capability URLs" | review 2026-10-10 |
| Proof of work at registration, bound to the address and the date | Hashcash | review 2026-10-10; §8, not built |

**The client**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Commands nest as `irongall <group> <command>`, the everyday ones at the top level | `gh` and `docker` | from memory; issue #37, proposed |
| A box's state lives under `${XDG_CONFIG_HOME:-~/.config}` | The XDG Base Directory Specification | from memory; §1 |

**Designs considered and not chosen:**
- **Signal's one-time prekeys and the Double Ratchet.** Forward secrecy for each message needs state for each pair and a pool of keys the server manages: too much machinery for stateless bot mail. A prekey the identity signs and renews is the middle course.
- **HPKE's Auth mode** (RFC 9180). The server could verify nothing, a leaked recipient key would let anyone forge any sender to it, and no stock command-line tool does it.
- **libsodium's sealed box.** No command-line tool, and no key format that can be pasted.
- **One key for both signing and encryption.** It has a proof for the general construction; separate keys are what libsodium recommends, and what a prekey that can be renewed needs.
- **Noise's X and K:** 1b above.

---

# Sources

For rows marked `review 2026-10-10`. A row marked `read` carries its own link.

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
- [RFC 9457 — Problem Details](https://www.rfc-editor.org/rfc/rfc9457) · [RFC 6750 — Bearer tokens](https://www.rfc-editor.org/rfc/rfc6750) · [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)
- The agent-communication survey of 1c names its systems with the dates it found. That review kept no links for them.

# Open in this file

- **To read at the source:** every row marked `from memory`; Apple's current page for § 1; the survey of 1c; and the systems of 1a whose designs move fastest (Signal, iMessage, Proton, SimpleX), last read 2026-10-10.
- **Decisions with no row yet:** accounts, the echo box, the share link, the limits a client meets.
- **The server is not in this repo,** so how irongall.dev's server is built has no row here.
