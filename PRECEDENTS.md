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
- **The gap between the two** does the job of GitHub's 60 seconds of backdating: a client whose clock is off is not refused. Here it is on the far end: every irongall check is exact at the verifier's clock, and the room is in what is made (§3a).
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
| **Short-lived certificates in place of revocation** | The web's rule waives revocation for a certificate of at most 10 days, 7 from 2026-03-15, and Let's Encrypt's six-day certificates carry no revocation URL at all (§ 3b) | read 2026-10-13 |

**Where ours differs, and why:**
- **Validity is judged at the verifier's clock,** as X.509 validation is without a trusted timestamp, where OpenPGP judges a signature at the time the signer states (both from memory). Nobody in irongall can vouch for when a signature was made, so a stated time proves nothing.
- **66 days is long for "short-lived".** Mail may wait 33 days and must still verify when it is read, so a certificate has to outlast the mail it signed. So a certificate is to be revocable, which is decided and not built (§ 3b).
- **A newer certificate does not retire an older one for mail already signed.** It does at the server and for prekey statements.

## 2a. A certificate's serial is taken from its maker's clock

**Ours** (decided 2026-10-14; issue #63): a client numbers a certificate by its own clock, in seconds since 1970, or one above the highest serial it knows of for the box when the clock gives nothing higher. A verifier compares two serials and reads neither as a time. So a box restored from its identity alone, which knows only what a server shows it, makes a certificate numbered above every one made before, and a revocation through the serial below it covers them all.

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | A serial "MUST be unique for each certificate issued by a given CA (i.e., the issuer name and serial number identify a unique certificate)". The issuer keeps that promise from its own record of what it issued, and nothing orders two serials | RFC 5280 §4.1.2.2, read 2026-10-14 |
| **The web's certificate authorities** | A serial carries at least 64 bits from a random source, so it is unique without a count | from memory |
| **OpenSSH certificates** | "serial is an optional certificate serial number set by the CA to provide an abbreviated way to refer to certificates from that CA." How a CA numbers is left to it, and a KRL is there "to revoke certificates by serial number or key ID" under the CA's key | `PROTOCOL.certkeys` at `V_9_9_P1` (the file is not on `master`) and `PROTOCOL.krl` on `master`, read 2026-10-14 |
| **BIND 9, a zone's serial** | With `serial-update-method unixtime`, "the SOA serial number is set to the number of seconds since the Unix epoch, unless the serial number is already greater than or equal to that value, in which case it is simply incremented by one." It is the rule here | The manual's `doc/arm/reference.rst` on `main`, read 2026-10-14. That a zone's secondaries only compare serials: from memory |
| **PowerDNS, signing as it answers** | `SOA-EDIT` `EPOCH` "Sets the SOA serial to the number of seconds since the epoch." Its reason is ours, a signer that keeps no count to raise: "With PowerDNS in Live-signing mode, the SOA serial is not increased by default when the RRSIG dates are rolled." | `docs/dnssec/operational.rst` on `master`, read 2026-10-14 |
| **RFC 1912** | For a zone's serial, "The recommended syntax is YYYYMMDDnn" | §2.2, read 2026-10-14 |
| **WireGuard's handshake** | "we include a TAI64N timestamp in the first message", encrypted, and "The server keeps track of the greatest timestamp received per client and discards packets containing timestamps less than or equal to it." A number from the sender's clock, held to an order by a receiver that compares and reads no time | wireguard.com/protocol, read 2026-10-14 |

**Where ours differs, and why:**
- **X.509's issuer keeps records, and an irongall identity is a key.** A certificate authority is never restored from its key alone; a box is, and that is what its recovery promises (`PROTOCOL.md` §6.4). The record a restored box could consult is its server's, which the protocol does not trust and which never saw a certificate made and not published.
- **X.509 needs a serial to be unique, and irongall also needs it to be ordered:** a box's statements are ordered by their certificate's serial (`PROTOCOL.md` §2b). A random serial, which is how an authority does without a count, gives no order. The clock is what a key with no records has that rises.
- **It is the serial, and not the certificate's own `valid after`, that carries the order.** Every verifier reads `valid after` as a time, so it cannot go one above the last when a clock reads behind. Nobody reads a serial as a time. And a revocation of certificates runs through a serial, as a KRL's range does: a KRL has no line for "made before a time".
- **What it rests on** is the clock of whoever holds the identity, and the spec says where that gives way: a clock that read ahead, a restore with a clock that reads behind at a server showing an older record, and two machines in one second.

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

## 3a. Clocks: every check is exact, and whatever is made leaves an hour of room

**Ours** (decided 2026-10-13; issues #40, #12 and #42): every check is exact at the clock of whoever makes it. Whoever makes a time-limited thing leaves an hour: a certificate starts an hour before it is made, a server takes a prekey statement that ends up to an hour past the 33 days a client asks for, a reader takes a `sent_at` up to an hour ahead of its clock, and a pass is asked for 10 minutes and taken up to 60 ahead. The hour is the pass's: a server takes a box whose clock is less than 10 minutes behind its own or up to 50 ahead, and no two such clocks are an hour apart. A box further off is refused at its pass and told how far its clock is from the server's (`PROTOCOL.md` §0).

**The maker dates the start back, and the verifier's check is exact:**

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **X.509 path validation** (RFC 5280 §6.1.3) | The verifier checks exactly | "The certificate validity period includes the current time" | read 2026-10-13: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) |
| **OpenSSH `ssh-keygen`** | Dates a certificate's start back by default; `sshd` checks exactly | now less 59 seconds, rounded down to the minute | read 2026-10-13: `ssh-keygen.c` at `V_10_2_P1` (`cert_valid_from = ((now - 59)/ 60) * 60`); the manual states no default |
| **Let's Encrypt** | Dates `notBefore` back | 58 minutes 30 seconds on its own site's certificate: `notBefore` 14:34:32, signed certificate timestamps 15:33:02, 2026-09-04 | measured 2026-10-13 with `openssl s_client -connect letsencrypt.org:443`; Boulder's `issuance/cert.go` takes 0.9 of a profile's largest backdate |
| **CA/Browser Forum Baseline Requirements** | Permit a CA to date back | a subscriber certificate's `notBefore` is "A value within 48 hours of the certificate signing operation" | read 2026-10-13: [`docs/BR.md`](https://github.com/cabforum/servercert/blob/main/docs/BR.md) |
| **HashiCorp Vault**, PKI and SSH | Dates back | `not_before_duration`, default 30 seconds | read 2026-10-13: [Vault API, PKI](https://developer.hashicorp.com/vault/api-docs/secret/pki) and [SSH](https://developer.hashicorp.com/vault/api-docs/secret/ssh) |
| **Kubernetes' certificate signer** | Dates back | 5 minutes | read 2026-10-13: `pkg/controller/certificates/signer/signer.go` (the code; its documentation was not read) |
| **OpenMLS** | Dates a KeyPackage's `not_before` back | an hour, "to adapt to skewed clocks" | read 2026-10-13: `openmls/src/key_packages/lifetime.rs` |
| **BIND `dnssec-signzone`** | Dates a signature's start back | "the current time minus 1 hour (to allow for clock skew)" | read 2026-10-13: its manual page, option `-s` |
| **MLS** (RFC 9420 §7.2) | Expects synced clocks | clients "SHOULD maintain time synchronization (e.g., using the Network Time Protocol)" | read 2026-10-13: [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) |

**The verifier of a short-lived token gives leeway:**

| Who | What they do | Their numbers | How it is known |
|---|---|---|---|
| **JWT** (RFC 7519 §4.1.4, §4.1.5) | Leeway on `exp` and `nbf`, optional | "some small leeway, usually no more than a few minutes" | read 2026-10-13: [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| **Kerberos** (RFC 4120) | Leeway both ways on an authenticator's time | "allowable clock skew (e.g., 5 minutes)"; the recommended constant is 5 minutes | read 2026-10-13: [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) §3.1.3, §8.2 |
| **DPoP** (RFC 9449 §11.1) | Leeway for an `iat` ahead, or a server nonce where clocks may differ more | "in the reasonably near future (on the order of seconds or minutes)" | read 2026-10-13: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) |
| **Mastodon's HTTP signatures** | Leeway both ways | `CLOCK_SKEW_MARGIN = 1.hour` | read 2026-10-13: `app/lib/signed_request.rb` (the code) |
| **DKIM** (RFC 6376 §3.5) | A timestamp ahead may be refused; room at expiry is optional | "MAY ignore signatures that have a timestamp in the future"; receivers "MAY add a 'fudge factor'" | read 2026-10-13: [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) |
| **GitHub Apps** | The maker dates `iat` back | 60 seconds, "to protect against clock drift" | §1's table |

**Where ours sits among them:**
- **An exact check, with the room left by whoever made the thing,** is how a certificate is handled in X.509 and OpenSSH. Nobody above checks exactly at both ends.
- **An hour** is what Let's Encrypt, OpenMLS and BIND date back by: each makes things that strangers on the internet verify. Thirty seconds to five minutes (Vault, Kubernetes, OpenSSH's default) is for machines one operator runs. irongall's boxes are strangers to each other.
- **The pass is the short-lived token.** A box is taken from under 10 minutes slow to 50 fast, by the server's clock: on the slow side that is twice Kerberos's 5 minutes, and it is the pass's own lifetime.
- **A `sent_at` more than an hour ahead is refused,** which is Mastodon's margin and more than DPoP's minutes. An honest sender's is not that far ahead: it posts nothing dated ahead of its own clock, and a server takes its pass only while that clock is at most 50 minutes fast.

**Where ours differs, and why:**
- **No leeway at any verifier,** where JWT and Kerberos put theirs. All the room is in what is made, so every check is one comparison against the verifier's own clock, and the rule a verifier applies has no number in it to disagree about. A caller sees the same effect.
- **A client compares its clock with the server's and does not correct by it.** The protocol is designed against a server that may be hostile, so the server's time is a thing to report as the server's word, never one to check by: a clock set by a server's lie would make an ended certificate valid again. The client's own words send its reader to a time source they trust.
- **Before 2026-10-13** nothing was dated back but by `ssh-keygen`'s default minute, and a prekey was asked for at exactly its ceiling. Measured then: a new box worked only from about a minute slow to about a second fast, and a reader two minutes slow lost mail under a fresh certificate (issue #40). No system above is that narrow.

**Not read:** AWS's request-signing window and smallstep's default backdate.

## 3b. Revocation: the identity signs it, every client checks it, and nothing less revokes

**Ours** (decided 2026-10-13; issue #14; §6.3): an address is ended for good by its identity's own signature over a fixed statement, with no date, no reason and no number in it. The record is that signature with the identity document, so it proves itself, and a client takes an address as revoked only with a record in hand that verifies: never on a server's `410`. A verified revocation is kept, reaches back over everything that address signed, and is never undone. A revocation is of the identity and of no one server, so any mailbox server or revocation server may hold a record, and a client may ask more than one (issue #52). **Certificates** are revoked the same way, and the address goes on (decided 2026-10-13, issue #51; through a serial since 2026-10-14, issue #79; §6.3a): the identity signs that every certificate it made up to and including a serial is revoked, the highest it has signed stands and nothing revokes fewer, and whoever has verified it takes nothing a revoked certificate signed.

**Who signs a revocation, and what it covers:**

| Who | What they do | How it is known |
|---|---|---|
| **OpenPGP** | A key revokes itself (signature type 0x20) or one subkey (0x28: "calculated directly on the primary key and the subkey being revoked. A revoked subkey is not to be used"). A revocation carries a reason: superseded, compromised, retired. "If a key has been revoked because of a compromise, all signatures created by that key are suspect. However, if it was merely superseded or retired, old signatures are still valid" | read 2026-10-13, [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) §5.2.1.11, §5.2.1.12, §5.2.3.31 |
| **X.509** | The issuer revokes one certificate by its serial, in a list it signs, numbered by "a monotonically increasing sequence number". An entry stays "until it appears on one regularly scheduled CRL issued beyond the revoked certificate's validity period". Only a hold is ever undone. An entry may carry the date the key is "known or suspected" compromised | read 2026-10-13, [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) §3.3, §5.2.3, §5.3.1, §5.3.2 |
| **CA/Browser Forum** | A certificate needs no revocation information only when it is short-lived: at most 10 days, and at most 7 for one issued on or after 2026-03-15. Every other must be revoked within 24 hours of a key compromise | read 2026-10-13, [Baseline Requirements](https://github.com/cabforum/servercert/blob/main/docs/BR.md) §1.6.1, §4.9.1.1, §7.1.2.11.2 |
| **Let's Encrypt** | Six-day certificates "will not include OCSP or CRL URLs": a short life "reduces the need for certificate revocation, which has historically been unreliable" | read 2026-10-13, [its announcement of 2025-01-16](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs/) |
| **OpenSSH** | A revocation list (KRL) revokes a CA's certificates by serial, by a range of serials or by key id, under a version that "increases each time the KRL is modified". It has no signature of its own: "KRL signatures are not supported by OpenSSH", and it recommends SSHSIG for one that travels. `ssh-keygen -Y verify -r` applies one to a signature: a range revoked the certificates under it and passed the next (measured 2026-10-14, OpenSSH 10.2). git takes one too: `gpg.ssh.revocationFile` is "Either a SSH KRL or a list of revoked public keys (without the principal prefix)." | read 2026-10-13 and 2026-10-14, [`PROTOCOL.krl`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl), `ssh-keygen(1)` and git's [`gpg` settings](https://github.com/git/git/blob/master/Documentation/config/gpg.adoc) |
| **Go** | `x/crypto/ssh` reads no KRL: its `CertChecker` leaves revocation to a function its caller writes, `IsRevoked`. A KRL package for it was proposed and declined in 2019: "This does not seem like enough people need it to adopt it." The library that proposal pointed to, `stripe/krl`, now says: "This project is deprecated and is no longer being actively maintained." | read 2026-10-14, [golang/go#22741](https://github.com/golang/go/issues/22741), `go doc golang.org/x/crypto/ssh.CertChecker`, [`stripe/krl`](https://github.com/stripe/krl) |

**Revoking everything issued before a point:**

| Who | What they do | How it is known |
|---|---|---|
| **AWS IAM** | A role's active sessions are revoked by a policy that denies every action to credentials whose `aws:TokenIssueTime` is earlier than a given time; new credentials are issued as before | read 2026-10-14, [Revoking IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) |
| **Microsoft Entra ID** | `revokeSignInSessions` invalidates a user's refresh tokens and session cookies by setting `signInSessionsValidFromDateTime` to the present | read 2026-10-14, [Microsoft Graph, `user: revokeSignInSessions`](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) |
| **Firebase Authentication** | `revokeRefreshTokens` revokes every refresh token of a user, and the time it did so is the user's `tokensValidAfterTime` | read 2026-10-14, [Manage user sessions](https://firebase.google.com/docs/auth/admin/manage-sessions) |
| **CA/Browser Forum** | No suspension: "The Repository MUST NOT include entries that indicate that a Certificate is suspended." | read 2026-10-14, [Baseline Requirements](https://github.com/cabforum/servercert/blob/main/docs/BR.md) §4.9.13 |

**A revocation made in advance:**

| Who | What they do | How it is known |
|---|---|---|
| **GnuPG** | Makes one with every new key, unasked, and keeps it "in the openpgp-revocs.d directory below the GnuPG home directory". It carries no reason, and the file says: "if the secret key is still accessible, it is better to generate a new revocation certificate and give a reason". A colon before its armor keeps it from being imported by accident. After one made by hand it prints: "Please move it to a medium which you can hide away; if Mallory gets access to this certificate he can use it to make your key unusable" | read 2026-10-13, the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html), `--generate-key`, and [`g10/revoke.c`](https://github.com/gpg/gnupg/blob/master/g10/revoke.c) |
| **Sequoia** | Makes one with every new key, unasked: "The co-generated emergency revocation file will automatically be stored in `$HOME/.local/share/sequoia/revocation-certificates` if you don't specify a different location" | read 2026-10-13, [the Sequoia book](https://book.sequoia-pgp.org/sq_key_generation.html) |

**Who may serve a revocation, and what a client does with no answer:**

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | "CRLs may be distributed by exactly the same means as certificates themselves, namely, via untrusted servers and untrusted communications." Its named limit is time: a revocation is not reliably seen until the next list is due | read 2026-10-13, RFC 5280 §3.3 |
| **OCSP** | The party that answers signs the answer, so it must be the issuer, a delegate the issuer names, or one the client was told to trust: a client "MAY provide a means of locally configuring one or more OCSP signing authorities" | read 2026-10-13, [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) §4.2.2.2 |
| **TLS** | A server hands its client the issuer's signed status in the handshake, so the client asks nobody else | read 2026-10-13, [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) §8 |
| **keys.openpgp.org** | A keyserver run by none of the keys' owners. "Non-identity information will still be distributed for all keys", so "it's still possible to check whether the key is revoked or not". A search "returns a key only if it exactly matches", which "prevents a malicious user or spammer from easily obtaining a list of all email addresses on the server". An upload needs no proof: "an attacker gains nothing from uploading a key they don't have access to" | read 2026-10-13, [its FAQ](https://keys.openpgp.org/about/faq) |
| **X.509's repository** | "repository: a system or collection of distributed systems that stores certificates and CRLs and serves as a means of distributing these certificates and CRLs to end entities". A party that signs its answers has to be trusted, and one that only stores does not: "the certificate validator needs to trust the on-line validation service while the repository does not need to be trusted" | read 2026-10-14, RFC 5280 §3, §3.3 |
| **The OpenPGP keyserver protocol** | "a keyserver - a server that stores public keys and/or certificates, with a searchable interface". Its "index" is an operation, a listing: it "requests a list of certificates on the keyserver that match the text in the \"search\" field" | read 2026-10-14, [draft-gallagher-openpgp-hkp-08](https://www.ietf.org/archive/id/draft-gallagher-openpgp-hkp-08.txt) §1, §5.2.4 |
| **Sequoia** | A client lists several keyservers and uses every one: by default certificates are published to five named servers, `--server` "can be given multiple times", and the default "can be changed in the configuration file using the setting `network.keyservers`" | read 2026-10-14, [`sq network keyserver publish`](https://sequoia-pgp.gitlab.io/sequoia-sq/man/sq-network-keyserver-publish.1.html), sq 1.5.0 |
| **GnuPG** | One setting names the server "that gpg communicates with to receive keys, send keys, and search for keys", the value `clear` empties the list, and it ships none: "There is no default keyserver since version 2.5.3" | read 2026-10-14, the [GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Dirmngr-Options.html), `--keyserver` |
| **IETF Token Status List** | Whoever serves a status list need not be whoever signed it: "Status Provider: An entity that provides the Status List Token on a public endpoint. This role may be fulfilled by the Status Issuer" | read 2026-10-14, [draft-ietf-oauth-status-list-12](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-12.txt) §3 |
| **Firefox** | A lookup that may fail is given a short wait: "By default, Firefox ignores the revocation check (i.e. soft-fails) if a valid response is not received from the OCSP server within 2 seconds (10 seconds for an EV certificate)" | read 2026-10-14, [Mozilla wiki, Revocation Checking in Firefox](https://wiki.mozilla.org/CA/Revocation_Checking_in_Firefox) |
| **keys.openpgp.org, its limits** | "Requests by fingerprint or key id are limited to five requests per second" | read 2026-10-14, [its API page](https://keys.openpgp.org/about/api) |
| **Mozilla CRLite** | A party that is no certificate authority gathers every revocation and ships the set to browsers, updated "four times per day", "replacing a network round-trip with local lookups" | read 2026-10-13, [Mozilla Security Blog, 2020-01-09](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) |
| **What went wrong on the web** | A check that passes when no answer comes is "completely useless": whoever can block the answer has a revoked certificate accepted. A check that refuses is not deployable. "If they were only valid for days then revocation would take care of itself." Let's Encrypt ended OCSP in 2025 because the responder "immediately becomes aware of which website is being visited" | read 2026-10-13, [A. Langley, 2014-04-19](https://www.imperialviolet.org/2014/04/19/revchecking.html); [Let's Encrypt, 2024-12-05](https://letsencrypt.org/2024/12/05/ending-ocsp/) |
| **HTTP** | "A 410 response is heuristically cacheable" unless it says otherwise. Under `no-store` a cache "MUST NOT store any part of either the immediate request or the response" | read 2026-10-13, [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) §15.5.11; [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) §5.2.2.5 |
| **An extension point nobody uses** | "Mechanisms that aren't used are the ones that fail most often." "Only by using the extension capabilities of a protocol is the availability of that capability assured" | read 2026-10-13, [RFC 9170](https://www.rfc-editor.org/rfc/rfc9170) §2.1, §3 |

**When a verifier asks, and how long an answer holds:**

| Who | What they do | How it is known |
|---|---|---|
| **X.509** | The list says when its successor is due: `nextUpdate` "indicates the date by which the next CRL will be issued", and "Conforming CRL issuers MUST include the nextUpdate field in all CRLs". A verifier works from a "local CRL cache", and fetches when "the current time is after the value of the CRL next update field" | read 2026-10-13, RFC 5280 §5.1.2.5, §6.3.3 |
| **OCSP** | The signed answer carries the same time, "at or before which newer information will be available about the status of the certificate", and it is optional: "If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time" | read 2026-10-13, RFC 6960 §2.4, §4.2.2.1 |
| **OpenSSH** | A server checks a local file of revoked keys and fetches nothing: it "may be consulted for each public key authentication attempt", so "it should only be atomically replaced". "if this file is not readable, then public key authentication will be refused for all users" | read 2026-10-13, [`sshd_config(5)`](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5), `RevokedKeys` |

**Where ours follows them:**
- **A send and a read are checked against what the box itself holds, with no call,** as OpenSSH checks its file and a browser its bundled set (CRLite, above). Whatever a client has verified about an address, from a mailbox server, a revocation server or a file, it keeps for good (decided 2026-10-13; issue #55; §6.3). A kept list is one file, moved into place whole, which is what `sshd_config(5)` asks of its own.
- **A client asks again when the answer it holds says nothing about now.** A CRL and an OCSP answer carry the time until which they stand, signed by whoever answers. Here a record that verifies stands for good and needs no such time, and the other answer, "none held", is signed by nobody: it is OCSP's answer with no `nextUpdate`, for which newer information is "available all the time". So a client asks before every post and for each sender in a drain, and keeps nothing of "none held" (§4.1).
- **The key revokes itself, and the revocation travels through servers nobody trusts,** as an OpenPGP key's does and as a CRL does. Here the identity signs it, as an OpenPGP key signs its own, so whoever serves one signs nothing and needs no delegation: a revocation server can keep a revocation back and cannot make one. That is the question X.509 has to answer with a delegate or a locally trusted responder, and it does not arise.
- **A revocation is of the identity, wherever that identity is used,** as an OpenPGP key's revocation is of the key whichever keyserver holds it, and a CRL of a certificate wherever it is presented. Nothing in an address names a server (§2): a mailbox server is one route to a box, and a box's identity may one day be reached by another. So a revocation is kept where anyone can ask, and not as one mailbox server's fact (§6.3).
- **What keeps it is a revocation server, named after the keyserver, and it is one:** run by anyone, chosen by the client, filled by upload, trusted for nothing, which is also what X.509 says of its repository. A client lists several, as `sq` and `gpg` list keyservers, asks every one it lists and publishes to every one it lists, as `sq network keyserver publish` does. A record that verifies from any one of them is final, so each one asked can only add. **The word is not "index",** which this project used until 2026-10-14: no standard above uses it for the party that serves revocations, and in the keyserver protocol an index is the listing a keyserver gives.
- **A lookup is for an address the asker already holds, and nothing is listed,** which is keys.openpgp.org's rule and its reason: an address here is what lets anyone write to a box (§2). So a revocation server is filled by upload and never by copying another, where CRLite gathers everything.
- **Another party's revocation server is asked only when the client's owner says so.** A lookup tells that server who the asker corresponds with, which is what OCSP told a certificate authority. The mailbox server knows it already. So the one default is the revocation server that the mailbox server's own operator runs, and only for a box on that mailbox server: Sequoia ships five keyservers and GnuPG now ships none, and ours ships one, where asking it tells nobody anything new.
- **A certificate is revocable** (§6.3a): one here lives up to 65 days, because mail may wait 33 and must verify when it is read, and nothing above waives revocation past 10. It is by serial: the identity revokes every certificate it made through one, as AWS, Entra ID and Firebase revoke what was issued before a point, and as a KRL's range from serial 1 does. A certificate's serial is the time it was made (§2b), so that is everything made before, on any machine. The highest one a verifier holds is all it needs, and nothing revokes fewer, as nothing in the web's certificates is suspended.
- **A revoked address stays revoked.** Nothing above undoes a revocation but a hold, and there is no hold here.
- **No cache may keep an API answer,** since a `410` is cacheable by default.

**Where ours differs, and why:**
- **No reason and no date in the statement,** where OpenPGP and X.509 carry both. A fixed text is what lets a revocation be signed years early and rebuilt by its verifier from the address alone, so nothing in it is parsed before it is trusted. And a date would be its signer's word: nobody here can vouch for when anything was signed. So there is one kind, the kind OpenPGP calls compromised, and it reaches back over everything the address signed. A box that is only retired is closed, and its key destroyed, with no statement at all.
- **No slot for a later field,** where OpenPGP's subpackets, X.509's extensions and a KRL's extension sections each have one, with a flag meaning "refuse what you do not understand". That flag is unsafe in a revocation: a reader that refuses one it cannot fully read treats a revoked address as live. Without the flag a later field could only ever be a hint, and a slot every reader sees empty for years is the one RFC 9170 says fails when it is used. What is added later is a second statement under a new tag, beside the first, which is what GnuPG does when it says to make a new one with a reason.
- **Certificates are revoked by three lines of text the identity signs with SSHSIG, and not by a KRL,** OpenSSH's format for exactly this, which `ssh-keygen -Y verify -r` applies itself. Go reads no KRL, and declined to, so each client here would write its own reader for a binary format that, holding the one range a revocation needs, says one number. The signature is the one `ssh-keygen(1)` recommends for a KRL that travels (issue #79).
- **No list, no version, and no way to revoke fewer,** where a CRL and a KRL are lists under a number that only rises and either can leave an entry out of a later one. A later list that left a certificate out brought it back, and a holder could refuse that only against the lists it had seen, so two holders could give one certificate two verdicts. A revocation through one serial cannot cover less than one through a lower, so every holder's verdict rests on the highest it holds. What it costs: one certificate cannot be revoked and an earlier one spared. Nothing here needs that: a box holds one certificate at its server, and its next is numbered above every one revoked (§2b).
- **No date on a revoked certificate,** where a CRL entry may carry the date its key is known or suspected compromised. The reason is the one above: nobody here can vouch for when anything was signed, so a revoked certificate loses everything it signed. The cost falls on its owner too: mail the box itself sent under that certificate, and that its reader has not read yet, is refused with a thief's, and is sent again.
- **Nothing is ever dropped from it,** where a CRL drops an entry once a list past the certificate's end has been issued. It is one serial, so its size is fixed and a later one replaces it; a holder may keep it for good, and every certificate it covers has ended 66 days after it was made.
- **Neither client writes a revocation unasked,** where GnuPG and Sequoia write one with every key, under the same home. Their copy still works when the key no longer can be used, as when its passphrase is forgotten (the reason is ours to give: neither source states one). An irongall identity has no passphrase today, so a copy beside it is lost with it and stolen with it, and covers nothing. It becomes a liability once the identity is kept somewhere other than the box and the copy stays behind. A passphrase on the identity is planned (issue #50), and with one their default applies. GnuPG's guard against an accidental publish is here the address written out in full.
- **The proof is asked for, not handed along with the refusal,** where TLS staples it. A `410` says only that a record exists, and one call fetches it from the server or from any revocation server: one way to get a record, and the same way from every source.
- **No answer stops a drain and holds a send, and "none held" does neither.** That is neither of the web's two: a client here refuses to go on without an answer, which a browser could not afford, and it can, because the server it is waiting on is the one it is already fetching mail from, or is about to post to. It is OpenSSH's rule for a file it cannot read.
- **A revocation server's silence stops nothing, which is the web's soft fail, weakness and all.** The web found a check that passes with no answer "completely useless" against whoever can block the answer (above), and that holds here: a revocation server tells against a mailbox server that hides a record, and not against one that also controls its asker's network (§6.3, the limits). It is soft all the same, because the answer that must come is already asked for, of the mailbox server, and to require a second would let every server a box listed stop its mail. The wait is ten seconds, the longer of Firefox's two: nobody is waiting on a bot's send as a person waits on a page, and a command asks a silent server once.
- **The reference revocation server limits what a caller writes, and not what it reads,** where keys.openpgp.org limits lookups. Nearly every address it is asked about has no record, and that answer comes from memory; a record brought to it costs a signature check or two and a write, so that is what is counted, for each caller, before it is checked. It also bounds how many addresses it holds, which with the largest body it takes is the most disk it can be made to fill: anyone can make an identity and revoke it.
- **Nobody signs "none held", so nothing says how long it stands,** where a certificate authority signs "good" with a time on it. Only the identity could sign one here, and the identity is the key a box may keep away from its daily work (§2b); a working key's word that its own certificate is not revoked would be the thief's word too. So the answer has no lifetime a client could hold it for, and the cost is one call for each post, to the server the post goes to. What remains is the web's limit all the same: a server that answers falsely that it holds none is believed, and nothing here bounds how long a revocation can go unseen by a peer that asks one server.

**Not read:** how Signal, Matrix and Keybase handle a compromised identity or device.

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
| Revocation is permanent, signed by the identity, and can be signed in advance | § 3b, above | read 2026-10-13; §6.3 |
| Certificates are revoked through a serial the identity signs, and the address goes on | § 3b, above | read 2026-10-13 and 2026-10-14; §6.3a |
| A box's prekey statements are ordered by their certificate's serial first, and by their own serial second: a later certificate passes any serial under an earlier one | DTLS orders its records by an epoch and a sequence number. "The epoch number is initially zero and is incremented each time keying material changes and a sender aims to rekey", and "Sequence numbers are maintained separately for each epoch, with each sequence_number initially being 0 for each epoch". Here the certificate is the epoch: a new one is a new working key. Ours differs in putting no bound on either number: the highest certificate serial takes a signature by the identity, which can already end the address by revoking it | read 2026-10-13, [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) §4.2 (DTLS 1.3); the sentence on sequence numbers is also DTLS 1.2's, [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) §4.1; §2b |
| Post-quantum by default | TLS's X25519MLKEM768, OpenSSH 10, Signal, iMessage PQ3 | review 2026-10-10 |

**Encryption and signing**

| Decision | Who else does it, or the standard | How it is known |
|---|---|---|
| Standard primitives and nothing home-made: age v1, Ed25519, SHA-256, HMAC-SHA-256, HKDF | The C2SP age specification; RFC 8032; RFC 2104; RFC 5869 | review 2026-10-10 |
| A signature namespace for each purpose, each naming the box it is about | SSHSIG's own namespace mechanism (OpenSSH `PROTOCOL.sshsig`) | review 2026-10-10 |
| A signature is read as `ssh-keygen -Y verify` reads it: the armour's whitespace skipped and what follows its END line not read, `reserved` skipped and signed as empty | OpenSSH's `sshsig_dearmor` and `sshsig_wrap_verify`, the reference implementation; `PROTOCOL.sshsig`: "Implementations should ignore the reserved field if it is not empty" | `sshsig.c` and `PROTOCOL.sshsig` (openssh-portable), read 2026-10-14; `sig/` vectors |
| **A deviation:** a signature is at most 4,096 bytes, and every verifier, a server's included, refuses a longer one | OpenSSH's `sshsig_dearmor` sets no bound of its own. The reason: a server keeps a box's signatures for good and serves them to anyone who asks, and with no bound, bytes the signer chose (after the END line, in `reserved`, in a certificate's nonce) are what it stores. The OpenPGP keyservers served keys with no bound on the signatures attached to them, and in 2019 keys flooded with tens of thousands broke the clients that fetched them; keys.openpgp.org serves no third-party signatures | `sshsig.c`, read 2026-10-14; the keyservers from memory |
| An Ed25519 signature's S must be below the group's order L, by explicit code where a verifier does not check it | RFC 8032 §5.1.7; Go's `crypto/ed25519` refuses S + L. `ssh-keygen` 10.2p1 built on OpenSSH's own Ed25519 takes it, so the script checks S itself | RFC 8032 §5.1.7, read 2026-10-14 ("If any of the decodings fail (including S being out of range), the signature is invalid"); `ssh-keygen` measured 2026-10-14 (`sig/bad-s-plus-l`) |
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
| Every JSON text is I-JSON and is read one way by every reader: one object, names compared exactly, none twice in any object, numbers in JSON's grammar, no byte-order mark (§0b) | RFC 7493 (I-JSON), whose §3 has a security protocol's receiver "not trust" a text that breaks it; RFC 8259 §8.3 (names compared code unit by code unit) and §8.1 (a parser "MAY ignore" a byte-order mark, so need not take one); JWS, RFC 7515 §4: "JWS parsers MUST either reject JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically last duplicate member name". Go's `encoding/json/v2` refuses a name twice and invalid UTF-8 by default, naming the parser differential between two services as its reason | RFC 7493, RFC 8259 and RFC 7515 read 2026-10-14; the `encoding/json/v2` documentation (Go 1.27.2) read 2026-10-14; jq 1.7.1 and 1.8.1 measured 2026-10-14 (they take `NaN` and `01`, skip a byte-order mark, and keep the last of a name given twice); `json/` vectors |
| A byte field is base64 in its one encoding: padded, no line break, the unused bits zero (§0b) | RFC 4648 §3.1 (no line feed unless the referring specification says), §3.2 (padding), §3.3 (a decoder "MUST reject" a character outside the alphabet "unless the specification referring to this document explicitly states otherwise"), §3.5 (non-zero pad bits: "The specification referring to this may mandate a specific behaviour") | RFC 4648 read 2026-10-14; `answer/` vectors |
| An integer the protocol defines is from 0 to 2^53 − 1, and so is every serial, which a send carries as a JSON number | RFC 7493 §2.2: "An I-JSON sender cannot expect a receiver to treat an integer whose absolute value is greater than 9007199254740991 [...] as an exact value"; RFC 8259 §6 calls integers in that range interoperable | both read 2026-10-14 |
| A text nests at most 32 deep | RFC 8259 §9: "An implementation may set limits on the maximum depth of nesting". jq 1.7.1 refuses 257, Go's `encoding/json/v2` 10,001: a limit under both gives one verdict | RFC 8259 read 2026-10-14; both measured 2026-10-14 |
| A member null is the same as one left out | The protobuf JSON mapping: "null is valid for any field and leaves the field unset" | protobuf.dev, "ProtoJSON Format", read 2026-10-14 |
| An answer's member a client does not know is ignored; a request's a server does not know is refused | RFC 7493 §4.2, "Must-Ignore Policy": "Protocols that allow the introduction of new protocol elements in a way that does not disrupt the operation of existing software have proven advantageous in practice". The protobuf JSON mapping: "The Protobuf JSON parser should reject unknown fields by default" | RFC 7493 and protobuf.dev read 2026-10-14; §0a |
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
