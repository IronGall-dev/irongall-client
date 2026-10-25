# The IronGall Protocol, version 1

**Status: draft.** Nothing here is final until version 1 is declared stable. What must be settled first is this repository's issues in the milestone `M1: protocol freeze`.

## 1. Introduction

IronGall is end-to-end encrypted, sender-authenticated mail between programs, through a store-and-forward server. A mailbox, a *box*, is named by its *address*, the hash of its identity key's public document, so an address authenticates the key it names and needs no directory. A sender encrypts to the recipient's *prekey*, which the recipient's *working key* signed under a certificate from the recipient's identity, and signs the message inside the encryption. The server stores ciphertext. It holds no private key, no plaintext and no signature over any message.

The server is not trusted for confidentiality or for authenticity: every check that protects a message is a client's. Section 15 states what a hostile server can and cannot do.

This document specifies the formats, the meaning of each HTTP operation, and what a client and a server check. Alongside it:

- **`api/openapi.yaml` is normative for the HTTP shapes:** routes, methods, request and answer members with their types, status codes, error codes and headers. This document says what each operation means, who may call it, what is checked and what each refusal means.
Where the two disagree, `api/openapi.yaml` is right about a shape and this document about a meaning.
- **`testdata/vectors/` holds the conformance vectors** (Section 16).
- **`PRECEDENTS.md`** sets each design decision beside the published standards and deployed systems that make the same one.

## 2. Conventions

### 2.1. Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

### 2.2. Notation

- A *line* ends in LF (0x0A). A text "of N lines" is exactly N lines: no CR, and nothing after the last LF.
- `‖` is concatenation. `str(x)` is a uint32 big-endian length followed by the bytes of `x` (RFC 4251 §5).
- An **address** is written as 64 lowercase hexadecimal characters, wherever it appears: a path, a statement, an envelope, a namespace.
- A **time** is RFC 3339 in UTC to the second, exactly `YYYY-MM-DDTHH:MM:SSZ`. What ends at a time has ended at that second: it is valid while a clock reads before it.
- A **serial** is a decimal integer from 1 to 2^53 − 1 with no leading zero. 2^53 − 1 is the largest integer every JSON reader holds exactly (Section 3.3).
- **base64** is standard base64 (RFC 4648 §4) in its one encoding: padded, with no character outside the alphabet (a line break included), and the unused bits of its last character zero, so that encoding the bytes again gives the same text. Two places differ, and say so: the armour of a signature (Section 3.2) and an adopt key (Section 11.16).
- In a namespace or a statement, `<A>` is the address of the box that signs it.

### 2.3. Terms

- **Box:** a mailbox: an address, its keys and its mail. Never a machine.
- **Identity key:** a box's long-term signing key, of a key type Section 4 defines. It signs certificates (Section 5) and revocations (Section 10), and nothing else.
- **Identity document `D`:** the two-line text that carries the identity's public key (Section 4.1). **Address `H`:** the SHA-256 of `D` (Section 4.2). One identity key has exactly one address.
- **Working key:** an Ed25519 key that the identity certifies for at most 64 days and an hour. It signs everything else a box signs: prekey statements, mail and passes.
- **Certificate:** the OpenSSH user certificate by which the identity certifies a working key (Section 5).
- **Statement:** a fixed-form text of lines, each ended by LF, that a key signs with SSHSIG (Section 3.2): a prekey statement (Section 6), a pass (Section 8), a revocation (Section 10).
- **Prekey:** a box's current age encryption key. **Prekey statement:** its publication, signed by the working key (Section 6). A prekey is **retired** once the server takes a later statement.
- **Renewal:** the publication of a new prekey statement (Section 11.9).
- **Pass:** a statement a box signs to prove itself to its server on a call (Section 8).
- **Envelope:** the signed JSON line that carries a message's metadata and body (Section 9.1).
- **Server:** the mailbox server a box is registered at and calls. A box's **own server** is the one it registered at.
- **TTL:** 33 days: the longest a server keeps mail (Section 13) and a reader takes it as fresh (Section 12.3, check 6).
- **Active, revoked, unknown:** the states of a box at a server (Section 11.6).
- **Served:** as a server answers it when a box is read (Section 11.8): the server's word until a client has verified it.
- **Pinned:** a peer's identity that a client keeps once something it signed has verified, and uses over the served one ever after (Section 12.2).
- **No answer:** what a client takes a call to have had when it failed, or when its answer breaks the form this document gives it (Sections 3.3, 11.1, 11.2, 12.3): it says nothing about what was asked.
- **Drain:** a client's pass over its box: every page of its list, each message fetched, judged and acked (Section 12.3).
- **Native stanza:** an age recipient stanza of a type a prekey has, `X25519` or `mlkem768x25519` (Section 9.4).
- **Floor:** the cutoff a box's replay set has been pruned to (Section 12.3, check 9).

## 3. Primitives

### 3.1. Algorithms

| Name | Role | Specification |
|---|---|---|
| age v1 | encryption to a prekey: `mlkem768x25519` (the hybrid ML-KEM-768 + X25519 recipient), or `X25519` | C2SP age |
| Ed25519 | the working key; the identity key of type `ssh-ed25519` | RFC 8032 |
| ECDSA P-256 | the identity key of the optional type `ecdsa-sha2-nistp256` | FIPS 186-5, RFC 5656 |
| SSHSIG | every signature: the signer's signature over SHA-512 or SHA-256 of the message, in a namespace | OpenSSH `PROTOCOL.sshsig` |
| SSH public key text | `<key type> <base64 of the wire key>` | RFC 4253 §6.6, RFC 8709, RFC 5656 |
| OpenSSH certificate | the certificate of a working key | draft-ietf-sshm-cert |
| SHA-256 | the address; a message's id | FIPS 180-4 |
| UUID | an envelope's `msg_id` | RFC 9562 |

A keyed hash in this protocol is HMAC or HKDF, inside age. Plain SHA-256 is applied only to public inputs: the identity document and the ciphertext.

### 3.2. Signatures

Every signature is an SSHSIG. For an Ed25519 key, the key signs

    "SSHSIG" ‖ str(namespace) ‖ str("") ‖ str(hash) ‖ str(HASH(message))

and the signature is a PEM-armoured (`SSH SIGNATURE`) blob:

    "SSHSIG" ‖ u32(1) ‖ str(signing key) ‖ str(namespace) ‖ str("") ‖ str(hash) ‖ str(str(key type) ‖ str(signature))

where `hash` is `sha512` or `sha256`. A verifier MUST accept both. The signing key is the certificate for what a working key signs (Section 5), and the bare identity key for what an identity signs.

A verifier MUST read a signature as OpenSSH's `sshsig.c`, and the key and signature code beneath it, reads one, with the two additional checks below. Where OpenSSH's builds differ, the rules below decide, and where they say nothing, the reading of OpenSSH 10.3p1 linked to an OpenSSL that has Ed25519; Appendix A lists where a build differs from them, and the `sig/` vectors (Section 16) hold each reading.

- **Armour.** The BEGIN line, ending in LF or CRLF; then the base64, in which space, tab, LF, VT, FF and CR are skipped wherever they stand, and which is otherwise in its one encoding; then LF and the END line. Nothing after the END line is read. One NUL MAY be the last byte before that LF; any other NUL or byte outside the alphabet in the base64 is refused.
- **Blob.** Its version is 0 or 1. A string read where no signature covers it (the namespace, the hash name, each signature's key type, and a bare key's type and curve) MAY end in one NUL, which is not part of it; a NUL before its last byte is refused. The signed data is built from those strings without the NUL. What an identity signed inside a certificate is read byte for byte (Section 5). An ECDSA signature's r and s are each at most 2,049 bytes.
- **Reserved.** The signed data's reserved string is empty; the blob's reserved field is read and skipped, whatever it holds.
- **First additional check: a bound on size, per identity key type:** 4,096 bytes for `ssh-ed25519` and 4,096 for `ecdsa-sha2-nistp256`. Everything a box signs, with its identity or with a working key under its identity's certificate, is held to its identity's bound. The bound counts every byte of the field that carries the signature, anything after the END line included; in a message it is the block from its BEGIN line through its END line (Section 9.2). Every verifier, a server included, MUST refuse a longer signature before verifying it, and one longer than the largest bound of any key type before reading it, and MUST NOT shorten one. A key type added later states its own bound and leaves the others unchanged.
- **Second additional check: an Ed25519 signature's S is below the group order L** (RFC 8032 §5.1.7), in an SSHSIG and on a certificate.
- **The Ed25519 equation** is RFC 8032 §5.1.7's without the cofactor, `[S]B = R + [k]A'`, compared as encodings: a neutral R is taken, and R with a point of small order added is refused.

### 3.3. JSON

Every JSON text the protocol carries is read by these rules, by a server and by a client: a request body, an answer, an envelope (Section 9.1) with the body in it, a revocation record (Section 10.3), and what a client keeps of one. A text that breaks one is refused whole: a request with `400 bad_request` (`bad_encoding` for a byte member), an answer as no answer, an envelope as `bad_envelope`.

- **I-JSON** (RFC 7493): UTF-8; no member named twice in any object, after its escapes are read; no surrogate and no Unicode noncharacter in a name or a string, written or escaped.
- **One object,** and nothing after it but whitespace (space, tab, LF, CR). No byte-order mark.
- **Names match exactly,** case and all.
- **Numbers** are in JSON's grammar (RFC 8259 §6), and none is of greater magnitude than a binary64 holds. A nonzero number too small for binary64 is taken.
- **Depth:** at most 32, objects and arrays counted together, the outermost as one.
- **Types.** A member the protocol defines is of its type, and null is the same as the member left out, except the envelope's `body` (Section 9.1). An integer member is written in digits alone, from 0 to 2^53 − 1: `1.0` and `1e0` are not integers.
- **Bytes.** A byte member is base64 (Section 2.2).
- **Unknown members.** A server MUST refuse a member it does not know in what it is sent. Every other reader MUST ignore one: a client in an answer, a box in an envelope. The rules above hold in it.

### 3.4. Clocks

Every check of a time is exact at the clock of whoever makes the check, with no allowance. Whoever makes a time-limited object leaves an hour of room for clocks that differ, in the way each object's section states: a certificate's start and its ceiling at a verifier (Section 5), a prekey statement's ceiling at a server (Section 6), a pass's lifetime (Section 8), a reader's limit on `sent_at` (Section 12.3, check 6), a renewal's timing (Section 12.4), and the server's keep of mail (Section 13).

## 4. Identity and address

### 4.1. The identity document

The identity document `D` is two lines of ASCII: the tag, then one SSH public key as `<key type> <base64 of the wire key>`, with no comment:

```
irongall-v1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI<43 characters>
```

The key MUST be of a type this section defines, in its one encoding, and MUST pass that type's key checks. Its one encoding is the wire key as OpenSSH writes it back once read: the key, parsed as the type line 2 names and written again, gives the same bytes. So one key has one document, and one address.

| Key type | Document | What fixes its one encoding | Key checks |
|---|---|---|---|
| `ssh-ed25519` | 93 bytes | the key's length, 32 (RFC 8709 §4) | a canonical point, not of small order |
| `ecdsa-sha2-nistp256` | 173 bytes | the curve's name, `nistp256`, and an uncompressed point | the point on the curve, not the point at infinity, each coordinate below the field's size |

- **Every client MUST verify `ssh-ed25519`,** and a client MUST NOT make an identity of any other type unless its owner asks for one. Every other type is OPTIONAL: a client verifies it or not, and a server registers it or not (Section 11.7). A box of an optional type can be written to, and heard from, only by boxes whose clients verify that type (Section 7).
- **The form is the same for every key type, defined here or not:** the tag line; a key type's name (RFC 4251 §6: printable ASCII with no comma, at most 64 characters); one space; the base64 of an SSH wire key that begins with that same name; LF. A reader MUST refuse a well-formed document of a type it does not verify as `unsupported_key_type`, never as malformed: a document that breaks the form, or does not hash to its address, is evidence of tampering, and one of a type the reader lacks is not.

### 4.2. The address

The address is the lowercase hexadecimal SHA-256 of `D`, 64 characters: `sha256sum < identity.doc | cut -c1-64`.

- It commits to the identity alone, so renewing or changing the type of the prekey never changes it.
- It has no checksum: a mistyped address names no box.
- Line 1 of `D` is the protocol's version. Another deployment of this protocol uses its own tag, and so its own address space.
- A client MUST write `from` (Section 9.1) in lowercase: a reader compares it with the verified signer as an exact string.

### 4.3. The link

An address is shared as the link `https://<server>/to/<address>`.

- A server MUST serve a page there for exactly 64 lowercase hexadecimal characters, and `404` for any other path. The page is fixed text, the address and the server's own link to it, and never text a box supplied, sent with `Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex`. A query on the link is ignored.
- A client given a link MUST take the address from its path, MUST NOT fetch the page, and MUST refuse a link to any server but its own.

## 5. The working key and its certificate

The identity signs certificates and revocations, and nothing else. Every other signature a box makes is its working key's, under a certificate the identity signed. A box that holds its identity makes its own certificates; a box whose identity is held elsewhere is given each certificate by whoever holds the identity (Section 12.7).

A certificate is an OpenSSH user certificate, and a verifier MUST check every row of this table:

| Field | Rule |
|---|---|
| Type | a user certificate |
| Certified key | the working key: `ssh-ed25519`, held to that type's key checks (Section 4.1), and never the identity key |
| Serial | a serial (Section 2.2), numbered as below |
| Key id | exactly `irongall-cert-v1` |
| Principals | exactly one: the box's address |
| Validity | `valid after` ≤ now < `valid before` ≤ now + 64 days and an hour, at the verifier's clock, in whole seconds |
| Critical options | none. A verifier MUST refuse a certificate with any (draft-ietf-sshm-cert-01 §2.1.1) |
| Extensions | ignored, each, but a verifier MUST refuse a certificate whose extensions are not in one encoding: each name once, in lexical order, and each value empty or one string that is not empty. A maker writes none |
| Reserved | ignored, whatever it holds. A maker writes it empty |
| Signed by | the key in the identity document, byte for byte |

Example: `ssh-keygen -s identity -I irongall-cert-v1 -n "$A" -z "$SERIAL" -V -1h:+64d -O clear work.pub`.

- **A signature by a working key carries its certificate** as the SSHSIG's signing key. A verifier MUST take the certificate from the signature, check it against the identity it holds for the address, and then verify the signature under it. A verifier MUST refuse such a signature by the bare working key or by the identity.
- **A certificate is checked at the verifier's clock, and only once the identity's signature on it has verified.**
- **A maker dates a certificate from an hour before it makes it, and asks for 64 days.** A verifier takes up to 64 days and an hour.
- **A box MUST NOT sign mail under a certificate with 33 days or less left,** so that the certificate outlasts the TTL of what it signed.
- **Every certificate certifies a new working key.**
- **Serials.** The maker numbers a certificate by its own clock, in seconds since 1970-01-01T00:00:00Z, or one above the highest serial it knows of for the box when its clock gives nothing higher: the served certificate's, what the box published or signed, and the highest serial the identity has revoked (Section 10.2). A box's first certificate is numbered the same way. A verifier MUST NOT read a serial as a time, or bound it by its clock: it compares two serials, and the higher is later. Two certificates of one identity can share a serial (made in one second, or each one above the same serial); a verifier that meets two takes either, and keeps nothing of it beyond the serial.
- **Ordering.** A box's prekey statements are ordered by their certificate's serial first, and by their own serial second. A statement is later than another if it is under a certificate of a higher serial, at any prekey serial, or under the same certificate at a higher prekey serial. A server orders a box's statements so (Section 11.9), and so does a sender, by what it has seen (Section 12.2).
- **What a later certificate retires.** At the server, everything under a certificate of a lower serial: it takes no pass and no statement under one (Sections 8, 11.9). At a sender, every statement under a lower one. At a reader, nothing: mail is taken under any certificate of its sender's identity that is valid when it is read and is not revoked (Section 10.2).
- **Nothing may depend on a certificate having one encoding.** A certificate an ECDSA identity signed has others, (r, n − s) and either number zero-padded up to 2,049 bytes, which anyone who has seen it can write. A server takes a pass only under exactly the bytes it has on record (Section 8).

## 6. The prekey statement

Five lines, signed by the box's working key under its certificate, in the namespace `irongall-prekey-v1:<A>`:

```
irongall-prekey-v1
<A>
<serial>
<age recipient>
<not_after>
```

- **Serial:** a serial. Under one certificate, each statement's is higher than the last's.
- **Key:** an age recipient of a type its Bech32 human-readable part names (BIP 173, as age writes a recipient: lowercase, its checksum valid, its data whole bytes, and with no limit on its length, as age has it): `age1pq` for `mlkem768x25519`, `age` for `X25519`. A key whose X25519 point, or whose post-quantum key's X25519 half, is of small order breaks the statement. A client makes a post-quantum prekey unless its owner asks for X25519. A prekey type added later is an addition inside v1 (Section 14).
- **`not_after`:** a time. A client signs a statement to end 33 days after it makes it, or sooner, down to a day and three hours (Section 12.4). A server takes a statement that ends at most 33 days and an hour after its own clock reads. A statement MUST NOT end after its certificate does.
- **A sender MUST NOT encrypt to a prekey past its `not_after`.** There is no grace period.
- **A sender MUST keep, for each box, the highest certificate serial and prekey serial it has seen on the box's statements, and refuse an earlier statement** (Section 5, ordering).
- **A sender MUST hold a statement to every other rule before its key's type.** A statement that passes every other rule and whose key is a well-formed Bech32 string whose human-readable part begins `age` and is neither `age` nor `age1pq` is refused as `unsupported_prekey_type`, never as a statement that does not verify, and nothing is sealed or posted to it.

## 7. Sender key types

A box declares the identity key types its client verifies, so that a sender of an optional type does not write to a box that cannot read it.

- **With each prekey it publishes, a box SHOULD declare every identity key type its client verifies,** in `sender_key_types`, a list of key type names, in its registration (Section 11.7) and in each renewal (Section 11.9). The read of the box carries it (Section 11.8).
- **`ssh-ed25519` is taken by every box, whatever it declared.** A box that declared nothing takes `ssh-ed25519` senders only.
- **A sender whose identity's type is not on the recipient's list MUST NOT send,** and a server refuses the send, `403 sender_key_type` (Section 11.10, step 7).
- **The one entry `any`** says that the box does not say which types its client verifies. A server then makes no check for that box. A client declares `any` only when its owner tells it to.
- **The declaration is the current prekey's.** A renewal replaces it, with nothing if it carries none; an identical retry changes nothing.
- **It is not signed.** What a recipient takes is decided by what its client verifies (Section 12.3), never by this list.
- **A server keeps the names it knows and ignores the rest.**

## 8. The pass

A box proves itself to its server, on every call it makes as itself, with a pass it signs for itself. The server issues nothing for it and stores nothing.

The pass is four lines, signed by the working key under its certificate, in the namespace `irongall-pass-v1:<A>`:

```
irongall-pass-v1
<A>
<server name>
<not_after>
```

- **The server name** is the host of the box's URL for its server, written as an origin is (RFC 6454 §6.2): lowercase, with no user information, and with its port only when the port is not the scheme's default. `https://irongall.dev:443` and `https://irongall.dev` name `irongall.dev`; `http://127.0.0.1:8080` names `127.0.0.1:8080`. A server MUST write the `Host` of a request the same way, and drop a port of 443 or 80 alike, so that checking a pass never depends on the scheme a request came by.
- **A client writes it as** `Authorization: irongall-pass address="<A>", not_after="<not_after>", signature="<base64 of the armoured signature>"`, in exactly that form, on one `Authorization` line. A request with two `Authorization` lines carries no pass.
- **A server reads it as RFC 9110 §11 lets a recipient read credentials:** the scheme in any ASCII case, then one space or more; the three parameters in any order, each name in any ASCII case and given once, and no other parameter; optional whitespace around each comma and each `=`, and empty list elements skipped (RFC 9110 §5.6.1.2); each value a token or a quoted-string, and a quoted-string holding a backslash refused. Each value is then held to its form: the address, a time, and the base64 of the signature. The signature is verified over the statement built from those values, never over the header's text. A server MUST refuse a value longer than the form a client writes with a signature of the largest bound any identity key type has (Section 3.2), whitespace included, `401 unauthorized`, before it hashes, parses or verifies it.
- **Lifetime.** A client signs a pass to end 10 minutes after it signs it. A server takes a pass that has not ended and ends at most an hour after its own clock reads.
- **A client keeps its pass for every call until it is about to end.** A client MUST NOT use a kept pass with more than 10 minutes left: its clock has gone back since it signed it. A server MAY remember a pass it has verified, by one written form of it: every form a verifier reads as the same pass is one (Section 3.2).
- **Which certificate.** A server takes a pass only under the box's current certificate, and only for a name that is its own, with one exception: a registration (Section 11.7) and a renewal (Section 11.9) carry a pass under the certificate of the statement they bring.
- **Refusals,** each `401`: `certificate_revoked`, where the call takes a pass under the box's current certificate and the identity has revoked that certificate, or brings a statement under a certificate the identity revoked (Section 11.4, rule 1); otherwise `pass_expired`, if at the server's clock the pass has ended or ends more than an hour ahead, or its certificate has not begun or has ended; `certificate_not_current`, if the pass is under any certificate other than the one the call takes a pass under, revoked or not, or the one on record does not verify, with `certificate_serial` naming the certificate the call takes a pass under (the box's current one, or the statement's a registration or a renewal brings), or the one a new statement must be above; `unauthorized`, if there is no pass, or it is not this box's, or not for this server, or does not verify.
- **A client that is refused a pass signs another and tries once more, and MUST NOT try more than once,** nor at all after a `certificate_revoked` that its own read of its box shows to be final (Section 12.5). A pass refused twice for its time is the clock (Section 12.1).
- **The read of a box (Section 11.8), the link page (Section 4.3) and the two revocation calls (Section 11.15) take no pass,** and a server reads none on them, whatever `Authorization` they carry.

## 9. Messages

### 9.1. The envelope

The envelope is one line of compact JSON, its LF included, and is what the sender signs. The server never sees it.

| Member | | |
|---|---|---|
| `v` | required | the integer `1` |
| `from` | required | the sender's address |
| `to` | required | the recipient's address |
| `sent_at` | required | a time: when this copy was posted (Section 12.2) |
| `msg_id` | required | a UUID as RFC 9562 §4 writes one (hex, hyphens between its 4, 2, 2, 2 and 6 octets), lowercase, of any version. A client makes a random one (version 4) once for each message and keeps it on every copy |
| `identity` | required | the sender's identity document, base64. `from` is its hash |
| `body` | required | the message: any JSON value, carried as that value. Its null is a value |
| `subject` | optional | a string |
| `in_reply_to` | optional | a string: the `msg_id` replied to |
| `supersedes` | optional | a string: a `msg_id` of the same sender that this message replaces. Stored mail is never altered; the recipient decides |

- **An empty string in `subject`, `in_reply_to` or `supersedes` is the member left out,** and a writer leaves such a member out.
- **A sender MUST refuse an `in_reply_to` or `supersedes` that is not a `msg_id`.** A reader checks only that each is a string.
- **The line is compact UTF-8 JSON** with no line feed of its own. A sender writes it without escaping `<`, `>`, `&` or non-ASCII characters.
- **A sender MUST hold the envelope to the rules its reader holds it to** (Section 3.3, and Section 12.3, check 3; the body nested at most 31 deep, so the envelope at most 32), and MUST refuse one that breaks a rule whole, never repairing it, before the outbox keeps it. One that keeps them is written compact, its members in the order given and its strings and numbers the values given.
- **A reader takes any JSON text on the line that Section 3.3 takes,** whatever spelling the sender's encoder chose, and MUST read the members from the line exactly as it decrypted it.
- **`v` changes only for a breaking change,** and a reader MUST refuse a `v` it does not know.

### 9.2. The signed plaintext

The sender signs the envelope's line with its working key, in the namespace `irongall-msg-v1:<recipient>`:

    ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f work-cert.pub < P > P.sig

What is encrypted is, in order:

```
{"v":1,"from":"…","to":"…","sent_at":"…","msg_id":"…","identity":"…","body":"…"}
-----BEGIN SSH SIGNATURE-----
U1NIU0lH…
-----END SSH SIGNATURE-----
................
```

1. **Line 1 is the envelope,** and its bytes, LF included, are what is signed.
2. **Then the signature,** as `ssh-keygen` writes it, through its END line.
3. **Then padding,** to the end (Section 9.3).

A reader MUST take the parts apart so:

1. **The signature is verified over line 1 exactly as decrypted,** and the envelope's members are read from those same bytes, never from anything rebuilt.
2. **Each part has one place, and nothing is searched for.** Line 2 MUST be the signature's BEGIN line, ending in LF. The block ends at the first END line, which MUST be followed by LF; any other byte there, or none, refuses the message, and no later END line is looked for. What follows is never parsed and never shown.
3. **One signature, one identity:** it is verified against the identity the envelope carries, and the verdict is the verification's result alone.

The namespace binds the signature to its recipient: a message signed for one box does not verify in another's namespace.

### 9.3. Padding

Every message is padded so that its ciphertext is a whole number of blocks.

- **A block** is the smallest power of two that is at least 1/16 of the ciphertext's size, and at least 1 KiB.
- **The padding is `.` bytes after the signature's END line, to the end,** as many as make the ciphertext the next whole number of blocks, and none for one already on a block. It is not signed.
- **For example,** a ciphertext of 40,000 bytes has a block of 4 KiB and is padded to 40,960; one of 70,000 has a block of 8 KiB and is padded to 73,728.
- **The ciphertext is what is measured.** An age file (C2SP age's format) of one native stanza and no other, of a plaintext of L bytes, is H + 16 + L + 16 × max(1, ⌈L / 65,536⌉) bytes: the header, H, 168 bytes for an `X25519` stanza and 1,627 for `mlkem768x25519`; the payload's nonce; the plaintext; and a tag for each 64 KiB chunk. A sender computes the padding from that before encrypting, and MUST refuse to send a file that is not the size it computed.
- **Padding is made at the seal,** for the prekey sealed to: a message sealed again to a prekey of another type is padded again.
- **A server does not check padding.** A size limit a server sets MUST be a whole number of its own blocks, as every power of two is, so that a message fits a limit padded exactly when it fits it bare.

### 9.4. Encryption

The signed plaintext and its padding are encrypted to the recipient's prekey with age (C2SP age), in the binary format, not armoured: `{ cat P P.sig; padding; } | age -r <recipient> > m.age`. A file for a post-quantum prekey has one `mlkem768x25519` stanza; for an X25519 prekey, one `X25519` stanza. A sender adds no other native stanza.

## 10. Revocation

### 10.1. Revocation of an address

A box's identity can end its address for good, and nothing else can.

- **The statement is fixed text:** `irongall-revoke-v1`, LF, the address, LF. It has no date, no reason and no number: a verifier builds it from the address, and a copy signed at any time is the same statement.
- **It is signed by the identity key,** in the namespace `irongall-revoke-v1:<A>`, with the bare identity as the signing key. A working key's signature over the same statement, under a certificate of that identity, is not a revocation: a verifier's `allowed_signers` line names the identity's key with no `cert-authority`.
- **It reaches back, and nothing undoes it.** Once a verifier has verified a revocation, it takes nothing signed for that address, whenever it was signed, sends it nothing, and keeps the revocation for good. No later answer and no later record undoes it.

### 10.2. Revocation of certificates

The identity revokes every certificate it made up to and including a serial, and keeps its address.

- **The statement is three lines:** `irongall-revoke-certs-v1`, the address, a serial.
- **It is signed by the identity key,** in the namespace `irongall-revoke-certs-v1:<A>`. A working key's signature is refused.
- **It revokes every certificate of the address whose serial is at or below its own, and the highest one verified stands.** A verifier keeps the highest it has verified. One through a lower serial changes nothing, whenever it arrives. There is no way to revoke fewer.
- **What a revoked certificate loses, at a verifier that holds the revocation:** a reader refuses mail signed under it, whenever it was signed (`certificate_revoked`); a sender refuses a prekey statement under it; a server takes no pass and no statement under it, and answers a send to a box whose current statement is under it `409 prekey_expired`. A box MUST NOT sign mail under a certificate it holds revoked. The address goes on.
- **A box MUST NOT make a certificate its identity has revoked:** its next certificate is numbered above the highest serial it holds revoked or its server shows it (Section 5). One through 2^53 − 1 leaves no certificate to make.
- **How long one is kept is not fixed here.** Every certificate it covers ends within 64 days and an hour of being made.

### 10.3. The revocation record

A record carries what an identity revoked, and proves itself: anyone holding the address checks it with nothing else.

```json
{"type":"revocation_record","identity":"<base64 of D>","revocation_signature":"<base64>","revoked_certificates":"<base64>","revoked_certificates_signature":"<base64>"}
```

- **`type`** is `"revocation_record"`. Every writer writes it, a server in its answers (`api/openapi.yaml` requires it there) and a client in what it sends, keeps and prints. A reader takes a record without it, and MUST refuse one that names another type (a server with `400 bad_request`, `member` `type`).
- **`identity`** is the identity document, which MUST hash to the address and pass its key checks (Section 4.1).
- **`revocation_signature`**, if present, is the revocation of the address (Section 10.1), its armoured signature in base64.
- **`revoked_certificates`** with **`revoked_certificates_signature`**, if present, is the revocation of certificates (Section 10.2): its statement's three lines, and the armoured signature over them, each in base64. The statement MUST be exactly that form, its line 2 the address.
- **The members are in any order.** A record carries at least one of the two revocations.
- **A record is worth the same from a server or from a file.** A verifier rebuilds the revocation of the address from the address, holds the revocation of certificates to its form, and verifies each signature under the document's key.

## 11. The HTTP API

The shapes of every operation below are `api/openapi.yaml`'s. This section says what each means and what a server checks.

### 11.1. Transport

- **A client MUST call its server over `https`,** except a server on its own machine named by an address in `127.0.0.0/8` or by `[::1]`, which it MAY call over `http`. The name `localhost` is not such an address. A client MUST refuse a URL of any other form before sending anything, and MUST send a call to a loopback address, or to `localhost`, through no proxy.
- **A client MUST NOT follow a redirect.** The API redirects nowhere, so a `3xx` other than `304` is no answer. A pass and a read of a box name an address, and neither is sent anywhere a server points.
- **Every API path is under `/v1/`.**

### 11.2. Requests and answers

- **Bodies.** A JSON body is read as Section 3.3 reads one. A send's body is bytes (Section 11.10).
- **Query parameters** are read as members are: a server MUST refuse a parameter its call does not take, or one given twice, `400 bad_request`, naming it in `member`. A send takes its two serials (Section 11.10) and a list its `cursor` (Section 11.11); no other call takes one.
- **`Date`.** Every answer under `/v1/` carries `Date`, by the clock the server's checks read.
- **No caching.** Every answer under `/v1/` carries `Cache-Control: no-store`.
- **Compression.** The read of a box (Section 11.8) MAY be answered with gzip (RFC 9110 §8.4.1.3), and only to a request whose `Accept-Encoding` takes it. A server MUST NOT compress any other answer: a list sets values senders chose beside the box's own (BREACH, RFC 7457 §2.6).
- **`HEAD`** is answered on every route that answers `GET`, as that `GET` without content (RFC 9110 §9.3.2): the same status and header fields, its preconditions evaluated as the `GET`'s. A list's `HEAD` is a poll whatever its cursor, and neither spends the cursor nor hands out another. A message's `HEAD` is no fetch: it reads only whether the box holds the message, spends nothing of new mail and marks nothing (Section 11.12), is one of the box's calls, carries no `Content-Length`, and ignores a `Range`.
- **Preconditions.** Every call evaluates `If-Match` and `If-None-Match` as RFC 9110 §13.1.1 and §13.1.2 have an origin server evaluate them, where Section 11.4 places them. The target is what the path names. Only a list's first page (Section 11.11) and an ACL (Section 11.14) carry an `ETag`. A target that carries none matches no listed tag: where the target exists, `If-Match: *` is true and `If-None-Match: *` false; where it does not, `If-Match` is false whatever it lists, and `If-None-Match: *` true; a list of tags is false in `If-Match` and true in `If-None-Match` either way. `*` is read as `*` only as the whole value; otherwise the value is a list of entity-tags, each read through its closing quote, and a value of any other form, `*` among tags included, matches nothing. `If-Match` compares strongly and `If-None-Match` weakly. A false `If-Match` is `412 precondition_failed`; a false `If-None-Match` is `304` to a `GET` or a `HEAD`, and `412` to any other method. A write that carries `If-Match` or `If-None-Match: *` (a registration, a renewal, a revocation, an ACL, an adopt, a leave) writes only while they still hold, and is otherwise `409 box_changed`, with nothing changed; a registration that meets a box registered meanwhile is answered as one of a registered box is, and an ack that meets its message acked meanwhile `404 no_such_message`. The conditions on dates are not evaluated, and no answer carries `Last-Modified`. `If-Range` is read only beside a fetch's `Range`, and is false (Section 11.12).
- **An unknown route** is answered with the router's plain `404` or `405`, with no code, or, past a limit, `429 rate_limited` as any call is. A client reads a plain `404` or `405` as a route that server does not offer, and a `404` with a code as that code.
- **A body that does not arrive in time** is `408 request_timeout`. **A server that cannot complete a request,** or is not ready to answer, says so, `503 unavailable` with `Retry-After`, rather than answer wrong. A client takes any other `5xx` as the same failure, with no wait given.

### 11.3. Errors

- **Every error body is RFC 9457 Problem Details** (`application/problem+json`), in AEP-193's form: `type`, `title`, `status`, `detail`, `code`, `hint`, and a member of its own for each value the error carries. Every value `detail` names is also one of those members.
- **`type`** is `tag:irongall.dev,2026-10-17:errors/<code>` (RFC 4151), the same at every server. It resolves to nothing.
- **A `code` is one of the closed list `api/openapi.yaml` gives, under the status it gives, beside its own `type`.** A code a client does not know, or one under another status, or beside another `type`, is no code: a client takes no branch on it and shows none of it, only the status. A member that breaks its type makes the body no answer (Section 3.3).
- **A client MUST NOT show `detail`, `hint`, `title`, or any other text a server sent** (a status line, a header or trailer line, a `Location`, a list's cursor in a path). They are a server's words, for a person reading the body. A client says what a code means in its own words, with the members it has checked to their types, and shows a string member only once it has checked it to a value it knows. A call with no answer the client can read is named by its method and path, never its query. A `hint` names a fix as a client command, never a shell line.
- **A client reads `code`, the members, `Retry-After` and `Date` on every answer that is not `2xx`.**
- **`401`** carries `WWW-Authenticate` with the scheme `irongall-pass` (Section 8).
- **`Retry-After`,** on a `429` and a `503`, and on every list answer (Section 11.11), is delay-seconds, digits alone. A client reads an HTTP-date there as no wait.
- **A code names what a client does about the error:** one call that can fail for causes a client meets differently has a code for each.

What each code means, and what a client does on it:

| Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request` | not a JSON text Section 3.3 takes; a member or query parameter missing, unknown, given twice, or holding a value its call does not take. `member` names it |
| 400 | `bad_address` | an address in the path that is not 64 lowercase hexadecimal characters |
| 400 | `bad_encoding` | a byte member that is not base64 in its one encoding |
| 400 | `identity_mismatch` | an identity document that does not hash to the address, or breaks its form (Section 4.1) |
| 400 | `unsupported_key_type` | an identity of a key type this protocol does not define, or this server does not register; `key_types` lists what it registers |
| 400 | `bad_key` | an identity key that fails its type's key checks; a malformed or badly signed prekey statement or certificate |
| 400 | `prekey_not_new` | a prekey equal to the current one or a retired one the server keeps (Section 11.9) |
| 400 | `prekey_time` | at the server's clock, a certificate that began less than 10 minutes before it or has ended, or a statement that has ended or ends more than 33 days and an hour ahead: nearly always the client's clock |
| 400 | `not_age` | a send's body that is not an age file |
| 400 | `wrong_recipient_type` | a send's age file without exactly one native stanza of the current prekey's type (Section 11.10, step 7) |
| 400 | `bad_revocation` | a revocation whose signature is not the identity's over its statement (Section 11.15) |
| 401 | `unauthorized`, `pass_expired`, `certificate_not_current`, `certificate_revoked` | the pass refused (Section 8). `certificate_serial` names the certificate on `certificate_not_current` |
| 403 | `unknown_sender` | the box a send's pass names is not registered |
| 403 | `sender_revoked` | the sending box is revoked |
| 403 | `sender_not_allowed` | the recipient's ACL does not admit the sender (Section 11.14): final for the message |
| 403 | `sender_key_type` | the recipient's client does not verify the sender's identity key type (Section 7); `key_type` names it |
| 403 | `adopt_key_refused` | an adopt key this server did not make, or that is spent, expired or revoked (Section 11.16) |
| 404 | `no_such_mailbox` | the box was never registered, or is forgotten |
| 404 | `no_such_message` | the message was acked or has expired: it is gone |
| 404 | `not_revoked` | the server holds no revocation of the address (Section 11.15) |
| 408 | `request_timeout` | the body did not arrive in time: send it again |
| 409 | `conflict` | what is held is newer, or other: a registration that is not an identical retry; a renewal under the current certificate at a prekey serial not higher (`prekey_serial` names the serial it must pass); a revocation of certificates through a serial lower than the one held (`through` names the one held); a send whose id another sender holds |
| 409 | `box_changed` | the box changed while the request was handled, or a condition it carried no longer held at its write: send it again as it is |
| 409 | `stale_prekey` | a newer prekey exists: read the box again and seal the same envelope (`prekey_serial`, `certificate_serial` name the current one) |
| 409 | `prekey_expired` | the recipient's prekey has ended, or is under a revoked certificate: its owner must renew |
| 410 | `revoked` | the address is revoked, for good; `record` carries the server's record of it (Section 10.3), which a client checks (Section 12.5) |
| 412 | `precondition_failed` | a precondition was false (Section 11.2) |
| 413 | `too_large` | a body or ciphertext over its cap, or an ACL with more entries than the server takes; `limit` gives the cap |
| 429 | `rate_limited` | past a limit (Section 11.5); `subject`, `quota_id`, and for a number a day `limit` |
| 429 | `fetch_paced`, `refetch_spent` | the box's fetches are paced (Section 11.12) |
| 429 | `pair_full` | the sender's unacked mail at this box is at its cap; `unacked`, `oldest_expires_at` |
| 429 | `mailbox_full` | the box holds as much mail as it may; `count`, how many it holds, as its list counts them |
| 429 | `mailbox_busy` | the box has taken as much new mail as it takes for now |
| 503 | `unavailable` | the server is not ready to answer |

Every `429` carries `Retry-After`.

### 11.4. The order of refusals

Which refusal a server answers first is its own, but for three rules. Otherwise, where a request fails several checks, a server answers the one it finds first, and a client acts on whichever comes; the steps of Sections 11.7 and 11.10 are numbered to be cited, not to order them.

1. **A box's state comes before any pass.** A call answers the state of the box whose pass it carries, and a read of a box the state of the box it reads, before any pass is judged: a call with a box's own pass, `404 no_such_mailbox` for a box unknown, `410 revoked`, and `401 certificate_revoked` where it takes a pass under the box's current certificate and the identity has revoked that certificate; a send, of its sender, `403 unknown_sender`, `403 sender_revoked` and `401 certificate_revoked`; the read of a box, `404 no_such_mailbox` or `410 revoked` with its record; the read of revocations, `404 not_revoked` or `200` with the record. So a box learns its own state whatever pass it carries.
2. **What could change nothing is answered from what is kept.** A registration of a box the server holds is answered from its record (Section 11.7, step 5), and an identical retry of it, or of a renewal, is `200 {}`; a revocation of an address the server holds revoked, or of certificates through a serial no higher than the one held, is answered from what is held (Section 11.15); a send's retry gets its first receipt, whatever has changed at its recipient since (Section 11.10, step 6). None of them is refused by a count of what it would make new. The budgets that bound any call may still defer one with a `429`: the address's `requests` and `misses`, and the box's `calls`.
3. **Preconditions are evaluated once the call knows its target's state** (by its route, its method, its pass where it takes one, and the read of its target) **and before it acts** (RFC 9110 §13.2.1, §13.2.2). What is refused before that point is answered as without them. After it, a false one is a call that does nothing but count: a list's is a poll, a fetch's or an ack's one of the box's calls, and it takes no cursor and no new mail, marks nothing fetched and writes nothing. A send evaluates them before its dedupe (Section 11.10, step 6).

### 11.5. Limits

What a server limits, and by how much, is its own: no limit's value is part of the protocol, and a server may add limits. A client meets a limit as a `429` with `Retry-After`, which it waits out and then retries, unless the code says otherwise. Every server keeps these promises:

- **A drain of a full box always completes:** its list pages are never refused, and its fetches may be paced, each `429 fetch_paced` saying when to go on, never stopped for good.
- **A box's counts are spent only** by calls that carried its pass, by mail sent to it, and by its identity's raises of the revocation of certificates. An address's counts are spent only by calls from it.
- **The identity's acts are counted apart from what a working key can spend:** a renewal under a later certificate apart from one under the current certificate, and one made while the current certificate is revoked not at all (Section 11.9); a raise of the revocation of certificates on a count of its own; the revocation of an address against no box (Section 11.15). So a holder of a taken working key cannot keep the identity from revoking that key's certificate.

**Who a call is counted against.** A call with a box's pass is counted against that box. A call with none is counted against the IPv4 address or the IPv6 /64 it comes from; a server MAY also count by a wider range. The read of a box is counted against its address whatever it carries. A check that fails, or a call that names no box, is counted against its address. No caller is exempt.

**How a refusal names its limit.** A limit without a code of its own (`fetch_paced`, `refetch_spent`, `mailbox_busy`, `pair_full`, `mailbox_full`) is `429 rate_limited`, with whom it was counted against in `subject` (`box`, or `ip`) and which limit in `quota_id`. Where one call would spend several limits, `Retry-After` is the time when every limit the server can read without doing the call's work lets the same call through (RFC 8555 §6.6), and the name is that limit's; a limit behind that work, a read of storage or a signature check, can still refuse the call once that wait is over. A send's number a day is behind its dedupe, so a send past its calls is told the calls' wait. **A number a day** is a budget of that many, refilled one at a time, evenly over the day, for each box: `limit` gives the number.

| `quota_id` | `subject` | Counts |
|---|---|---|
| `polls` | `box` | its polls: each list without a cursor, a `304` and a `412` among them, and each list with a cursor that is not a continuation (Section 11.11) |
| `pages` | `box` | its continuations, sized so that a full box always drains |
| `calls` | `box` | its other calls with its pass, a send, a renewal and an identical retry of its registration among them |
| `sends` | `box` | its sends, a number a day, counted only for sends that carried its pass |
| `renewals` | `box` | its renewals under its current certificate, a number a day |
| `certificates` | `box` | its renewals under a later certificate, a number a day, but for one made while its current certificate is revoked |
| `certificate_revocations` | `box` | its identity's raises of the revocation of certificates, a number a day |
| `registrations` | `ip` | registrations from an IPv4 address or IPv6 /64, and what a server counts as one (Section 11.15) |
| `registrations_range` | `ip` | the same, from an IPv6 /48 |
| `misses` | `ip` | calls that named no box, or carried nothing that verified |
| `sends_before_pass` | `ip` | sends, counted before their pass is read |
| `requests` | `ip` | every request but one that carries a pass the server has already verified, on a call that takes it: registrations, renewals and requests no route matches among them |

A server's limit outside these names none in `quota_id`.

### 11.6. Box states

Every call names a box, and this is what each does in each state.

| State | Register `PUT /v1/<A>` | Renew `PUT /v1/<A>/prekey` | A call with the box's pass | Revoke `PUT /v1/<A>/revocations` |
|---|---|---|---|---|
| **unknown** (never registered, or forgotten) | → `active`, `201` | `404 no_such_mailbox` | `404 no_such_mailbox` | kept: of the address → `revoked`, `201`; of certificates, `200`, and the address stays unknown |
| **active** | an identical retry, `200`; otherwise `409 conflict` | `200`, stays `active` | served | of the address → `revoked`, `201`, its mail deleted; of certificates, `200` |
| **revoked** | `410 revoked` | `410 revoked` | `410 revoked` | `410 revoked`, answered from the record |

- **A send answers its sender's state** as `403 unknown_sender` or `403 sender_revoked` (Section 11.10, step 1), and its recipient's as this table does.
- **There is no delete of a box.** A box leaves a server for good by its identity's revocation, pauses with its ACL (Section 11.14), and is forgotten once it stops renewing.
- **There is no pending state:** a registration carries a pass minutes old, so a box is active from its first call.
- **A box is forgotten once nothing valid for it is left** (Section 13): it has stopped renewing, its certificate has ended and its last prekey's mail has expired. It is then unknown, and registers anew, its ACL and its account gone. What its identity revoked is kept.
- **A replay** of a request that took effect, byte for byte, gets `200` and the same result; a conflicting one gets `409 conflict`.

### 11.7. Register

`PUT /v1/<A>` with `identity`, `prekey` and `prekey_signature` (the exact bytes of each, base64) and `sender_key_types` if the box declares any, carrying a pass under the certificate of that prekey statement. The box is in use at once.

The server checks:

1. The address in the path is 64 lowercase hexadecimal characters → otherwise `bad_address`.
2. The body has exactly those members → otherwise `bad_request`, naming the member.
3. `identity` hashes to the address and has the form of an identity document (Section 4.1) → otherwise `identity_mismatch`.
4. **The key's type and the key.** A type this protocol does not define → `unsupported_key_type`. The key in its one encoding → otherwise `identity_mismatch`. The type's key checks → otherwise `bad_key`. A server registers `ssh-ed25519` and whichever other defined types its operator chooses, and answers the rest `unsupported_key_type`, naming its list.
5. **A registration never changes a registered box.** One the server holds is answered from its record: an active box, and the request byte-identical to its current identity, prekey statement and signature → `200 {}` once its pass (step 7) is verified under the box's current certificate, or `401 certificate_revoked` if the identity has revoked that certificate; anything else → `409 conflict`. A revoked address → `410 revoked` with its record, box or none. Any other registration is counted against its address (Section 11.5, `registrations`).
6. **The prekey statement and its signature:** the statement's form (Section 6); line 2 is the address; a valid age recipient on line 4, of small order neither in its X25519 point nor in a post-quantum key's X25519 half; the signing key a certificate of that identity in every rule of Section 5; the namespace `irongall-prekey-v1:<A>`; the statement's `not_after` after now and at most 33 days and an hour after now; the statement not outliving its certificate → otherwise `bad_key`, or `prekey_time` where what fails is the certificate's time or the statement's `not_after`, a certificate that began less than 10 minutes before the server's clock among them. A certificate the identity revoked, by what the server keeps of the address → `401 certificate_revoked`.
7. **The pass** (Section 8): this box's, for this server, not ended, under the certificate of step 6 → otherwise a `401`. The certificate shows the identity chose this working key, and a pass minutes old shows its holder is present: nobody can register an identity they do not hold, and a statement that leaked cannot be registered by whoever found it.
8. **A new box** is stored `active` → `201 {}`. A box registered meanwhile by another request is answered as step 5 answers.
9. **The server keeps the statement's certificate and its serial.** It takes a pass only under that certificate, and a later statement only under it or under a certificate of a higher serial.

### 11.8. Read a box

`GET /v1/<A>`, with no pass: everything a sender needs before it posts, and everything a box knows of itself at its server.

- **An active box** → `200` with `identity`, `prekey` and `prekey_signature`, `sender_key_types` if the box declared any, and `revoked_certificates` with `revoked_certificates_signature` if the server holds a revocation of its certificates.
- **An unknown address** → `404 no_such_mailbox`, whatever its identity has revoked of its certificates (the read of revocations serves that: Section 11.15).
- **A revoked address** → `410 revoked`, with the record in `record`.
- **The read takes no pass.** It is public: a server counts it against the address it comes from, whatever `Authorization` it carries, and reads no pass on it. A client sends none on it.

### 11.9. Renew the prekey

`PUT /v1/<A>/prekey` with `prekey` and `prekey_signature`, and `sender_key_types` if the box declares any, carrying a pass under the certificate that statement is signed under. Its authority is a statement later than the current one, signed by a working key the identity certified: no pass under the box's current certificate is needed, so a box that lost its working key comes back by a renewal under a new certificate, and a box moves to a new certificate this way.

- **An identical retry** is answered from the record: `200 {}` once its pass is verified, or `401 certificate_revoked` while the box's current certificate is revoked.
- **Any other statement** is verified as at registration (Section 11.7, steps 6 and 7) and MUST be later than the current one (Section 5): under a certificate of a higher serial, at any prekey serial, or under the current certificate at a higher prekey serial. Under the current certificate at a prekey serial not higher → `409 conflict`, `prekey_serial` naming the serial it must pass. Under a certificate of a lower serial, or another certificate of the current serial → `401 certificate_not_current`, `certificate_serial` naming the one it must be above. Under a certificate the identity revoked → `401 certificate_revoked`.
- **A key equal to the current one, or to a retired one the server keeps,** → `400 prekey_not_new`. A server keeps the newest of a box's retired prekeys (how many is its own), each until its statement's `not_after`, only for this check.
- **On success** the new prekey becomes current and its certificate the box's current one, so no pass under an earlier certificate is taken again; its declaration (Section 7) is the box's from then on; the answer is `200 {}`.
- **Counting** (Section 11.5): a renewal under the current certificate spends `renewals`, one under a later certificate `certificates`, and one while the current certificate is revoked neither, nor any of the box's calls. Past either, `429 rate_limited` naming it. An identical retry spends neither.
- **A box the server has forgotten** → `404 no_such_mailbox` (Section 12.4).

### 11.10. Send

`POST /v1/<B>/messages?prekey_serial=<serial>&certificate_serial=<serial>`, its body the age file's exact bytes (`Content-Type: application/octet-stream`), carrying the sender's pass → `201` with `id`, `received_at` and `expires_at`, and `Location: /v1/<B>/messages/<id>`. The sender is the box the pass names. The two serials name the prekey the file is sealed to, its own and its certificate's; both are REQUIRED.

- **A server reads the body as bytes, whatever its `Content-Type` says.**
- **A ciphertext is at most 16 MiB (16,777,216 bytes).** A server's caps on it, an account's among them, are at most that, and every reader takes a ciphertext of any size up to it, so mail one server takes, every reader reads. A larger one is a new version of the protocol.
- **The server checks no signature on a message:** there is none for it to see. What it holds a sender to is the pass.

The server checks, and only step 9 stores anything. Every count is taken before the work it guards and given back if that work does not happen.

1. **Who is sending: the pass** (Section 8), read for the box it names. Before it, the address's `sends_before_pass`. The box it names unknown → `403 unknown_sender`; revoked → `403 sender_revoked`. Then the pass's own refusals, and the sender's `calls` (Section 11.5), which every send spends, a retry included.
2. **The path and the query.** `<B>` is an address → otherwise `bad_address`. `prekey_serial` and `certificate_serial` are each given once, each a serial, and no other parameter is → otherwise `bad_request`, naming the parameter.
3. **The body's size:** at most the sender's cap → otherwise `413 too_large` with the cap in `limit`, from the `Content-Length` before anything is read, or as it reads.
4. **It is an age file** → otherwise `not_age`, an empty body included.
5. **`B` is active:** unknown → `404 no_such_mailbox`; revoked → `410 revoked`.
6. **Dedupe:** the id is the ciphertext's SHA-256. If `B` holds that id, acked or not: from the same sender, a retry → `200` with the original receipt, whatever has changed at `B` since; from another sender → `409 conflict`.
7. **`B` takes new mail, on this prekey, from this sender.** `B`'s current prekey past its `not_after`, or under a certificate `B`'s identity has revoked → `409 prekey_expired`. A sender whose identity is not `ssh-ed25519`, to a `B` that declared neither that type nor `any` (Section 7) → `403 sender_key_type`. The two serials not those of `B`'s current statement → `409 stale_prekey`. **Exactly one native stanza** (`X25519` or `mlkem768x25519`) of the current prekey's type; a stanza whose type matches `^[!-~]{1,8}-grease$` with at most 4 arguments is ignored, as age has a reader ignore a stanza it does not recognise, and its body is bounded by nothing but the message cap → otherwise `wrong_recipient_type`. Which key the file is sealed to cannot be checked.
8. **Quotas, counted only for sends that carried their sender's pass.** `B`'s ACL does not admit the sender → `403 sender_not_allowed`, one code and one wording whether the sender is denied or only not allowed. The sender's `sends` → `429 rate_limited`. Its unacked mail at `B` at the pair's cap → `429 pair_full`. `B`'s mail at its cap → `429 mailbox_full`. The new mail `B` takes, from every sender together, past its budget → `429 mailbox_busy`; a retry spends none. `pair_full` and `mailbox_full` carry a `Retry-After` of the poll interval, and `mailbox_busy` the time until `B` takes another.
9. **Store it** (Section 13) → `201`. A concurrent send of the same ciphertext that got there first is answered as step 6 does. Any other failure is `503 unavailable`, and the sender posts the message again from its outbox.

### 11.11. List

`GET /v1/<B>/messages`, with the box's pass → `200` with `count`, `messages` and `next_cursor`, and `Retry-After`.

- **`count`** is every live message in the box; **`messages`** is one page of up to 50 entries, oldest first by `received_at`, each its `id`, `from` (the box whose pass its send carried, on the server's word), `size` (its ciphertext's length, at most 16 MiB), `received_at` and `expires_at`; **`next_cursor`** is null after the last page. An empty box is `{"count":0,"messages":[],"next_cursor":null}`.
- **A cursor is opaque** and is one or more of `A`–`Z`, `a`–`z`, `0`–`9`, `-` and `_` (AEP-158). The next list carries it as `?cursor=` as it is.
- **`Retry-After` on every list answer, a `304` included, is the server's poll interval,** in seconds.
- **A first page carries an `ETag`,** a strong validator of the page's body, which changes with any message that enters or leaves the page or the count. A page after the first carries none.
- **`If-None-Match`** that matches the first page's tag is `304`, with its `ETag`, its `Retry-After` and no body. A list with a cursor is `304` only to `If-None-Match: *`. **`If-Match`** that is false is `412 precondition_failed`.
- **Every poll is counted** (`polls`), a `304` and a `412` included: a box that polls faster than its budget is refused `429`, never answered `304`.
- **A list with a cursor is a continuation** only if it is a `GET` whose preconditions hold, the box holds mail after the cursor, and the cursor is the `next_cursor` the server handed the box last. A continuation spends `pages`. Only a `GET`'s `200` spends the cursor it carries and hands out the next; a false precondition, a refusal or a `HEAD` leaves the box holding the cursor it was handed. Any other cursor the server can read is answered all the same and counted as a poll, and with nothing after it the page is empty.
- **The server checks:** `<B>` an address → otherwise `400 bad_address`; the one parameter `cursor`, once, of the form above and one the server can read as a cursor it makes → otherwise `400 bad_request`, naming it.
- **There is no long poll.**
- **Lists are eventually consistent:** a list may show a just-acked message, or miss a just-stored one, for a moment.

### 11.12. Fetch

`GET /v1/<B>/messages/<id>`, with the box's pass → `200`, `application/octet-stream`, the ciphertext's exact bytes with a `Content-Length`, and nothing else. A message that is gone → `404 no_such_message`.

- **Ranges.** `Range: bytes=N-`, one open-ended range whose N is below the ciphertext's length, is answered `206 Partial Content` with the bytes from N to the end and `Content-Range: bytes N-<last>/<length>`, each number in digits with no leading zero. The unit `bytes` is read in any ASCII case. Any other `Range` (several ranges, a closed one, a suffix, N at or past the length, another unit), or one beside an `If-Range`, gets the whole body, `200`. No answer is `416`.
- **A fetch carries no validator.** A message's id is its ciphertext's SHA-256, so the bytes under an id never change.
- **Counting.** A message's first fetch spends the box's budget of new mail taken out; past it, `429 fetch_paced`. A fetch of a message the box has fetched before spends an allowance the size of its poll budget, the box's alone and apart from its polls; past it, `429 refetch_spent`. Each carries `Retry-After`. A ranged fetch is counted as any fetch is.
- **Bodies are served by the API itself, never by a redirect.**

### 11.13. Ack

`DELETE /v1/<B>/messages/<id>`, with the box's pass → `204`. It deletes the stored ciphertext and takes the message out of the list. The server keeps a dedupe record of it until its `expires_at` (Section 13). A message that is gone → `404 no_such_message`. Reading does not delete.

### 11.14. ACL

A box's ACL is whom its server takes the box's mail from.

- **Semantics.** A box with no ACL takes mail from everyone. With one, `deny` is checked first, then `allow`, and a sender matched by neither is refused, `403 sender_not_allowed`.
- **`PUT /v1/<B>/acl`,** with the pass, replaces it whole with `allow` and `deny`. Each entry is an address, or `*`, which matches every address; there is no other pattern, and repeats are taken once. `allow` is REQUIRED (`["*"]` is everyone and `[]` nobody): a document without it is `400 bad_request`. `deny` may be left out, for none. More entries, in both lists together, than the server takes is `413 too_large`. The answer is `200` with the ACL as held, `*` first and then each address once in ascending order, and no `ETag`.
- **`GET /v1/<B>/acl`,** with the pass, answers the ACL as held, in that order, with its `ETag`, a strong validator that changes whenever the lists change. A box with none answers `{"allow":["*"],"deny":[]}`, and has a tag too. There is no `DELETE`.
- **A `PUT` MAY carry `If-Match`,** so that it replaces only the ACL its writer read: compared strongly with the tag of the ACL held now, a box with none included. `If-None-Match: *`, or one naming the ACL's tag, is false, since a box always has an ACL. A `PUT` without a precondition replaces whatever is held.
- **What it denies is deleted:** the box's unacked mail from every sender the new `deny` matches is deleted with the change. A send that passed the check while the ACL changed may still be stored after it.
- **A box pauses with it:** `{"allow":[],"deny":["*"]}` refuses every sender and deletes the box's unacked mail.
- **It is not signed.** Only its box reads it, and only the server acts on it.

### 11.15. Revocations

Neither call takes a pass.

- **`PUT /v1/<A>/revocations`** with a record (Section 10.3). The server verifies it as a client does, and keeps what verifies for good, with a box at the address or none.
  - **A revocation of the address** → `201 {}`: a box at the address is revoked for good, and its mail and its record are deleted.
  - **A revocation of certificates** → `200 {}`, and so does one through the same serial again; one through a lower serial than the one held → `409 conflict`, `through` naming the one held.
  - **Both in one body:** a revocation of certificates no higher than the one held changes nothing, whether or not it verifies, and the address's revocation is kept once it verifies (`201`). Any other part that does not verify refuses the body whole, and nothing in it is kept.
  - **An address already revoked** → `410 revoked` with the record.
  - A document that does not hash to the address → `400 identity_mismatch`; a signature that does not verify → `400 bad_revocation`.
  - **A revocation of an address is counted against no box:** a server counts it against its caller's address, and MAY count one for an address it holds nothing of as a registration (`registrations`).
  - **A record for an address with no box binds a later registration:** `410 revoked` while the address is revoked, and no certificate the identity revoked is taken.
- **`GET /v1/<A>/revocations`** → `200` with the record the server holds of the address, with a box there or none, or `404 not_revoked`.

### 11.16. Accounts

A box may belong to one account at its server. The protocol fixes how a box joins and leaves one; what an account does is the server's own, within Section 11.5's promises. A server without accounts does not offer these routes.

- **`PUT /v1/<A>/account`,** with the pass, with `key`, an adopt key → `200` with `account`, the account's id. One use of the key is spent, unless the box is already in that account. A box in another account moves.
- **`DELETE /v1/<A>/account`,** with the pass → `204`, in an account or not. An account can drop a box from its side too.
- **Joining or leaving changes nothing about the box's mail.**
- **An adopt key** is `iga1_` followed by base64url without padding (RFC 4648 §5), at most 1,024 bytes in all. What it encodes is the server's own: a client holds a key to that form and reads nothing else of it, and MUST NOT take one as a command-line argument, where process lists and transcripts keep it. A key this server did not make, or that is spent, expired or revoked → `403 adopt_key_refused`.
- **An account id** is 1 to 32 of `a`–`z`, `0`–`9` and `-`.
- **An account's caps on a ciphertext** stay at most 16 MiB.

## 12. Clients

### 12.1. Keys and what a client keeps

- **A box's keys and state are in a directory only its owner can read** (0700), and never the working directory.
- **The identity key** is a plain OpenSSH private key file, with no passphrase and no seed derivation. It is backed up: losing it loses the address (Section 12.5).
- **A prekey MUST NOT be backed up, synced, derived from a seed, or kept where old versions survive** (a secrets manager, a version-control system, a snapshot): a prekey that survives its deletion voids the forward secrecy of Section 15.3. A working key is not backed up either: a restored box makes new ones.
- **What a client keeps, each by the rule of its section:** each peer's identity, pinned once something it signed has verified (Sections 12.2, 12.3); the highest certificate and prekey serials it has seen on each peer's statements (Section 6); every revocation it has verified, never removed (Section 12.5); its replay set and its floor (Section 12.3, check 9); when it signed each of its prekeys (Section 12.4); and its outbox, as written (Section 12.2).
- **A client MUST NOT adopt a server's `Date` as its clock, nor tell its owner to set the clock by it.** When a refusal is for a time, it reports the difference between the two, as the server's word, pointing its owner to a time source the owner trusts: a box checks everything against its own clock, and a clock set by a lying server would make an ended certificate valid again and stale mail fresh.
- **A key that reads mail decrypts the messages a client fetches (Section 12.3), and nothing else a server sends.**
- **One command of a box at a time.** A client MUST hold a box's lock for the whole of every command that writes the box, so a box has one consumer, and a command that finds it held waits.
- **One box, one place.** A box runs in one place at a time, where its working keys, prekeys and state are kept. A machine that is to run beside it is a box of its own, with its own identity and address; one restored from the identity alone takes the box's place (Section 12.4).

### 12.2. Sending

**Read the recipient's box before every post** (Section 11.8), of a new message and of one that waited, and check it before anything is sealed:

- **Identity:** the pinned one, or at first contact the served one; a pin always wins. The served identity MUST hash to the address and pass Section 4.1, as a server holds it at registration. One of a type the client does not verify is refused, and nothing is sealed. It is pinned only once its prekey statement has verified, and a later read never replaces it.
- **A verifier built on `ssh-keygen`** uses an `allowed_signers` file of exactly one line, `<address> cert-authority <key>`, built for each verification from the identity it has hash-checked, never from a server's text.
- **The prekey statement:** its signature, under a certificate of that identity that passes every rule of Section 5, and every rule of Section 6: its form and namespace, line 2 the recipient's address, its key, its `not_after` not passed and not after its certificate's end, and the statement not earlier than what the sender has seen. The serials are recorded only after every check passes.
- **Revocations:** what the read carries of a revocation of the recipient's address or certificates is kept once it verifies (Section 12.5). Nothing is posted to an address the sender holds a revocation of, and such an address is refused before any call; a statement under a revoked certificate is refused.
- **No answer is not "none held."** If the read fails, or serves no box (`404 no_such_mailbox`, or `410 revoked` with nothing that verifies), nothing is sealed or posted, and the message waits in the outbox. A failed read's code is no answer about the message.
- **What the read shows, or leaves out, is the server's word and is kept nowhere,** so the next post reads again.

**The outbox:**

- **A retry posts the same envelope, never a new message.** A new send makes a new `msg_id`, and a reader that acts on mail would act twice. The outbox keeps the envelope until a receipt arrives.
- **A seal is made for one post and never kept.** Each post, the first and every retry, reads the box as above, then dates the envelope (`sent_at` the sender's clock, every other member as it was), seals it to the statement the read passed, signed by the working key in use, and posts it. A message that waited thus goes to what the sender holds at its post.
- **A post is dated after the read, and never before its entry was written.** An entry dated ahead of the clock at its dating waits until the clock passes that time.
- **An entry is posted for 33 days from when it was written,** by the clock at each dating, and never after, so no copy of a message is dated more than 33 days after the first.
- **On `409 stale_prekey`, the sender posts the same envelope again** within the same send: the box read, the envelope dated and sealed anew, as above.
- **A refusal no later post of the message can pass is final:** `bad_address`, `too_large`, `conflict` and `sender_not_allowed` (only the recipient can change its ACL); the message is never posted again. **Any other refusal leaves it in the outbox,** posted again after `Retry-After` where the answer gives one.
- **A box MUST NOT sign mail under a certificate it holds revoked** (Section 10.2): the entry waits until its renewal is taken.
- **A `410 revoked`, to the read or to the send, is checked, never believed** (Section 12.5).
- **A post whose answer is lost costs a send.** The server stored it; the retry is a new ciphertext, which the server stores and counts as new mail, and the recipient delivers the message once (Section 12.3, check 10).

### 12.3. Receiving

A client drains every page of its list (Section 11.11). For each entry it fetches the message (Section 11.12) and reads at most the listed `size`: a body of another length breaks the answer's form, and the drain stops there, with nothing judged or acked and the message still on the server. A fetch that was cut resumes by range; the whole, the bytes kept and the range, is held to the listed `size` and to the id (check 9), as a body read whole is, and a `206` whose `Content-Range` is not the range asked for, or not of the listed size, breaks its form.

**The checks, in this order.** Only a message that passes all of them is accepted.

1. **Decryption** with every retained prekey (`undecryptable`). A reader MAY refuse as `undecryptable`, before any key agreement, a file without exactly one native stanza, which no server takes as a send (Section 11.10, step 7).
2. **The layout** (Section 9.2): the envelope line, then a signature block from line 2 to the first END line, followed by LF (`bad_message`).
3. **The envelope is one JSON object** as Section 3.3 reads one; its body is held to the same rules and passed on as it is (`bad_envelope`).
4. **The sender's identity document,** from the envelope's `identity`: base64, the form of Section 4.1, and a key that passes its checks (`bad_identity`). `from` MUST be its hash (`reattributed`). A well-formed document of a type the reader does not verify, whose hash is `from`, is refused as `unsupported_key_type`.
5. **The signature,** over line 1 exactly as decrypted, in the namespace `irongall-msg-v1:<this box>`, by a working key under a certificate of that identity that holds now (Section 5) (`bad_signature`).
6. **The rest of the envelope,** in this order: a body, and every member of its type (`from` and `to` addresses); `v` the integer 1; `to` this box (`reattributed`); `msg_id` in its form (each other failure `bad_envelope`); and `sent_at` no older than 33 days and not before the box's floor (both `stale`, check 9), and no more than an hour ahead of this box's clock (`future`).
7. **The listed `from` is the sender that verified** (`reattributed` otherwise).
8. **Revocation:** the box holds no revocation of the sender (Section 12.5). The reader asks by one read of the sender's box (Section 11.8), once for each sender in a drain, after that sender's signature has verified. A revocation that verifies refuses the message as `revoked`, and every later one from that address, whenever it was signed. A box served with no revocation, no such box, or `410 revoked` with nothing that verifies is an answer that none is held. Any other result is no answer: the drain stops, and the message stays on the server. The same read carries the sender's revocation of certificates: mail under a revoked certificate is refused as `certificate_revoked`.
9. **Replay:** the SHA-256 of the ciphertext, computed by the reader, is not in the replay set (`replay`). A listed `id` that differs from it is refused (`bad_id`). The set keeps each message's hash, with its `sent_at`, `from` and `msg_id`, until `sent_at` + 66 days and an hour. **A prune that drops a line first raises the box's floor to its cutoff,** the date of the pass it prunes by (Section 12.4) less 66 days and an hour, in the same write or before it; a prune that drops nothing leaves the floor, and a `sent_at` before the floor, or less than 33 days above it, is `stale` whatever the clock reads.
10. **Retry:** `(from, msg_id)` is not in the replay set. A match is a copy of a message already delivered: it is acked and not delivered again.

**Who a sender is is never asked of the server:** the message carries what proves it, and the sender's identity is pinned only once every check has passed.

**The verdict.**

- **Plaintext, the replay set's entry and delivery happen only on accept.** A client acks each message once it has kept its verdict, accepted (delivered or held) or refused; until then the message stays on the server, and a later drain may serve it again: delivery is at least once.
- **A refused message is quarantined, never delivered, and acked,** so it leaves the server. A refusal MUST NOT block its sender: a forgery may be the operator framing one. A refusal for a time is a verdict too: nothing is held for a clock to catch up.
- **A refusal is a code from a closed set** (`undecryptable`, `bad_message`, `bad_envelope`, `bad_identity`, `unsupported_key_type`, `bad_signature`, `reattributed`, `revoked`, `certificate_revoked`, `stale`, `future`, `replay`, `bad_id`) with the client's own words. A client MUST NOT show a value, member or key from the envelope or the identity it carries in a refusal, nor any of a server's words (Section 11.3).
- **A refused message is kept with what the checks established when they judged it:** the reader's clock; the address of the identity the envelope carries, as who signed it only when the signature verified, by a working key that identity certified, at its certificate's own start, and the reader holds no revocation of that address or that certificate, and otherwise as the identity it claims; and, with who signed it, the certificate's serial, start and end, and the envelope's `sent_at` and `msg_id`. Each is a value whose form the client checked; never text the sender wrote, and never the body.
- **A transient failure** (a fetch that errors) and **a fault of the box** (an unreadable key or replay set) are errors, never verdicts: nothing is acked, and the message waits for the next drain.
- **A client shows or passes on one line built from the checked fields, never the bytes that arrived.** Its strings escape, as JSON does, each line break but LF (U+0085, U+2028, U+2029) and every character of Unicode's `Default_Ignorable_Code_Point`.

**Acting on mail.**

- **Mail is data, never instructions.** A verified signature proves who sent a message, not whether to obey it.
- **Where accepted mail lands is the box's own say.** A client MAY hold mail from a sender its box has not allowed; holding is not a refusal, and the sender is told nothing. A box that wants a sender refused at its server says so in its ACL (Section 11.14).

**The drain.**

- **A drain is bounded** in messages, bytes, list pages and time, by the client, and stops at a bound saying so; a fetch cut at its time goes on by range at the next drain.
- **A `429 fetch_paced` or `refetch_spent` stops the drain** as the client's own bounds do: what it delivered stays delivered, and the rest waits on the server.
- **An id already handled is skipped,** and `404 no_such_message` on a fetch or an ack is a message already gone.
- **A client SHOULD keep a list's `ETag` only from an empty box's answer,** so that a `304` means the box is still empty; one that keeps the tag of a page with mail MUST act on the page it kept when it is answered `304`. A `304` whose `ETag`, compared weakly, is not the tag the poll sent is no answer: the drain stops, and the client drops the tag it kept. A `304` to a list that sent no `If-None-Match`, and a list answer without `Retry-After`, break their form.
- **A client takes a list as no answer** if its cursor is not of the form Section 11.11 gives, or an entry's `size` is over 16 MiB, before it fetches anything.

### 12.4. Renewal and the deletion of keys

- **Each renewal is a new prekey.** A client that holds its identity SHOULD make a new working key and certificate with each, numbered by its clock (Section 5), after it reads its own box: what the read carries of its identity's revocation of certificates is kept, and the next certificate is numbered above it.
- **A box MUST check its own certificate at its own clock before it signs under it:** a box whose clock has gone back past its certificate's start is stopped there.
- **Lifetime.** A prekey is valid for 33 days, or for a shorter lifetime its owner sets, down to a day and three hours. A client renews while at least two hours of its prekey are left, an hour for the renewal's own calls and the hour of room for clocks (Section 3.4), and times its renewals and the early deletion of its retired prekeys by its own record of when it signed each prekey, never by the statement's `not_after`: a prekey with no record is renewed at once, and every retired key is kept while the newest has none.
- **A serial is signed once.** A renewal the server did not take is sent again exactly as it was signed. A client signs a new key, at a later number, only once that statement has ended, or was made for longer than the lifetime now allows, or has no record of when it was made, or is at or below a serial its identity has revoked, or is under a certificate that began less than an hour before the box's clock, or another key type is wanted, or its server holds a statement no earlier than it (below). The key passed over is kept and deleted as a retired one.
- **A renewal answered `409 conflict`, or `401 certificate_not_current` under the second pass Section 8 allows, is final for its statement:** the server holds a statement no earlier than it, and takes only a later one (Section 11.9). The box reads itself (Section 11.8): its own statement served is a renewal taken whose answer was lost; any other is a statement it did not make, and whether the box renews again is the rule below.
- **A client MUST NOT use a kept certificate that began less than an hour before its clock:** it was made while the clock read ahead. The statement and working key made with it are made again, by the clock as it reads: for the same prekey at a box's first registration, and at a later number at a renewal.
- **Deletion.** A retired prekey is deleted at its deletion time: at the latest its statement's `not_after` plus the TTL. A drain that stopped at a bound deletes no retired prekey. A client MAY delete earlier all but the newest retired prekey, after a drain that empties the box, by a list the server took under a pass dated more than an hour after the newest retired prekey was made. While a renewal under a new certificate waits, a box holds two working keys: the one under its current certificate, which signs its passes, and the one the waiting statement is signed with. The working key before such a renewal is deleted once it is taken.
- **A client deletes keys, and prunes its replay set, by its clock only once a server has taken a pass dated by that clock, and by that pass's date** (its `not_after` less ten minutes), never by a reading of the clock: a drain's once its list is answered, a renewal's once it is taken. While a renewal is untaken, every retired key is kept. Section 15.3 gives the reason.
- **A box its server has forgotten** sends its renewal as a registration (Section 11.7), numbered above what it published. A box restored from its identity alone, with no prekey of its own to keep the type of, makes a post-quantum prekey unless its owner says otherwise.
- **The prekey's type MAY change at any renewal,** with no change of address.
- **A box reads its own record at its server by every rule of Section 5 but its certificate's dates** (Section 11.8): what it needs of the read is that its identity signed the statement, and where the statement stands in the box's order. A certificate's dates bind what is signed under it, never a renewal past it, so a record its server took is never one the box cannot renew past for a date. A record that does not verify, or stands before what the box published, stops a renewal, and the remedy (Section 12.6) goes on past it.
- **A box whose read of itself shows a statement it did not make** MUST say so to its owner, with what it recommends:
  - **Under a certificate of a working key the box did not make,** its identity has certified someone else's key. The box SHOULD recommend that its owner revoke the address (Section 10.1): a revocation of certificates cannot end it, since whoever holds the identity makes a later certificate as easily (Section 15.5).
  - **Under a certificate of the box's own working key,** that key is in another's hands. Where the identity is kept beside the box's other keys, a copy of them holds the identity too, and the box SHOULD recommend revoking the address; otherwise, the remedy of Section 12.6.

  A box that has published a statement of its own MUST NOT renew above one it did not make unless its owner asks. One that has published none, restored from its identity alone, is served its lost machine's statement so, and its first renewal takes the box over. A box MUST NOT sign mail under a certificate of its own working key that such a statement shows another holds: the remedy, or the revocation of the address, takes that mail with it, so the outbox waits for the box's next certificate.
- **A box that does not renew** is sent nothing once its prekey's `not_after` passes (`409 prekey_expired` to its senders), signs no mail once its certificate has 33 days or less left, and can poll while its certificate lasts. Once that has ended its server takes no pass from it, and a renewal is the one call that brings it back while the server keeps it.

### 12.5. Revocation at a client

- **A client takes "revoked" only with a revocation that verifies.** A `410 revoked`, a `403 sender_revoked` or a `401 certificate_revoked` is a server's word. A client verifies the record a `410` carries; it reads the box (Section 11.8) only after a `403 sender_revoked`, its own box, or a `410` that carries no record or one that does not verify, unless that read is what answered. A record that verifies is final. Without one, the call has failed and nothing more: no state changes, and a message stays in the outbox. What a server shows that does not verify counts as nothing shown.
- **On `401 certificate_revoked`, a client reads its own box before it tries again.** A revocation there that verifies and covers the certificate it signs under is final: no second pass is signed for the call, and the box renews instead. With none, it signs one more pass, as for any `401`.
- **A box asks about revocations, and publishes its own, at its own server alone:** of the recipient by the read before every post, of each sender once in a drain, and whenever its owner says. Where its server holds no box for it, a box reads its own with `GET …/revocations`.
- **What it has verified about an address, from any source and at any time, it keeps for good,** and checks every send and every read against, with no call to anyone. A record handed over is checked and kept as a served one is. "None held" is kept nowhere.
- **A box that holds its own revocation is finished, whatever any server answers.** It signs nothing more as that address: no pass, no mail, no certificate; a send is never posted, and a drain, a renewal and every call that carries a pass are refused before anything is asked. It still asks about, keeps and publishes revocations, which carry no pass. One it keeps that no longer verifies is a fault, and stops the same.
- **A publish answered `410 revoked` is done** once the record it carries verifies, or, where it carries none that does, the record the client's read of its box then carries.
- **A client publishes a revocation of an address only with the address written out in full,** as its owner's confirmation, and writes no record unasked.
- **A record made in advance** is the body of the publishing call, and publishing it later needs no box and no key. Whoever holds it can end the address, so it is kept apart from the identity.

### 12.6. The remedy for a taken working key

For a working key taken without the identity that certified it; a taken identity is ended by revoking its address (Section 10.1). Run where the identity is. It revokes, then renews, in that order.

1. **Read what is held,** at the box's own server, and keep what verifies of the box's revocation of its certificates. An answer it cannot use does not stop the remedy.
2. **Revoke every certificate below the number its clock gives,** through the serial one below it, or sign again one through a higher serial that is held already, and publish it once (Section 11.15). A `409 conflict` means the server holds a higher one: the client reads the box again, keeps that one once it verifies, and renews above it. A conflict that shows none that verifies and covers the certificates stops the remedy there, with nothing renewed.
3. **Then renew,** under a new working key and a certificate numbered one above the revocation's serial, and send nothing an earlier renewal left: whoever copied the box while it waited holds that renewal's working key. Until the server takes the new prekey the box signs no mail.

A box whose own revocation covers the certificate it uses renews at its next drain.

### 12.7. A box whose identity is held elsewhere

The identity's holder makes the box's certificates and its revocations; the box keeps everything else (Section 12.1).

- **The box makes each working key and keeps it; the identity's holder certifies only its public half.** The box gives the holder the public key and the lowest serial the certificate may have: one above the highest the box knows of for itself (Section 5). The holder numbers the certificate by Section 5, at that serial or above. The box holds the certificate to every rule of Section 5, to a serial no lower than the one it gave and to the key it made, and then renews under it (Section 11.9); one that began less than an hour before the box's clock (Section 12.4) it uses only once that hour has passed. A prekey never leaves the box, and the holder holds no key that reads mail.
- **Between certificates the box renews under its current one:** each renewal a new prekey at a higher prekey serial, each statement ending no later than the certificate (Section 6). With less left on the certificate than the shortest prekey lifetime (Section 12.4), it makes no renewal under it.
- **From 33 days left on its certificate the box signs no mail** (Section 5): what it sends waits in its outbox, which posts an entry for 33 days from when it was written (Section 12.2), and its renewals and drains go on. **Once the certificate has ended** its server takes no pass under it, and nothing goes on until the holder gives it a later one: the renewal under that one is taken while the server keeps the box (Sections 11.9, 13), and registers the box anew once the server has forgotten it (Section 12.4).
- **Wherever Sections 12.5 and 12.6 have a box renew under a new certificate,** this one waits for its holder to give it one. A certificate the holder gives it is its owner's ask (Section 12.4).
- **A renewal answered `409 conflict` or `401 certificate_not_current`** is final for its statement (Section 12.4), and the box signs no statement at a higher prekey serial to pass the one served: whoever holds the same working key can sign at any serial, and only a later certificate passes it. A `409` whose read shows a statement the box did not make is under its own working key's certificate, which another holds: the box signs no mail under it (Section 12.4) and recommends the remedy. After such a `401` it waits for a certificate above the serial the answer names.
- **Both revocations are the holder's** (Section 10). **The remedy (Section 12.6) is split:** the holder runs steps 1 and 2; the box then makes a new working key, never one made before the revocation, the holder certifies it above the revocation's serial, and the box renews under it (step 3).

## 13. What a server stores, and for how long

How a server stores things is its own. What it promises a client is this.

- **Per box:** the identity document; its state (Section 11.6); the current prekey statement and its signature, as they were sent, and served so; the serial of the certificate that statement is under; the sender key types it declared; for the newest retired prekeys, the type, `not_after` and a hash of the key (Section 11.9); when the box was registered; its account, if any; and its ACL. No private key, no pass, and no record of when the box was last seen.
- **Per address, with a box or none:** the identity document and what its identity revoked (Section 10), each kept for good and served to whoever asks.
- **A box is kept until nothing valid for it is left:** a registration and every renewal keep it until the later of its certificate's end and its prekey's `not_after` plus the TTL. Past that a server MAY forget it at any moment, and it is then unknown (Section 11.6).
- **Per message:** the ciphertext exactly as the send's body carried it; `from`, the box whose pass the send carried; its size; `received_at` and `expires_at`. Its id is the ciphertext's SHA-256. No signature: the message's is inside the ciphertext.
- **A `200` or `201` to a send means the message is stored.**
- **Mail expires 33 days less an hour and two minutes after it is received,** read or not: the TTL, less the hour of room for clocks, less two minutes for a post's own time from its dating to the server's receipt. `expires_at` is the authority: a server MUST NOT serve a message past it.
- **An ack deletes the ciphertext.** The id, `from`, the size and the times stay as the dedupe record until `expires_at` (Section 11.10, step 6).
- **A revocation of the address** does to every message in the box what an ack does to one, and the box's record goes with it; the revocation stays. **An ACL** does the same to the mail of every sender its `deny` matches.
- **Logs.** A server MUST NOT log an address or a message id in the clear: each is replaced by a short hash of itself, which only someone already holding it can match. A server MUST NOT log a pass or a request body.

## 14. Compatibility and versioning

Until version 1 is declared stable, nothing is final. From that declaration:

- **A server refuses a member it does not know, and every other reader ignores one** (Section 3.3).
- **Signed statements match their format exactly:** the identity document, the prekey statement, the pass, and the two revocations. A new format takes a new tag. Each namespace is versioned on its own.
- **A new member is optional.**
- **A server MAY add a route.** A client reads a plain `404` or `405` as a route that server does not offer (Section 11.2).
- **`irongall-revoke-v1` stays valid for good,** so a revocation signed in advance keeps working.
- **A new identity key type is an addition inside v1:** the identity document has one form for every type (Section 4.1), so a type defined later takes no new tag, and a box declares the types its client verifies (Section 7).
- **A new prekey type is an addition inside v1** the same way (Section 6).

What version 1 fixes, and where each can grow inside it:

| Fixed | Grows by |
|---|---|
| The signed statements, byte for byte (Sections 4.1, 6, 8, 10); a certificate's type, key id, principal and validity (Section 5) | a new format under a new tag; a new identity or prekey key type; a certificate extension, which a reader ignores |
| The namespaces, `irongall-<purpose>-v1:<address>` | a new purpose |
| A signature's form, and its bound for each key type (Section 3.2) | a new key type, with a bound of its own |
| What is encrypted: the envelope's line, the signature block, the padding (Section 9) | the envelope's optional members; `v` changes only for a breaking change |
| JSON as Section 3.3 reads it; a byte member's one encoding; a message's ciphertext as a send's body | nothing |
| The largest ciphertext, 16 MiB (Section 11.10) | a new version of the protocol |
| The routes, methods, statuses, codes and members (`api/openapi.yaml`) | a route; an optional member; a code, which a client that lacks it reads by its status |
| The pass's scheme and its three parameters (Section 8) | a new scheme |
| An error's `type` (Section 11.3); the link (Section 4.3) | a new code |

## 15. Security considerations

### 15.1. Threat model

IronGall protects a message's content from everyone but its recipient, and its sender's identity from forgery by anyone, the server included. It does not hide from the server who writes to whom.

- **The adversaries:** the server's operator, and whoever terminates TLS for it, who see everything stored and in transit; a network attacker, who sees TLS; a registered sender; many cheap identities; and a compromised or prompt-injected box.
- **The assets, in order:** a message's content; its sender's authenticity; the authenticity of a box's keys; availability; metadata.
- **The trust root is the address.** It is exchanged out of band, so whoever delivers it to a sender is trusted to deliver the right one, as with any key fingerprint.
- **Every defence below holds for a client that verifies and gates:** one that runs every check of Section 12 and acts on none that failed. Code or commands a server serves are no such client.

### 15.2. What a hostile server can and cannot do

- **It sees:** addresses, identity documents, certificates and prekeys; who mails whom; each message's size to within a padding block (Section 9.3); times and IP addresses; ciphertext; each box's passes; which account a box is in; and each box's ACL, which under an allow list names senders the box takes mail from who may never have written to it.
- **It never sees:** plaintext, a private key, an age file key, or any message's signature. **It holds nothing signed that says who wrote to whom:** a pass names a box and a time, and no recipient and no message.
- **It can:** deny service; drop, delay or delete mail, undetectably; say a box is revoked when it is not, which a client checks and does not believe (Section 12.5); keep a revocation from a peer that has never seen it (Section 15.6); replay old mail, and name another box as a message's sender, both of which Section 12.3 refuses; serve a stale prekey to a sender, but only one the box's working key signed, and only until its `not_after`, and not to a sender that has seen a newer one; act as a box toward itself; take mail a box's ACL refuses, which the box's client still judges, or refuse mail it admits, which it could drop anyway; lie once in the ACL a box restored without its own lists adopts, so that a verified sender's mail lands as allowed, or mail it could drop anyway is dropped; write anything in an error's words, which a client never shows, or in a receipt, an account id or a cursor, which a client checks to their forms before it uses one (Section 11.3); and serve altered instructions to an agent that runs what it is served.
- **It cannot,** against a client that verifies and gates: read mail, forge a sender, reattribute a message, substitute a key (that would need a SHA-256 second preimage or a signature forgery), alter a message undetected, end an address, make a pass, or turn a pass into plaintext or a signature on mail.

### 15.3. Forward secrecy

- **Every box has forward secrecy, bounded by how often it renews and deletes,** given a client that deletes retired prekeys (Section 12.4): a message is unrecoverable from the box's keys once every prekey it could be encrypted to is deleted, at the latest its statement's `not_after` plus the TTL, 66 days after the prekey was published. A client that renews and empties its box often, and deletes all but the newest retired prekey after an emptying drain, brings that to its second renewal after the message arrived.
- **Mail waiting on the server is exposed until the box fetches it.** A box that stops renewing keeps its ended prekey as its current one, and its last messages stay exposed until it renews.
- **A box that no server takes a pass from keeps its retired keys** past their deletion time, until one does: it cannot tell its clock far ahead from a server that refuses it, and deletes by that clock no key that mail may wait for.
- **It depends on real deletion.** A key kept in a backup, a synced folder or a store with version history survives its deletion.
- **There is no per-message forward secrecy and no post-compromise security:** version 1 has no ratchet. A leaked prekey reads all mail encrypted to it until it is renewed and deleted.

### 15.4. Sender authentication

- **Each message carries its sender's signature inside the encryption,** by a working key the sender's identity certified, verified by the recipient. The signature resists key-compromise impersonation: a leaked prekey lets nobody forge a sender to its box.
- **The signature is bound to its recipient,** by the namespace and by the envelope's `to`, so a recipient cannot pass a signed message on to a third box as mail from its sender, the known flaw of signing before encrypting.
- **It is not deniable toward a recipient:** a recipient can show anyone what a sender signed. That is an audit trail for programs that act on mail, and a privacy cost. The server holds no message signature and can prove nothing of who sent what.
- **A message a box cannot decrypt has only the server's word for its sender:** a box restored without its prekeys cannot prove whom to ask to send again.
- **Decrypting precedes verifying.** Until the signature is checked, a reader handles bytes nobody vouched for: age's, then the envelope's line. age is made to be handed files from anyone, and a refusal is acked whatever its reason, so neither the server nor the sender learns which check failed. Each part of what is decrypted has one place, and nothing is searched for (Section 9.2).
- **age to a public key authenticates nobody:** only the signature inside makes a message its sender's. The padding after it is unsigned, and never read.

### 15.5. Stolen keys

- **A stolen identity key is the worst case.** Its thief can certify a working key of its own, publish prekeys and read new mail until the owner revokes the address (Section 10.1), which ends the address for good: recovery is a new address, announced out of band. A thief that holds the identity can also revoke, which gains it nothing.
- **A lost identity key can be revoked only by a record made in advance** (Section 12.5). Without one, the address stops taking mail once its prekey ends, and its correspondents are told the new address out of band.
- **A stolen working key** signs as the box until its certificate ends, at most 64 days and an hour after the certificate was made, if a server delivers the mail. A renewal under a new certificate takes it from the server at once, and from every sender that has seen the newer certificate. A revocation of its certificate ends it everywhere the revocation is seen (Section 12.6). A certificate cannot be much shorter: it signs mail for 31 days, the longest month, so that a certificate made each month by an identity held elsewhere carries the box's mail until the next, and it must outlast the last of that mail by the 33 days it may wait, since it is checked at the reader's clock and nothing vouches for when a signature was made. Mail the owner sent under a revoked certificate and not yet read is refused with the thief's.
- **A stolen pass,** for the minutes it has left and at that server only, gives the box's metadata and its ciphertext; control of its availability (irrecoverable deletion of unacked mail, leaving its account, its ACL, with which it can pause the box until its owner writes the next); and posting in its name, which verifies at no recipient. It never gives plaintext, signs no mail and no prekey, and cannot end the address. Hence a pass of ten minutes, kept in a directory only the owner reads.
- **A stolen prekey** reads all mail encrypted to it, until the box renews. A sender that has seen no newer serial can still be served the old statement until its `not_after`, so a box that renews often MAY set a shorter lifetime (Section 12.4).

### 15.6. Revocation's limits

- **A server can keep a revocation from a peer that has never seen it,** answering that it holds none, and nothing tells the peer otherwise. Asking before every post narrows that in time and no further: what a client was shown while its server answered truly, it keeps after that server stops. A server that hides a record from its first answer is answered only by a record from the box's owner, handed over out of band.
- **A box asks its own server alone.** A second server listed beside it would tell against a server that withholds only where the revoked box's owner and the reader list the same one.
- **This protocol bounds no time a revocation can go unseen by a peer whose server hides it.** The usual remedy is key transparency, a log of what a server serves that clients check, which this protocol does not have.

### 15.7. Clocks

- **A box whose clock is further off than the room allows is stopped** before it fetches mail it would judge by that clock, prunes its replay set by it, or deletes a prekey by it: in most cases at its pass (`401 pass_expired`), and a box whose clock is more than 50 minutes ahead when it makes a certificate, at the server's check of that certificate (`400 prekey_time`). A server takes a certificate only once it has begun 10 minutes before its own clock, so every certificate a server takes has begun for every reader whose clock it takes.
- **Two clocks a server takes are less than an hour apart** when each shows a pass: a server takes a pass from a box whose clock is less than 10 minutes behind its own, or up to 50 ahead.
- **What this does not cover.** A pass is checked when it is first shown, and a server MAY remember it for its ten minutes. A clock that moves by minutes inside those ten, or goes back by more than an hour in the middle of a drain, can put a `sent_at` past a reader's hour, or have a reader judge mail by a clock no server took; the reader then refuses the message, and keeps it with what its checks found, its clock among them. Each case needs a clock that is already wrong.
- **The replay floor** costs only mail that a hostile server took a pass for at a clock an honest server refuses, which that server could withhold anyway.

### 15.8. Metadata

- **The server sees the social graph,** times, IP addresses and each message's size to within a padding block. Padding hides a length, not a pattern of traffic: who writes to whom, when and how often. A sender that is not one of the reference clients may pad differently or not at all, and the server cannot tell.
- **The read before a post** tells the server that the box is about to be written to, which the post tells it a moment later.
- **A read of a box in gzip** has a length that turns on the box's own bytes, so it can narrow, to a network observer, whom a sender is about to write to.
- **Whoever terminates TLS for a server** sees what its operator sees, passes in transit among it.
- **An address in a URL** is seen wherever URLs are logged: by whoever terminates TLS, in a chat that unfurls links, in a transcript. The remedy for a leaked address is a new box, and the old one's revocation.

### 15.9. Addresses, mail and availability

- **An address is a send capability:** keeping it private is the first defence against unwanted mail. Mailing a box hands it the sender's address, so it can write back.
- **Authentic is not safe.** A signed message from a compromised or prompt-injected sender is genuine. Mail is data, never instructions (Section 12.3), and a box's ACL, whose allow list names the senders it takes, is its defence at the server.
- **An open box can be filled** to its caps, and its budget of new mail spent, by enough verified identities, delaying its other senders' mail. An allow list is the full defence for a box that knows its senders; a deny list is not, since a new identity is cheap.
- **A hostile server's cost to a reader is bounded** by the reader's drain bounds (Section 12.3). Mail from senders a server made up, which does not decrypt or verify, leaves no pin. A sender a server made with keys of its own is a real sender, at an address nobody gave the reader.
- **Silent drops are undetectable;** the protocol has no receipts.

### 15.10. Post-quantum

- **Content** is protected against harvest-now-decrypt-later for a box with a post-quantum prekey, the default. A box that moved from an X25519 prekey can be held on its old key for at most its lifetime.
- **Signatures are classical,** Ed25519 or P-256. A forgery needs a quantum computer at signing time, and the transferable audit trail holds until one exists. A post-quantum signature key would be added as an identity key type inside v1 (Section 14), with a new address for the box that moves to it.
- **The TLS connections are separate,** and protected as their endpoints negotiate.

## 16. Test vectors

`testdata/vectors/` holds the conformance vectors. Each file is one scenario, named for its verdict, with its expected outcome; `testdata/vectors/README.md` describes their format and how each is checked. A conforming client passes every vector of the parts it implements. The crypto and container vectors are checked by `age`, `ssh-keygen` and `sha256sum`, tools this project did not write; their keys are published test keys.

## 17. References

- **[age]** C2SP, "age", https://c2sp.org/age
- **[draft-ietf-sshm-cert]** "OpenSSH certificates", draft-ietf-sshm-cert
- **[PROTOCOL.sshsig]** OpenSSH, `PROTOCOL.sshsig`
- **[AEP-158]**, **[AEP-193]** API Enhancement Proposals: pagination; errors
- **[BIP 173]** Bech32
- **[FIPS 180-4]**, **[FIPS 186-5]**
- **[RFC 2119]**, **[RFC 8174]** BCP 14
- **[RFC 3339]** timestamps · **[RFC 4151]** the `tag` URI scheme · **[RFC 4251]**, **[RFC 4253]** SSH · **[RFC 4648]** base64 · **[RFC 5656]** ECDSA in SSH · **[RFC 6454]** origins · **[RFC 7457]** TLS attacks · **[RFC 7493]** I-JSON · **[RFC 8032]** EdDSA · **[RFC 8259]** JSON · **[RFC 8555]** ACME · **[RFC 8709]** Ed25519 in SSH · **[RFC 9110]** HTTP semantics · **[RFC 9457]** problem details · **[RFC 9562]** UUIDs

## Appendix A. Where OpenSSH releases differ (informative)

A client built on `ssh-keygen` meets these variances against Section 3.2 and Section 4.1:

- **An Ed25519 signature's R.** OpenSSH's own Ed25519 from 10.6p1, libsodium's, used where libcrypto has none, refuses the neutral R, and takes R with a point of order 2 or 4 added; it refuses R with a point of order 8 added.
- **An Ed25519 signature's S.** `ssh-keygen` before 10.3p1 on OpenSSL's Ed25519, and before 10.4p1 on its own, takes S + L, so a client built on it checks S itself.
- **An Ed25519 key.** Go's `crypto/ed25519`, and OpenSSH before 10.6p1, take small-order and non-canonical keys, so a client checks them itself.
- **A P-256 key's coordinates.** OpenSSH up to 10.2p1 refuses a coordinate of 128 bits or fewer, or of n − 1 or more, which OpenSSH from 10.3p1 and `golang.org/x/crypto/ssh` take.
- **A P-256 key at all.** OpenSSH built without OpenSSL reads none.
- **Certificates.** `ssh-keygen -Y verify` takes a certificate with a second principal, a critical option, or extensions out of order or given twice, checks no key id, and knows a serial only through a revocation list, so a client built on it reads those fields from the certificate itself.
