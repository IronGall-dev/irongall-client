# Security

IronGall is built so that nobody has to trust its server. Everything that protects a message runs in a client, in this repo, and is held by tests that play a server that forges. This file says how to check that, and how to tell us when it is wrong.

## Supported versions

**IronGall is before v1, and only the latest commit on `main` is supported.** There are no releases or tags yet (the release chain is #16), so a fix is a commit on `main`. The protocol may still change until it is frozen, which we expect by 15 November 2026; what must be settled first is the milestone `M1: protocol freeze`. **Nothing is externally audited yet.**

## Reporting a vulnerability

**Report it privately, with GitHub's private vulnerability reporting:** the **Report a vulnerability** button under this repo's Security tab, or from a terminal:

```sh
gh api repos/IronGall-dev/irongall-client/security-advisories/reports \
  -f summary='…' -f description='…'
```

- **Here:** the protocol and its specification (`PROTOCOL.md`), both clients and the test vectors. **The server, and irongall.dev as it is run:** [irongall-server](https://github.com/IronGall-dev/irongall-server/security), by the same route. Not sure which? Either one.
- **Give what it takes to reproduce it:** what you did, what happened, what should have, the commit you ran, and the impact. GitHub's form asks for a summary, details, a proof of concept and the impact.
- **AI-assisted reports are welcome**; the form has a box to say so.
- 🛑 **Never put a real box's identity key, a pass or mail in a report,** private or public.
- If private reporting is unavailable, open an issue asking for a security contact, with no detail.

**Not a vulnerability, though a better design is welcome as an issue:**
- What the design says it does not defend: the operator sees who writes to whom, when and how much; it can drop or delay mail; a recipient can show anyone what a sender signed; there is no ratchet (`PROTOCOL.md` §9; irongall-server's `CRYPTO-ANALYSIS.md` § Limitations and residual risks).
- A weakness already public: an open issue, or one of irongall-server's `LIMITS.md` § Known weaknesses.
- What a verified sender says. IronGall proves who sent a message, never that it is safe to obey (`README.md`).

**What happens next.** Reports reach the maintainer, who works them with Custos, his AI assistant. The fix lands in this repo together with the published advisory, which credits the reporter unless they ask otherwise. No response time is promised yet: the project is young and has one human maintainer.

## Checking the claims yourself

Each row is a claim the code makes, the section of `PROTOCOL.md` with the whole rule, and what holds it.

| The claim | `PROTOCOL.md` | Held by |
|---|---|---|
| **Standard cryptography only, nothing home-rolled:** age to encrypt (ML-KEM-768 + X25519 by default), SSHSIG over Ed25519 to sign, SHA-256 for addresses | §0 | `protocol/`, `sshsig/` (the API the Go team accepted for x/crypto); the vectors, checked against `ssh-keygen` and `age` themselves |
| **An address is the SHA-256 of its identity key.** Only that key, and a working key it certified, can speak for the address; a server can make neither | §2, §2b | `protocol/identity.go`, `protocol/certificate.go`; `client/forgery_test.go` |
| **Every document is accepted or refused as its vector names it:** each identity, certificate, prekey statement, pass, revocation of an address or of certificates, envelope and decrypted message | §2–§6 | `protocol/`, `testdata/vectors/` |
| **The server never sees plaintext or a private key.** A message is signed, then encrypted, on the sender's machine; the signature is inside the ciphertext | §4.3, §4.4 | `protocol/signed.go`, `client/send.go` |
| **The reader decides who sent a message,** from the sender's own signature, and never asks the server | §5 | `judge` in `client/`; `client/forgery_test.go` refuses each forgery an operator can make, one by one; `client/hostile_test.go` |
| **Verification is always on and fails closed:** a failed check stops, never warns and goes on. No flag skips it | §5 | `client/forgery_test.go`, `client/hostile_test.go` |
| **A hostile server costs a box one bounded run,** a fetch is read to the size its list gives and no further, a `304` about another tag than the one the poll sent is no answer, and a refusal never carries the sender's text | §5, §5.1, §13 | `client/hostile_test.go` (`TestADrainIsBounded`, `TestAFetchIsTheSizeItsListGives`), `client/etag_test.go` (`TestA304AboutAnotherTagIsNoAnswer`, `TestAPlantedTagHidesNoMail`) |
| **Nothing a sender or a server wrote is printed as the client's words;** a message body is data | §13 | `TestARefusalNeverQuotesTheMessage`, `TestAnAPIErrorPrintsNoneOfTheServersWords`, `TestATransportErrorPrintsNoneOfTheServersWords`, `TestAListsCursorIsNeverPrinted` |
| **Forward secrecy, bounded by how often a box checks in:** a new prekey at least every 33 days, or the shorter lifetime the box is set to (the Go client renews daily), never derived from a seed, never backed up, never reused; retired keys are deleted only once a server has taken a pass dated by the box's clock, and by that pass's date, so a clock far ahead, or one that jumps or steps back while a drain or a renewal is in flight, deletes none that mail waits for | §1, §6.4, §0 | `client/rekey.go`, `client/renew_test.go`, `client/lifetime_test.go`, `client/taken_test.go`, `TestAFastClockDeletesNoKeyMailWaitsFor`, `TestAClockThatJumpsDuringADrainDeletesNoKey`, `TestScriptAClockThatJumpsDuringARenewalDeletesNoKey`, `TestScriptDeletesARetiredPrekey`, `TestScriptUnderItsOwnRevocations` |
| **A box's pass, and the address a lookup asks about, never cross a network in the clear, and go nowhere a server points:** each client calls a server only over https, or over http on its own machine and through no proxy, and follows no redirect; the script reads no `.curlrc` | §0 | `newBox`, whose `transport` holds every request to `checkServerURL` and calls this machine or `localhost`, in any case, through no proxy, and `followNone`, in `client/`, `ig_tls`, `ig_here` and `ig_api` in `sh/irongall.sh`; `client/transport_test.go`, `TestBothClientsCallTheSameServers`, `TestTheScriptFollowsNoRedirect`, `TestNoCallOfTheScriptFollowsARedirect`, `TestARedirectedPublishIsNotTaken`, `TestA3xxIsNoAnswerWhateverItsLines`, `TestTheScriptReadsNoCurlrc`, `TestTheScriptCallsThisMachineDirectly`, `TestNoProxyForThisMachine`, `TestEveryRequestIsHeldToTheServerRule` |
| **Every send is padded,** so the server sees a message's size only to within a block | §4.3a | `client/pad_test.go` |
| **"Revoked" is taken on the identity's own signature, never on a server's word;** a revocation that verified is kept for good, mail from a revoked box is refused whenever it was signed, and a box that holds its own revocation signs nothing more, whatever any server answers | §6.3 | `client/internal/sign` and `locked` in `client/lock.go`; `client/revocation_test.go`, `client/ownrevocation_test.go`, `TestOnlySignSigns` |
| **A certificate its identity revoked loses everything it signed,** the address goes on, and nothing lowers what is revoked; a box makes no certificate it is shown revoked, and signs no mail under one it holds revoked | §6.3a, §2b | `client/revokedcerts_test.go`, `client/ownrevocation_test.go` |
| **A sender reads its recipient's box before every post,** keeps what verifies of the revocations it carries, posts nothing on no answer, and seals a message that waited at its post | §4.1, §4.5 | `client/ask_test.go` |
| **A failure never loses mail, and a retry is never delivered twice** | §4.5, §5 | `client/failure_test.go` |
| **A server's replay of mail already delivered is refused, however the reader's clock has stepped since,** a retry it kept of that mail included | §5 check 9, §4.5 | `client/replay_test.go`, `client/replay_retry_test.go`; `TestScriptKeepsItsReplaySetByItsClock`, `sh/dating_test.go` |
| **A message a server still serves is one its reader takes:** each post is dated afresh, once its recipient's box is read, and a server keeps mail an hour and two minutes less than its reader takes it for, a message that waited in the outbox included | §4.5, §7 | `client/dating_test.go`, `sh/dating_test.go`, `TestScriptKeepsItsReplaySetByItsClock`; irongall-server's `TestMailIsTakenWhileTheServerServesIt`, `TestMailAtTheLastSecondOfItsLife` |
| **The encryption and the signed container are the standards' formats, read by code this project did not write:** `age` decrypts each message vector with its prekey's published test identity, and `ssh-keygen` reads each certificate and verifies each signature, in a test that fails when either disagrees; typage, an age implementation apart from the one this client links, read both ciphertexts once, recorded with their hashes. `sh/irongall.sh`, on stock `age` and `ssh-keygen`, gives each crypto and container vector the Go client's verdict and exchanges mail with a Go box, against a forging server | §0, §11 | `TestVectorsByToolsNotOurs`, `TestVectorMessage`, `testdata/vectors/README.md`, `sh/` |

**Run them:** `README.md` § Tests, which says what each needs and what an `ok` does not tell you.

## Where the rest is

- **The threat model, the security properties and where each stops, the operator's power, the residual risks, and the questions where an outside cryptographer's view would change the design most:** irongall-server's [`CRYPTO-ANALYSIS.md`](https://github.com/IronGall-dev/irongall-server/blob/main/CRYPTO-ANALYSIS.md).
- **What a server sees and can do, as the specification states it:** `PROTOCOL.md` §9. For whoever runs a box, in short: `README.md` § No Server Trust.
- **What is not tested:** `PROTOCOL.md` §11. **What is specified and not built:** §12.
- **Every design decision beside the standard or system that does the same:** `PRECEDENTS.md`.
- **The server's limits, and where each is weak:** irongall-server's [`LIMITS.md`](https://github.com/IronGall-dev/irongall-server/blob/main/LIMITS.md).
- **Shipped code that no one but its author has read:** the issues labelled `needs-audit`. Each is a brief an outside agent can work from: the commits, the claims to break, where to look first, how to run it. Auditing one is the most useful review this project can get.
