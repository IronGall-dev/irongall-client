#!/usr/bin/env python3
"""mutate.py: show every client check can fail.

Each line of M breaks one check, runs `go test ./...`, and restores the file.
Every mutation must be CAUGHT: some test goes red. MISSED means no test can
reach the check: add the test, or delete the check as dead code. BUILD FAILED
means the mutation itself does not compile: fix the line.

Run from anywhere, with go on PATH:   test/mutate.py [index ...]
Every file is restored, even on an error or ^C. Nothing here needs a server or
a network: the tests run against internal/fakeserver.

Not here: durability (fsync) and error plumbing, which no test can observe
failing; a check's line is listed only when a test can see it break.
"""
import os
import subprocess
import sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/'
M = [
    # pinning and resolving a peer
    ('client/peer.go', '\tif id.Address() != peer {', '\tif false {'),
    ('client/peer.go', '\tp, err := protocol.VerifyPrekey(id, ir.Prekey, ir.PrekeySignature)', '\tp, err := protocol.ParsePrekey(ir.Prekey); _ = id'),
    ('client/peer.go', '\tif p.Serial < seen {', '\tif false {'),
    ('client/peer.go', '\tif p.Expired(b.now()) {', '\tif false {'),
    ('client/peer.go', '\t\t// A pin always wins.', '\t\tdoc = served'),
    # judging a message
    ('client/recv.go', '\tif err := protocol.Verify(id, m.Ciphertext, m.Signature, protocol.MessageNamespace(me)); err != nil {', '\tif _ = id; false {'),
    ('client/recv.go', '\tenv, err := protocol.OpenEnvelope(p, from, me, b.now())', '\tenv, err := protocol.OpenEnvelope(p, from, me, b.now().AddDate(-1, 0, 0))'),
    ('client/recv.go', '\tif seen {\n\t\treturn nil, false, "replay', '\tif _ = seen; false {\n\t\treturn nil, false, "replay'),
    ('client/recv.go', '\tif again {', '\tif _ = again; false {'),
    ('client/recv.go', '\t\t\tif err := b.recordSeen(m.Ciphertext, d.Envelope); err != nil {', '\t\t\tif err := error(nil); err != nil {'),
    ('client/recv.go', 'list.Count == 0 && t != ""', 't != ""'),
    ('client/recv.go', '\tif !handled {', '\tif _ = handled; true {'),
    ('client/recv.go', '\tif why == "" && local != id {', '\tif false {'),
    ('client/recv.go', 'writeFile(b.path("inbox", local+".json"), d.Line)', 'writeFile(b.path("inbox", local+".json"), d.Plaintext)'),
    ('client/recv.go', 'writeFile(b.path("quarantine", local+".json"), raw)', 'writeFile(b.path("quarantine", id+".json"), raw)'),
    ('client/recv.go', '\tids, err := b.prekeyIdentities()\n\tif err != nil {\n\t\treturn nil, false, "", err', '\tids, err := b.prekeyIdentities()\n\tif err != nil {\n\t\treturn nil, false, err.Error(), nil'),
    ('client/recv.go', '\treturn nil, false, "", err\n}', '\treturn nil, false, err.Error(), nil\n}'),
    ('cmd/crossbot/main.go', 'd.Line); werr', 'd.Plaintext); werr'),
    # owner calls
    ('client/api.go', '\t\t\t\t_ = b.storeToken(ct)', '\t\t\t\t_ = ct'),
    ('client/api.go', '\tif Code(err) != protocol.CodeTokenStale {', '\tif true {'),
    ('client/box.go', '\t\tb.http = &http.Client{Timeout: requestTimeout}', '\t\tb.http = http.DefaultClient'),
    # sending and the outbox
    ('client/send.go', '\tif Code(err) == protocol.CodeStalePrekey {', '\tif false {'),
    ('client/send.go', '\tfor _, ext := range []string{".P", ".age", ".sig", ".json"} {\n\t\tif err := removeIfExists(stem + ext)', '\tfor _, ext := range []string{} {\n\t\tif err := removeIfExists(stem + ext)'),
    ('client/send.go', '\t\t\terrs = append(errs, fmt.Errorf("%s: %w", filepath.Base(stem), err))\n\t\t\tcontinue', '\t\t\treturn receipts, err'),
    ('client/send.go', '\t\tif !slices.Contains(undeliverable, Code(err)) && !b.expired(stem) {', '\t\tif !slices.Contains(undeliverable[:0], Code(err)) && !b.expired(stem) {'),
    ('client/send.go', '\t\tif !slices.Contains(undeliverable, Code(err)) && !b.expired(stem) {', '\t\tif !slices.Contains(undeliverable, Code(err)) {'),
    # the lock
    ('client/lock.go', '\tif err := flock(f); err != nil {', '\tif err := error(nil); err != nil {'),
    ('client/lock.go', '\tif created {\n\t\tflags |= os.O_CREATE', '\tif true {\n\t\tflags |= os.O_CREATE'),
    ('client/lock.go', '\tif !stillNamed(f, l.dir+"/pid") {', '\tif false {'),
    # prekeys
    ('client/rekey.go', '\t\tif !b.now().Before(p.NotAfter.Add(protocol.TTL)) {', '\t\tif !b.now().Before(p.NotAfter) {'),
    ('client/rekey.go', '\t\tif err != nil || n >= top {', '\t\tif err != nil {'),
    ('client/rekey.go', '\tif cur.Serial < published {', '\tif false {'),
    ('client/rekey.go', '\tif err := b.recordPublished(next); err != nil {', '\tif err := error(nil); err != nil {'),
    ('client/rekey.go', '\tl, err := b.lock()\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tp, err := b.rekey(ctx, kt)\n\tif e := l.release(); err == nil {\n\t\terr = e\n\t}\n\treturn p, err', '\treturn b.rekey(ctx, kt)'),
    ('client/box.go', '\tif !exists(stem+".agekey") || keyType(stem+".agekey") != kt {', '\tif !exists(stem + ".agekey") {'),
    # the envelope
    ('protocol/envelope.go', '\t\tif _, dup := fields[key]; dup {', '\t\tif false {'),
    ('protocol/envelope.go', '\tif !utf8.Valid(plaintext) {', '\tif false {'),
    ('protocol/envelope.go', '\tif f, err := json.Number(fields["v"]).Float64(); err != nil || f != EnvelopeVersion {', '\tif f, err := json.Number(fields["v"]).Float64(); err != nil && f != EnvelopeVersion {'),
    ('protocol/envelope.go', '\tif _, err := d.Token(); err != io.EOF {', '\tif _, err := d.Token(); err != io.EOF && false {'),
    ('protocol/envelope.go', '\tif !utf8.ValidString(body) {', '\tif false {'),
]

only = sys.argv[1:]
caught = missed = 0
for i, (f, a, b) in enumerate(M):
    if only and str(i) not in only:
        continue
    path = R + f
    src = open(path).read()
    if src.count(a) != 1:
        print(f'{i}: PATTERN COUNT {src.count(a)} in {f}: {a[:60]!r}')
        continue
    open(path, 'w').write(src.replace(a, b))
    try:
        r = subprocess.run(['go', 'test', '-count=1', './...'], cwd=R, capture_output=True, text=True, timeout=600)
    finally:
        open(path, 'w').write(src)
    out = r.stdout + r.stderr
    fails = [l.strip() for l in out.splitlines() if l.lstrip().startswith('--- FAIL')]
    if 'build failed' in out or '[setup failed]' in out:
        print(f'{i}: BUILD FAILED {f} {a.strip()[:50]!r}\n{out[-600:]}')
    elif r.returncode == 0:
        missed += 1
        print(f'{i}: MISSED  {f} {a.strip()[:70]!r}')
    else:
        caught += 1
        print(f'{i}: caught  {f} {a.strip()[:50]!r} -> {", ".join(x.replace("--- FAIL: ", "") for x in fails[:3])}')
print(f'caught {caught}, missed {missed}')
