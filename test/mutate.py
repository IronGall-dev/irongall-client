#!/usr/bin/env python3
"""mutate.py: show every client check can fail.

Each line of M breaks one check, runs `go test ./...`, and restores the file.
Every mutation must be CAUGHT: some test goes red. MISSED means no test can
reach the check: add the test, or delete the check as dead code. BUILD FAILED
means the mutation itself does not compile: fix the line.

Run from anywhere, with go on PATH:   test/mutate.py [--since REF] [index ...]
It runs in a throwaway copy of HEAD (a detached worktree in a temp
directory), never in the checkout: commit first, and nothing else waits on a
pass. It is an occasional check, run in the background, not a step of every
change. --since REF keeps only the entries whose file changed since REF.
Nothing here needs a server or a network: the tests run against
internal/fakeserver.

Not here: durability (fsync) and error plumbing, which no test can observe
failing; a check's line is listed only when a test can see it break.
"""
import argparse
import atexit
import os
import shutil
import subprocess
import tempfile

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
    ('client/recv.go', 'Line: []byte(lineBreaks.Replace(string(line)))', 'Line: line'),
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
    ('client/send.go', '\t\tif !slices.Contains(undeliverable, Code(err)) {', '\t\tif !slices.Contains(undeliverable[:0], Code(err)) {'),
    ('client/send.go', '\tif b.expired(stem) {', '\tif false {'),
    # the lock
    ('client/lock.go', '\tif err := flock(f); err != nil {', '\tif err := error(nil); err != nil {'),
    ('client/lock.go', '\tif created {\n\t\tflags |= os.O_CREATE', '\tif true {\n\t\tflags |= os.O_CREATE'),
    ('client/lock.go', '\tif !stillNamed(f, l.dir+"/pid") {', '\tif false {'),
    # prekeys
    ('client/rekey.go', '\t\tif !b.now().Before(p.NotAfter.Add(protocol.TTL)) {', '\t\tif !b.now().Before(p.NotAfter) {'),
    ('client/rekey.go', '\t\tif err != nil || n >= top {', '\t\tif err != nil {'),
    ('client/rekey.go', '\tif cur.Serial < published {', '\tif false {'),
    ('client/rekey.go', '\tif err := b.recordPublished(next); err != nil {', '\tif err := error(nil); err != nil {'),
    ('client/rekey.go', '\tl, err := b.lockWait(ctx, rekeyLockWait)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tp, err := b.rekey(ctx, kt)\n\tif e := l.release(); err == nil {\n\t\terr = e\n\t}\n\treturn p, err', '\treturn b.rekey(ctx, kt)'),
    ('client/rekey.go', '\tl, err := b.lockWait(ctx, rekeyLockWait)', '\tl, err := b.lock()'),
    ('client/lock.go', '\t\tif !errors.Is(err, errLocked) || !time.Now().Before(deadline) {', '\t\tif !errors.Is(err, errLocked) || deadline.IsZero() || true {'),
    ('client/box.go', '\tif !exists(stem+".agekey") || keyType(stem+".agekey") != kt {', '\tif !exists(stem + ".agekey") {'),
    # the envelope
    ('protocol/envelope.go', '\t\tif _, dup := fields[key]; dup {', '\t\tif false {'),
    ('protocol/envelope.go', '\tif !utf8.Valid(plaintext) {', '\tif false {'),
    ('protocol/envelope.go', '\tif f, err := json.Number(fields["v"]).Float64(); err != nil || f != EnvelopeVersion {', '\tif f, err := json.Number(fields["v"]).Float64(); err != nil && f != EnvelopeVersion {'),
    ('protocol/envelope.go', '\tif _, err := d.Token(); err != io.EOF {', '\tif _, err := d.Token(); err != io.EOF && false {'),
    ('protocol/envelope.go', '\tif !utf8.ValidString(body) {', '\tif false {'),
    ('client/errors.go', '[]string{e.Problem.Detail, e.Problem.Hint}', '[]string{e.Problem.Hint}'),
    ('cmd/crossbot/main.go', 'if errors.As(err, &e) && e.RetryAfter > 0 && time.Until(deadline) > e.RetryAfter {', 'if false {'),
    # the echo box, and a box restored from its identity
    ('cmd/crossbot-echo/main.go', '\tif client.Code(err) == protocol.CodeNoSuchMailbox {', '\tif false {'),
    ('cmd/crossbot-echo/main.go', '\tcase err == nil && !bytes.Equal(held, key):', '\tcase err == nil && !bytes.Equal(held, key) && false:'),
    ('cmd/crossbot-echo/main.go', '\tif _, err := e.b.Flush(ctx); err != nil && ctx.Err() == nil {', '\tif err := error(nil); err != nil && ctx.Err() == nil {'),
    ('cmd/crossbot-echo/main.go', '\t\tif err != nil || e.now().Sub(fi.ModTime()) < replyTTL {', '\t\tif err != nil || e.now().Sub(fi.ModTime()) <= replyTTL {'),
    ('cmd/crossbot-echo/main.go', '\tfor _, f := range failed {', '\tfor _, f := range failed[:0] {'),
    ('cmd/crossbot-echo/main.go', '\t\tfor _, d := range res.Delivered {', '\t\tfor _, d := range res.Delivered[:0] {'),
    ('cmd/crossbot-echo/main.go', '\te.remove(filepath.Join(e.b.Dir(), "inbox", d.ID+".json"))', ''),
    ('cmd/crossbot-echo/main.go', '\t\t\te.remove(filepath.Join(e.b.Dir(), "quarantine", r.ID+".json"))', ''),
    ('cmd/crossbot-echo/main.go', '\tif res != nil && res.PollAfter > 0 {', '\tif false {'),
    ('cmd/crossbot-echo/main.go', '\tif errors.As(err, &ae) && ae.RetryAfter > 0 {', '\tif errors.As(err, &ae) && ae.RetryAfter > 0 && false {'),
    ('cmd/crossbot-echo/main.go', 'fmt.Fprintf(&s, "body, as JSON: %s\\n", env.Body)', 'fmt.Fprintf(&s, "body, as JSON: %q\\n", env.Body)'),
    ('client/box.go', '\tif err := b.makeDirs(); err != nil {\n\t\treturn nil, err\n\t}\n\treturn b, nil', '\treturn b, nil'),
    # recv renews a prekey more than a day old, retries a failed renewal hourly, and keeps one prior prekey
    ('client/recv.go', '\trenewed, renewErr := b.renewIfDue(ctx)\n', '\tvar renewed *protocol.Prekey\n\tvar renewErr error\n'),
    ('client/recv.go', '\tif err == nil {\n\t\terr = b.dropRetired(began)', '\tif true {\n\t\terr = b.dropRetired(began)'),
    ('client/rekey.go', 'err == nil && b.now().Sub(made) <= renewAfter {', 'err == nil && b.now().Sub(made) < renewAfter {'),
    ('client/rekey.go', '\tif !b.renewFailed.IsZero() && b.now().Sub(b.renewFailed) < renewRetry {', '\tif false {'),
    ('client/rekey.go', '\t\tb.renewFailed = b.now()\n', ''),
    ('client/rekey.go', 'err != nil || began.Sub(made) <= retiredGrace {', 'err != nil || began.Sub(made) < retiredGrace {'),
    ('client/rekey.go', 'newest := retired[len(retired)-1]', 'newest := retired[0]'),
    ('client/rekey.go', 'for _, n := range retired[:len(retired)-1] {', 'for _, n := range retired {'),
    ('client/rekey.go', 'for _, ext := range []string{".agekey", ".txt", ".txt.sig"} {', 'for _, ext := range []string{".agekey"} {'),
    ('cmd/crossbot/main.go', '\t\t\t\tif res.RenewErr != nil {', '\t\t\t\tif false {'),
    # the link, <server>/to/<address>: printed by init and addr, taken by send, and only for this box's server
    ('client/box.go', 'a, err := protocol.ParseAddress(strings.TrimPrefix(s, b.base+protocol.LinkPath))', 'a, err := protocol.ParseAddress(s)'),
    ('client/box.go', 'a, err := protocol.ParseAddress(strings.TrimPrefix(s, b.base+protocol.LinkPath))', 'a, err := protocol.ParseAddress(s[strings.LastIndex(s, "/")+1:])'),
    ('client/box.go', '\tcase strings.Contains(s, "://") && !strings.HasPrefix(s, b.base+"/"):', '\tcase false:'),
    ('client/box.go', 'return b.base + protocol.LinkPath + b.Address().String() }', 'return b.Address().String() }'),
    ('cmd/crossbot/main.go', '_, err = fmt.Fprintln(stdout, b.Link())\n\t\treturn err\n\n\tcase "addr":', '_, err = fmt.Fprintln(stdout, b.Address())\n\t\treturn err\n\n\tcase "addr":'),
    # crossbot.sh, the stock-tools client (sh/sh_test.go runs it)
    ('sh/crossbot.sh', 'local a=${1#"$CB_BASE/to/"}', 'local a=$1'),
    ('sh/crossbot.sh', 'local a=${1#"$CB_BASE/to/"}', 'local a=${1##*/}'),
    ('sh/crossbot.sh', '[[ $1 != *://* || $1 = "$CB_BASE/"* ]] ||', 'true ||'),
    ('sh/crossbot.sh', 'a=$(cat "$CB/address") && echo "$CB_BASE/to/$a"', 'cat "$CB/address"'),
    # Not listed: cb_pin's "a pin always wins" branch. Only one document hashes to an address, so re-pinning from
    # any served identity that passes the hash check reaches the same pin: the branch saves a re-check, nothing more.
    ('sh/crossbot.sh', '[ "$(wc -c < "$f")" -eq 93 ] && [ "$(sed -n 1p "$f")" = crossbot-v1 ] &&', 'true &&'),
    ('sh/crossbot.sh', '[ -z "${2-}" ] || [ "$(sha256sum < "$f" | cut -c1-64)" = "$2" ] || return 1', 'true'),
    ('sh/crossbot.sh', '[[ ! $k =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1', 'true'),
    ('sh/crossbot.sh', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) ;;'),
    ('sh/crossbot.sh', '[ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || cb_refuse "the identity the server sent does not hash to $B" || return 1', 'true'),
    ('sh/crossbot.sh', 'cb_idcheck "$f" || cb_refuse', 'true || cb_refuse'),
    ('sh/crossbot.sh', 'ssh-keygen -Y verify -f "$4" -I "$B" -n "crossbot-prekey-v1:$B" -s "$2" < "$p" > /dev/null 2>&1 ||', 'true ||'),
    ('sh/crossbot.sh', '[ "$(wc -l < "$p")" -eq 5 ] && [ "$(tail -c 1 "$p" | od -An -tx1 | tr -d \' \\n\')" = 0a ] &&', 'true &&'),
    ('sh/crossbot.sh', '[[ $s =~ ^[1-9][0-9]{0,17}$ ]] || { echo "$B\'s prekey serial is malformed"', 'true || { echo "$B\'s prekey serial is malformed"'),
    ('sh/crossbot.sh', 'age -r "$k" < /dev/null > /dev/null 2>&1 ||', 'true ||'),
    ('sh/crossbot.sh', '[ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || cb_refuse "rollback: $B\'s', 'true || cb_refuse "rollback: $B\'s'),
    ('sh/crossbot.sh', '[ "$na" -gt "$(cb_now)" ] || cb_refuse', 'true || cb_refuse'),
    ('sh/crossbot.sh', 'iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || cb_refuse "the body is not UTF-8 text"', 'true || cb_refuse "the body is not UTF-8 text"'),
    ('sh/crossbot.sh', '[ "$sa" -lt $(($(cb_now) - 33*86400)) ]; then      # the server would take it', 'false; then      # the server would take it'),
    ('sh/crossbot.sh', 'revoked | sender_revoked | bad_address | too_large | conflict) cb_failed "$o";', 'revoked | sender_revoked | bad_address | too_large | conflict) ;;&'),
    ('sh/crossbot.sh', 'cb_post "${n%%.*}" "${f%.P}" || rc=1; done', 'cb_post "${n%%.*}" "${f%.P}" || return 1; done'),
    ('sh/crossbot.sh', 'if [ "$(cb_code)" = stale_prekey ]; then', 'if false; then'),
    ('sh/crossbot.sh', 'cb_lock || return 1\n  cb_drain', 'cb_drain'),
    ('sh/crossbot.sh', 'if ! grep -q "^$id " "$CB/seen" 2> /dev/null; then cb_one', 'if true; then cb_one'),
    ('sh/crossbot.sh', '[ "$h" = "$id" ] || { why=', 'true || { why='),
    ('sh/crossbot.sh', 'no_such_mailbox | revoked) rm -f "$CB/peers/$A/identity.json" ;; *) return 1 ;; esac', '*) return 1 ;; esac'),
    ('sh/crossbot.sh', '    3) echo "$why: nothing is judged or acked until this box is fixed" >&2; return 1 ;;\n', ''),
    ('sh/crossbot.sh', 'ssh-keygen -Y verify -f "$CB/peers/$A/signers" -I "$A" -n "crossbot-msg-v1:$B" -s "$m.sig" < "$m.age" > /dev/null 2>&1 ||', 'true ||'),
    ('sh/crossbot.sh', '[ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }', 'true'),
    ('sh/crossbot.sh', 'cb_envcheck "$m.P" "$A" "$B" || return 1', 'true'),
    ('sh/crossbot.sh', '! grep -q "^$h " "$CB/seen" 2> /dev/null || { echo "replay', 'true || { echo "replay'),
    ('sh/crossbot.sh', '! grep -q " $A $(jq -r .msg_id "$m.P")\\$" "$CB/seen" 2> /dev/null || return 2', 'true'),
    ('sh/crossbot.sh', 'iconv -f UTF-8 -t UTF-8 < "$e" > /dev/null 2>&1 || { echo "the envelope is not UTF-8"', 'true || { echo "the envelope is not UTF-8"'),
    ('sh/crossbot.sh', '= "$(jq length "$e" 2> /dev/null)" ] ||', '= "$(jq length "$e" 2> /dev/null)" ] || true ||'),
    ('sh/crossbot.sh', '.from == $a and .to == $b and', ''),
    ('sh/crossbot.sh', 'test("\\\\A[0-9a-f-]{36}\\\\z")', 'test("^[0-9a-f-]{36}$")'),
    ('sh/crossbot.sh', 'and all(.subject, .in_reply_to, .supersedes, .pad; . == null or type == "string")', ''),
    ('sh/crossbot.sh', '[ "$sa" -ge $(($(cb_now) - 33*86400)) ] || { echo "sent_at is older than 33 days', 'true || { echo "sent_at is older than 33 days'),
    ('sh/crossbot.sh', '| gsub("\\u2028"; "\\\\u2028")', ''),
    ('sh/crossbot.sh', '{v: 1, from, to, sent_at, msg_id, body} +', '. +'),
    ('sh/crossbot.sh', 'cb_line "$m.P" > "$CB/inbox/$h.json"', 'cp "$m.P" "$CB/inbox/$h.json"'),
    ('sh/crossbot.sh', 'cb_lock 60 || return 1', 'cb_lock || return 1'),
    ('sh/crossbot.sh', '[ "$s" -ge "$(cat "$CB/serial" 2> /dev/null || echo 0)" ] || cb_refuse "rollback: the server serves', 'true || cb_refuse "rollback: the server serves'),
    ('sh/crossbot.sh', '[ "$(cb_now)" -lt $((na + 33*86400)) ] || rm -f', 'true || rm -f'),
    ('sh/crossbot.sh', '[ "$n" -lt "$top" ] || continue', 'true'),
    ('sh/crossbot.sh', '[.detail, .hint] | map(', '[.hint] | map('),
    ('sh/crossbot.sh', '[ -z "$1" ] || [ "$1" = --no-pq ] || cb_refuse', 'true || cb_refuse'),
    ('sh/crossbot.sh', '[ -s "$CB/address" ] || { cb_refuse "no box in $CB: run init first"; return 1; }', 'true'),
]

ap = argparse.ArgumentParser(description='Show every client check can fail.')
ap.add_argument('indexes', nargs='*', type=int, help='run only these entries')
ap.add_argument('--since', metavar='REF', help='only entries whose file changed since REF')
args = ap.parse_args()
changed = None
if args.since:
    changed = set(subprocess.run(['git', '-C', R, 'diff', '--name-only', args.since, 'HEAD'], capture_output=True, text=True, check=True).stdout.split())

# A copy of HEAD: the checkout, which the server's image also builds from, is never touched.
tmp = tempfile.mkdtemp(prefix='mutate-client-')
W = os.path.join(tmp, 'crossbot-client') + '/'


def cleanup():
    subprocess.run(['git', '-C', R, 'worktree', 'remove', '--force', W], capture_output=True)
    shutil.rmtree(tmp, ignore_errors=True)


atexit.register(cleanup)
subprocess.run(['git', '-C', R, 'worktree', 'add', '--detach', '-q', W, 'HEAD'], check=True)
head = subprocess.run(['git', '-C', R, 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
dirty = subprocess.run(['git', '-C', R, 'status', '--porcelain', '--untracked-files=no'], capture_output=True, text=True).stdout.strip()
print(f'testing HEAD {head}' + (' (the checkout has uncommitted changes, which are not tested)' if dirty else ''), flush=True)

caught = missed = 0
for i, (f, a, b) in enumerate(M):
    if args.indexes and i not in args.indexes:
        continue
    if changed is not None and f not in changed:
        continue
    path = W + f
    src = open(path).read()
    if src.count(a) != 1:
        print(f'{i}: PATTERN COUNT {src.count(a)} in {f}: {a[:60]!r}', flush=True)
        continue
    open(path, 'w').write(src.replace(a, b))
    try:
        r = subprocess.run(['go', 'test', '-count=1', '-failfast', './...'], cwd=W, capture_output=True, text=True, timeout=600)
    finally:
        open(path, 'w').write(src)
    out = r.stdout + r.stderr
    fails = [l.strip() for l in out.splitlines() if l.lstrip().startswith('--- FAIL')]
    if 'build failed' in out or '[setup failed]' in out:
        print(f'{i}: BUILD FAILED {f} {a.strip()[:50]!r}\n{out[-600:]}', flush=True)
    elif r.returncode == 0:
        missed += 1
        print(f'{i}: MISSED  {f} {a.strip()[:70]!r}', flush=True)
    else:
        caught += 1
        print(f'{i}: caught  {f} {a.strip()[:50]!r} -> {", ".join(x.replace("--- FAIL: ", "") for x in fails[:3])}', flush=True)
print(f'caught {caught}, missed {missed}')
