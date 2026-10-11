#!/usr/bin/env bash
# test.sh: irongall.sh against an in-shell fake server that can act as a malicious operator. No server, no network.
#
#   sh/test.sh <empty work dir>          (go test ./sh runs it, in a temporary directory)
#
# Two parts:
#  1. The primitives by hand: identity document → address, the age-encrypted token, JSON+base64 transport, one
#     stanza, a recipient-bound signature, decryption.
#  2. irongall.sh, sourced as an agent would, with only ig_api (curl) replaced by a fake server on files. The fake
#     plays the hostile operator too: forged keys and identities, rollback, expiry, forged, re-signed and replayed
#     mail, a newline-injected sender, a wrong id. And the honest paths: two sends in a row, a retried envelope,
#     renewal with a NEW key, 409 stale_prekey, restore without a token, pagination, the lock, token refresh,
#     deletion of retired prekeys (forward secrecy), the outbox's failures, a fault in the box itself, the
#     optional fields, sent/ and aliases.
# Needs what irongall.sh needs, but curl. KEYTYPE=auto (default: pq if `age-keygen -pq` works, else no-pq, saying
# why) · pq · no-pq. The work dir is left in place after the run.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: test.sh <empty work dir>}; mkdir -p "$W"; W=$(cd "$W" && pwd); cd "$W"
[ -z "$(ls -A "$W")" ] || { echo "$W is not empty"; exit 2; }
KEYTYPE=${KEYTYPE:-auto}
if [ "$KEYTYPE" = auto ]; then
  if age-keygen -pq -o "$W/probe.agekey" > /dev/null 2>&1; then KEYTYPE=pq; else
    KEYTYPE=no-pq; echo "KEYTYPE=auto -> no-pq: age $(age --version) has no -pq (post-quantum needs age >= 1.3)"; fi
  rm -f "$W/probe.agekey"
fi
case "$KEYTYPE" in pq) PQ=-pq; NOPQ= ;; no-pq) PQ=; NOPQ=--no-pq ;; *) echo "KEYTYPE must be auto, pq or no-pq"; exit 2 ;; esac
stanza_of(){ case "$1" in age1pq1*) echo mlkem768x25519 ;; age1*) echo X25519 ;; esac; }
echo "mode: KEYTYPE=$KEYTYPE, age $(age --version)"
PASS=0
ok(){ echo "PASS  $*"; PASS=$((PASS + 1)); }
bad(){ echo "FAIL  $*"; exit 1; }
NA=$(jq -nr 'now + 33*86400 | floor | todate')        # a valid not_after: 33 days out, the maximum

# ===== Part 1: the primitives, by hand =====
for X in A B C; do
  ssh-keygen -q -t ed25519 -N '' -C '' -f $X.sigkey
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 $X.sigkey.pub)" > $X.doc
  sha256sum < $X.doc | cut -c1-64 > $X.addr
  age-keygen $PQ -o $X.agekey 2> /dev/null
  printf 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$(cat $X.addr)" "$(age-keygen -y $X.agekey)" "$NA" > $X.prekey
  ssh-keygen -q -Y sign -n "irongall-prekey-v1:$(cat $X.addr)" -f $X.sigkey < $X.prekey > $X.prekey.sig
done
A=$(cat A.addr); B=$(cat B.addr); C=$(cat C.addr)
echo "address A = $A (${#A} chars); identity document $(wc -c < A.doc) B; prekey statement $(wc -c < A.prekey) B"
c=$(sed -n 2p B.doc | cut -c31); r=q; [ "$c" != q ] || r=p
sed "2s/^\(.\{30\}\)./\1$r/" B.doc > B.doc.tampered
cmp -s B.doc B.doc.tampered && bad "tamper did not change the file"
[ "$(sha256sum < B.doc | cut -c1-64)" = "$B" ] && [ "$(sha256sum < B.doc.tampered | cut -c1-64)" != "$B" ] && ok "identity document hashes to its address; a one-character tamper does not" || bad "identity hash"
printf 'igt1_%s' "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > token.plain    # a random stand-in for a token
age -r "$(sed -n 4p A.prekey)" < token.plain > token.age
age -d -i A.agekey < token.age | cmp -s - token.plain && ok "the owner decrypts its token" || bad "token"
age -d -i C.agekey < token.age > /dev/null 2>&1 && bad "a stranger decrypted the token" || ok "a stranger cannot decrypt the token"
BKEY=$(sed -n 4p B.prekey); STANZA=$(stanza_of "$BKEY")
jq -cn --arg f "$A" --arg t "$B" '{v:1, from:$f, to:$t, sent_at:(now | floor | todate), msg_id:"33333333-2222-4333-8444-555555555555", subject:"t", body:("x" * (10*1024-300))}' > P
age -r "$BKEY" < P > m.age
ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f A.sigkey < m.age > m.age.sig
jq -n --arg f "$A" --arg c "$(base64 < m.age | tr -d '\n')" --arg s "$(base64 < m.age.sig | tr -d '\n')" '{from:$f, prekey_serial:1, ciphertext:$c, signature:$s}' > post.json
echo "plaintext $(wc -c < P) B -> binary age $(wc -c < m.age) B, signature $(wc -c < m.age.sig) B, JSON body $(wc -c < post.json) B"
[ "$(head -c 2000 m.age | grep -a -c '^-> ')" = 1 ] && head -c 2000 m.age | grep -a -q "^-> $STANZA " && ok "exactly one $STANZA stanza (what the server checks)" || bad "stanza type"
jq -r .ciphertext post.json | base64 -d | cmp -s - m.age && jq -r .signature post.json | base64 -d | cmp -s - m.age.sig && ok "ciphertext and signature byte-exact through jq -r | base64 -d" || bad "transport"
jq -n --arg c "$(base64 m.age)" '{c:$c}' | jq -r .c | base64 -d | cmp -s - m.age && ok "line-wrapped base64 still decodes exactly" || bad "wrapped base64"
printf '%s %s\n' "$A" "$(sed -n 2p A.doc)" > A.signers
ssh-keygen -Y verify -f A.signers -I "$A" -n "irongall-msg-v1:$B" -s m.age.sig < m.age > /dev/null 2>&1 && ok "B verifies A's signature" || bad "verify"
ssh-keygen -Y verify -f A.signers -I "$A" -n "irongall-msg-v1:$C" -s m.age.sig < m.age > /dev/null 2>&1 && bad "signature valid for another box" || ok "the signature is invalid for any other recipient"
age -d -i B.agekey < m.age | cmp -s - P && ok "B decrypts, plaintext identical" || bad "decrypt"
age -d -i C.agekey < m.age > /dev/null 2>&1 && bad "C decrypted B's mail" || ok "C cannot decrypt B's mail"

# ===== Part 2: irongall.sh, sourced, against an in-shell fake server =====
set +eu
IRONGALL_HOME=$W/box/none; . "$HERE/irongall.sh"
grep -q '^ig_recv()' "$HERE/irongall.sh" || bad "no functions in irongall.sh"
SRV=$W/srv; mkdir -p $SRV/tmp $SRV/op; MODE=honest
as(){ IG=$W/box/$1; }                          # switch to box $1's state directory
# --- the fake server: the API on files, replacing ig_api (curl) only
srv_err(){ jq -n --argjson st "$1" --arg c "$2" --arg h "$3" '{type:("https://irongall.dev/errors/"+$c), title:$c, status:$st, detail:$h, code:$c, hint:$h}' > "$IG/error.json"; echo "ERROR $1 $2: $3" >&2; return 1; }
srv_tok(){ printf 'igt1_%s' "$(printf 'k1:%s:%s' "$1" "$(cat $SRV/$1/epoch)" | sha256sum | cut -c1-43)"; }
srv_tokenjson(){ jq -n --arg t "$(srv_tok "$1" | age -r "$(sed -n 4p $SRV/$1/prekey.txt)" | base64 | tr -d '\n')" '{token:$t}'; }
srv_state(){ local a=$1 st s; shift; [ -e $SRV/$a/state ] || { srv_err 404 no_such_mailbox "never registered"; return 1; }
  st=$(cat $SRV/$a/state); for s in "$@"; do [ "$st" = "$s" ] && return 0; done
  [ "$st" = revoked ] && { srv_err 410 revoked "revoked"; return 1; }; srv_err 404 no_such_mailbox "the box is $st"; }
srv_auth(){ srv_state "$1" pending active || return 1
  [ "$2" = "$(srv_tok "$1")" ] || { srv_err 401 token_stale "POST /v1/$1/token, decrypt, retry"; return 1; }
  [ "$(cat $SRV/$1/state)" = active ] || echo active > $SRV/$1/state; }      # the first token-authenticated call activates
srv_check(){ # <addr> <identity doc> <statement> <sig> <current serial>: the server's prekey-statement rules
  local s na now; printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > $SRV/tmp/signers
  ssh-keygen -Y verify -f $SRV/tmp/signers -I "$1" -n "irongall-prekey-v1:$1" -s "$4" < "$3" > /dev/null 2>&1 || { srv_err 400 bad_key "the statement is not signed by the identity"; return 1; }
  [ "$(sed -n 1p "$3")" = irongall-prekey-v1 ] && [ "$(sed -n 2p "$3")" = "$1" ] || { srv_err 400 bad_key "the statement must name this address"; return 1; }
  s=$(sed -n 3p "$3"); [ "$s" -gt "$5" ] || { srv_err 409 conflict "the serial must be above $5"; return 1; }
  na=$(jq -n --arg t "$(sed -n 5p "$3")" '$t | fromdateiso8601' 2> /dev/null) || { srv_err 400 bad_key "not_after must be RFC 3339 UTC; never is not allowed"; return 1; }
  now=$(date -u +%s); [ "$na" -gt "$now" ] && [ "$na" -le $((now + 33*86400)) ] || { srv_err 400 bad_key "not_after must be in the future and at most 33 days away"; return 1; }
  if grep -qxF "$(sed -n 4p "$3")" $SRV/$1/keys.used 2> /dev/null; then srv_err 400 bad_key "every prekey must be a NEW key"; return 1; fi; }
srv_install(){ cp $SRV/tmp/pk.txt $SRV/$1/prekey.txt; cp $SRV/tmp/pk.sig $SRV/$1/prekey.sig; sed -n 4p $SRV/tmp/pk.txt >> $SRV/$1/keys.used; }
srv_register(){ local a=$1 f=$2 d=$SRV/$1
  if [ -e $d/state ]; then [ "$(cat $d/state)" = revoked ] && { srv_err 410 revoked "revoked"; return 1; }
    jq -er .identity "$f" | base64 -d > $SRV/tmp/id.doc; jq -er .prekey "$f" | base64 -d > $SRV/tmp/pk.txt; jq -er .prekey_signature "$f" | base64 -d > $SRV/tmp/pk.sig
    cmp -s $SRV/tmp/id.doc $d/identity.doc && cmp -s $SRV/tmp/pk.txt $d/prekey.txt && cmp -s $SRV/tmp/pk.sig $d/prekey.sig && srv_state "$a" pending active && { srv_tokenjson "$a"; return; }   # identical to the CURRENT registration
    srv_err 409 conflict "this address is registered: to replace its prekey, PUT /v1/$a/prekey"; return 1; fi
  jq -er .identity "$f" | base64 -d > $SRV/tmp/id.doc && jq -er .prekey "$f" | base64 -d > $SRV/tmp/pk.txt && jq -er .prekey_signature "$f" | base64 -d > $SRV/tmp/pk.sig || { srv_err 400 bad_request "identity, prekey, prekey_signature"; return 1; }
  [ "$(sha256sum < $SRV/tmp/id.doc | cut -c1-64)" = "$a" ] || { srv_err 400 identity_mismatch "the identity document must hash to the address"; return 1; }
  srv_check "$a" $SRV/tmp/id.doc $SRV/tmp/pk.txt $SRV/tmp/pk.sig 0 || return 1
  mkdir -p $d/msgs $d/dedupe; cp $SRV/tmp/id.doc $d/identity.doc; echo 0 > $d/epoch; echo 0 > $d/seq; echo pending > $d/state
  srv_install "$a"; srv_tokenjson "$a"; }
srv_prekey(){ local a=$1 f=$2 d=$SRV/$1
  srv_state "$a" pending active closed || return 1
  jq -er .prekey "$f" | base64 -d > $SRV/tmp/pk.txt && jq -er .prekey_signature "$f" | base64 -d > $SRV/tmp/pk.sig || { srv_err 400 bad_request "prekey, prekey_signature"; return 1; }
  if cmp -s $SRV/tmp/pk.txt $d/prekey.txt && cmp -s $SRV/tmp/pk.sig $d/prekey.sig; then srv_tokenjson "$a"; return; fi
  srv_check "$a" $d/identity.doc $SRV/tmp/pk.txt $SRV/tmp/pk.sig "$(sed -n 3p $d/prekey.txt)" || return 1
  cp $d/prekey.txt $d/prev.txt; cp $d/prekey.sig $d/prev.sig; srv_install "$a"
  echo $(($(cat $d/epoch) + 1)) > $d/epoch; [ "$(cat $d/state)" = closed ] && echo pending > $d/state; srv_tokenjson "$a"; }
srv_identity(){ local a=$1 d=$SRV/$1 doc txt sig; srv_state "$a" pending active closed || return 1
  doc=$d/identity.doc; txt=$d/prekey.txt; sig=$d/prekey.sig
  if [ -e $SRV/stale-once ] && [ "$(cat $SRV/stale-once)" = "$a" ]; then rm -f $SRV/stale-once; txt=$d/prev.txt; sig=$d/prev.sig; fi
  case "$MODE" in
    "evil-keys $a") awk -v k="$(sed -n 4p $SRV/op/prekey.txt)" 'NR == 4 {$0 = k} 1' $d/prekey.txt > $SRV/tmp/evil.txt; txt=$SRV/tmp/evil.txt ;;  # the operator's age key, the box's signature
    "evil-identity $a") doc=$SRV/op/identity.doc; txt=$SRV/op/stmt.txt; sig=$SRV/op/stmt.sig
      printf 'irongall-prekey-v1\n%s\n99\n%s\n%s\n' "$a" "$(sed -n 4p $SRV/op/prekey.txt)" "$NA" > $txt
      ssh-keygen -q -Y sign -n "irongall-prekey-v1:$a" -f $SRV/op/identity < $txt > $sig ;;
    "rollback $a") txt=$d/prev.txt; sig=$d/prev.sig ;;
    "forged $a") txt=$SRV/forged.txt; sig=$SRV/forged.sig ;;
  esac
  jq -n --arg i "$(base64 < $doc | tr -d '\n')" --arg p "$(base64 < $txt | tr -d '\n')" --arg s "$(base64 < $sig | tr -d '\n')" '{identity:$i, prekey:$p, prekey_signature:$s}'; }
srv_send(){ local b=$1 f=$2 d=$SRV/$1 A ps id now s r
  [ -z "$SEND_FAILS" ] || { srv_err "${SEND_FAILS% *}" "${SEND_FAILS#* }" "set by the test"; return 1; }
  jq -e 'type == "object" and (keys - ["ciphertext","from","prekey_serial","signature"] == []) and (.from|type) == "string" and (.ciphertext|type) == "string" and (.signature|type) == "string"' "$f" > /dev/null || { srv_err 400 bad_request "from, ciphertext, signature and an optional prekey_serial; nothing else"; return 1; }
  srv_state "$b" active || return 1
  A=$(jq -r .from "$f"); [ -e $SRV/$A/state ] && [ "$(cat $SRV/$A/state)" = active ] || { srv_err 403 unknown_sender "register your own box and poll it once"; return 1; }
  [ "$(jq -n --arg t "$(sed -n 5p $d/prekey.txt)" '$t | fromdateiso8601')" -gt "$(date -u +%s)" ] || { srv_err 409 prekey_expired "this box's prekey expired; its owner must publish a new one"; return 1; }
  ps=$(jq -r '.prekey_serial // empty' "$f"); [ -z "$ps" ] || [ "$ps" = "$(sed -n 3p $d/prekey.txt)" ] || { srv_err 409 stale_prekey "a newer prekey exists: GET /v1/$b/identity again"; return 1; }
  jq -r .ciphertext "$f" | base64 -d > $SRV/tmp/c.age; jq -r .signature "$f" | base64 -d > $SRV/tmp/c.sig
  printf '%s %s\n' "$A" "$(sed -n 2p $SRV/$A/identity.doc)" > $SRV/tmp/signers
  ssh-keygen -Y verify -f $SRV/tmp/signers -I "$A" -n "irongall-msg-v1:$b" -s $SRV/tmp/c.sig < $SRV/tmp/c.age > /dev/null 2>&1 || { srv_err 403 bad_signature "sign the ciphertext with your identity, namespace irongall-msg-v1:$b"; return 1; }
  id=$(sha256sum < $SRV/tmp/c.age | cut -c1-64)
  if [ -e $d/dedupe/$id ]; then [ "$(sed -n 1p $d/dedupe/$id)" = "$A" ] && { sed -n 2p $d/dedupe/$id; return 0; }; srv_err 409 conflict "another box already sent this ciphertext"; return 1; fi
  now=$(date -u +%s); s=$(($(cat $d/seq) + 1)); echo $s > $d/seq
  r=$(jq -cn --arg id "$id" --argjson t "$now" '{id:$id, received_at:($t|todate), expires_at:($t + 33*86400 | todate)}')
  printf '%s\n%s\n' "$A" "$r" > $d/dedupe/$id
  jq -n --argjson r "$r" --arg from "$A" --arg c "$(jq -r .ciphertext "$f")" --arg g "$(jq -r .signature "$f")" '$r + {from:$from, ciphertext:$c, signature:$g}' > $d/msgs/$(printf %06d $s)-$id.json
  echo "$r"; }
srv_inject(){ # <box> <from> <c.age> <c.sig> [id]: what a malicious operator can do, put anything in a box
  local d=$SRV/$1 s id=${5:-$(sha256sum < "$3" | cut -c1-64)}; s=$(($(cat $d/seq) + 1)); echo $s > $d/seq
  jq -n --arg id "$id" --arg from "$2" --arg c "$(base64 < "$3" | tr -d '\n')" --arg g "$(base64 < "$4" | tr -d '\n')" --argjson t "$(date -u +%s)" '{id:$id, from:$from, received_at:($t|todate), expires_at:($t + 33*86400 | todate), ciphertext:$c, signature:$g}' > $d/msgs/$(printf %06d $s)-$id.json; }
srv_list(){ local d=$SRV/$1 c=${2#\?cursor=} all page last nc=null x; [ -n "$2" ] || c=0
  all=$(ls $d/msgs | sort); page=$(printf '%s\n' "$all" | awk -F- -v c="$c" 'NF && $1 + 0 > c + 0' | head -n "${PAGE:-50}")
  last=$(printf '%s\n' "$page" | tail -n1 | cut -d- -f1)
  [ -n "$page" ] && [ "$(printf '%s\n' "$all" | awk -F- -v c="$last" 'NF && $1 + 0 > c + 0' | wc -l)" -gt 0 ] && nc="\"$last\""
  for x in $page; do jq -c '{id, from, size:(.ciphertext | length * 3 / 4 | floor), received_at, expires_at}' $d/msgs/$x; done \
    | jq -s --argjson n "$(printf '%s\n' "$all" | awk NF | wc -l)" --argjson nc "$nc" '{count:$n, messages:., next_cursor:$nc, poll_after:60}'; }
srv_fetch(){ local f; f=$(ls $SRV/$1/msgs | grep -- "-$2.json\$" | head -n1); [ -n "$f" ] || { srv_err 404 no_such_message "acked or expired"; return 1; }; jq . $SRV/$1/msgs/$f; }
srv_ack(){ local f; f=$(ls $SRV/$1/msgs | grep -- "-$2.json\$" | head -n1); [ -n "$f" ] || { srv_err 404 no_such_message "acked or expired"; return 1; }; rm -f $SRV/$1/msgs/$f; }
ig_api(){ # the fake: the same contract as irongall.sh's ig_api (METHOD PATH [JSON file] [curl args…]), no network
  local m=$1 p=$2 f=${3-} tok="" a rest; shift 2; [ $# -gt 0 ] && shift
  rm -f "$IG/error.json"; [ "${1-}" = -H ] && tok=${2#Authorization: Bearer }
  a=${p#/v1/}; a=${a%%/*}; a=${a%%\?*}; rest=${p#/v1/$a}; echo "$m $p" >> $SRV/log
  case "$m $rest" in
    "PUT ") srv_register "$a" "$f" ;;
    "GET /identity") srv_identity "$a" ;;
    "POST /token") srv_state "$a" pending active && srv_tokenjson "$a" ;;
    "PUT /prekey") srv_prekey "$a" "$f" ;;
    "POST ") srv_send "$a" "$f" ;;
    "GET /messages/"*) srv_auth "$a" "$tok" && srv_fetch "$a" "${rest#/messages/}" ;;
    "GET /messages"*) srv_auth "$a" "$tok" && srv_list "$a" "${rest#/messages}" ;;
    "DELETE /messages/"*) srv_auth "$a" "$tok" && srv_ack "$a" "${rest#/messages/}" ;;
    *) srv_err 404 not_found "no such route: $m $p" ;;
  esac; }
SEND_FAILS=
# the operator's own keys, for the forging modes
ssh-keygen -q -t ed25519 -N '' -C '' -f $SRV/op/identity; printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 $SRV/op/identity.pub)" > $SRV/op/identity.doc
age-keygen $PQ -o $SRV/op/agekey 2> /dev/null; printf 'x\nx\nx\n%s\n' "$(age-keygen -y $SRV/op/agekey)" > $SRV/op/prekey.txt
forge(){ # <to> <claimed from> <body> → op.age + op.sig: an envelope claiming <claimed from>, encrypted to <to>'s prekey, signed by the OPERATOR
  jq -cn --arg f "$2" --arg t "$1" --arg b "$3" '{v:1, from:$f, to:$t, sent_at:(now | floor | todate), msg_id:"00000000-0000-4000-8000-000000000000", body:$b}' | age -r "$(sed -n 4p $SRV/$1/prekey.txt)" > $SRV/op.age
  ssh-keygen -q -Y sign -n "irongall-msg-v1:$1" -f $SRV/op/identity < $SRV/op.age > $SRV/op.sig; }
seal_as(){ # <from box> <to> <envelope file> → <envelope file>.age + .sig: a genuine message from that box, outside its outbox
  age -r "$(sed -n 4p $SRV/$2/prekey.txt)" < "$3" > "$3.age" && ssh-keygen -q -Y sign -n "irongall-msg-v1:$2" -f $W/box/$1/identity < "$3.age" > "$3.sig"; }
recv(){ if RECV_OUT=$(ig_recv 2> $SRV/recv.err); then RECV_RC=0; else RECV_RC=$?; fi; RECV_ERR=$(cat $SRV/recv.err); }   # → RECV_OUT (accepted envelopes), RECV_ERR, RECV_RC
box_count(){ ls $SRV/$1/msgs | awk NF | wc -l; }

# --- 1. init: keys, registration, activation
as Z; ig_recv 2> err.txt && bad "recv in no box" || grep -q "no box in" err.txt && ok "recv where there is no box says so" || bad "no box: $(cat err.txt)"
for X in A B C D; do as $X; L=$(ig_init $NOPQ) && [ "$L" = "$IG_BASE/to/$(cat $IG/address)" ] || bad "ig_init $X printed $L, not its link"; eval "$X=\$(cat \$IG/address)"; done
as A; [ "$(sha256sum < $IG/identity.doc | cut -c1-64)" = "$A" ] && [ "$(cat $SRV/$A/state)" = active ] && ok "ig_init: the address is the identity's hash, and the first token call activated the box" || bad "init"
[ "$(stat -c %a $IG/identity)" = 600 ] && [ "$(stat -c %a $IG/token)" = 600 ] && [ "$(stat -c %a $IG/prekeys/1.agekey)" = 600 ] && ok "keys and token are 0600 (umask 077)" || bad "file modes"
as A; ig_init $NOPQ > /dev/null && ok "ig_init again: idempotent" || bad "init rerun"
ig_init classic 2> err.txt && bad "an unknown option was taken" || grep -q "unknown option classic" err.txt && ok "an unknown option (the old 'classic') is REFUSED, not taken as post-quantum" || bad "unknown option: $(cat err.txt)"
# --- 2. send, twice in a row, and receive both
as A; printf 'hello B' > body1; printf 'second, "quoted" <tags> & ünïcode\n' > body2
ig_send "$B" body1 && ig_send "$IG_BASE/to/$B" body2 && ok "two sends in a row, the second to B's link" || bad "two sends"
[ "$(ig_addr)" = "$IG_BASE/to/$A" ] && ok "ig_addr prints the box's link" || bad "ig_addr: $(ig_addr)"
for L in "https://elsewhere.example/to/$B" "$IG_BASE.example/to/$B"; do
  ig_send "$L" body1 2> err.txt && bad "sent to $L" || grep -q "a link to another server: this box's server is $IG_BASE" err.txt && ok "a link to another server is REFUSED: $L" || bad "$L: $(cat err.txt)"; done
for L in "$IG_BASE/to/$B/" "$IG_BASE/v1/$B" "$(tr a-f A-F <<< "$B")"; do
  ig_send "$L" body1 2> err.txt && bad "sent to $L" || grep -q "not an address, a link to one, or an alias" err.txt && ok "neither an address, a link to one nor an alias is REFUSED: $L" || bad "$L: $(cat err.txt)"; done
[ "$(ls $SRV/$B/msgs | awk NF | wc -l)" = 2 ] && [ -z "$(ls $IG/outbox | grep -v '^failed$')" ] && ok "no refused destination made mail" || bad "refused destinations made mail: $(ls $IG/outbox)"
cp $SRV/$B/msgs/*.json $SRV/; CAPTURED=$(ls $SRV/*.json | head -n1)      # one genuine A→B message, for the replay and re-sign tests
as B; recv
[ $RECV_RC = 0 ] && [ "$(printf '%s\n' "$RECV_OUT" | awk NF | wc -l)" = 2 ] && printf '%s\n' "$RECV_OUT" | jq -se --arg a "$A" 'map(select(.from == $a)) | map(.body) == ["hello B", "second, \"quoted\" <tags> & ünïcode\n"]' > /dev/null && ok "B receives both, verified and in order, bodies exact" || bad "receive: $RECV_OUT / $RECV_ERR"
[ "$(box_count "$B")" = 0 ] && [ "$(ls $IG/inbox | wc -l)" = 2 ] && ok "both acked, and kept in inbox/" || bad "ack"
[ "$(cat $IG/inbox/*.json | wc -l)" = 0 ] && [ "$(ls $IG/inbox | sed 's/\.json$//' | sort)" = "$(cut -d' ' -f1 $IG/seen | sort)" ] && ok "each inbox/ file is one line, named by the ciphertext hash computed here" || bad "inbox names"
# --- 3. a retried envelope: re-encrypted, so a new ciphertext id, but the same msg_id
as A; jq -cn --arg f "$A" --arg t "$B" '{v:1, from:$f, to:$t, sent_at:(now | floor | todate), msg_id:"11111111-2222-4333-8444-555555555555", body:"once"}' > $IG/outbox/$B.retry.P
ig_seal "$B" $IG/outbox/$B.retry && ig_api POST "/v1/$B" $IG/outbox/$B.retry.json > /dev/null && ig_seal "$B" $IG/outbox/$B.retry && ig_api POST "/v1/$B" $IG/outbox/$B.retry.json > /dev/null || bad "retry setup"
ig_api POST "/v1/$B" $IG/outbox/$B.retry.json > r.json && [ "$(box_count "$B")" = 2 ] && ok "a byte-identical re-POST gets the original receipt, stored once" || bad "dedupe"
rm -f $IG/outbox/$B.retry.*
as B; recv
[ "$(printf '%s\n' "$RECV_OUT" | awk NF | wc -l)" = 1 ] && printf '%s' "$RECV_ERR" | grep -q duplicate && ok "a re-encrypted retry with the same msg_id is delivered ONCE (recipient dedupe on from + msg_id)" || bad "msg_id dedupe: $RECV_OUT / $RECV_ERR"
# --- 4. forged mail: the operator signs as A (A is pinned at B) and also serves its own identity for A
as B; forge "$B" "$A" "PAPAYA"; MODE="evil-identity $A"; srv_inject "$B" "$A" $SRV/op.age $SRV/op.sig; recv; MODE=honest
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "does not verify" && [ "$(box_count "$B")" = 0 ] && cmp -s $IG/peers/$A/identity.doc $SRV/$A/identity.doc && ok "forged reply from a PINNED sender: REFUSED, quarantined, acked; the pin is unchanged" || bad "forged pinned: $RECV_OUT / $RECV_ERR"
# first contact: mail claiming D, whom B has never seen; the operator serves ITS identity for D
as B; forge "$B" "$D" "PAPAYA"; MODE="evil-identity $D"; srv_inject "$B" "$D" $SRV/op.age $SRV/op.sig; recv; MODE=honest
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "does not hash" && [ ! -e $IG/peers/$D/identity.doc ] && ok "first contact, server-forged identity: REFUSED, and nothing pinned" || bad "first contact: $RECV_OUT / $RECV_ERR"
# a newline in from, trying to plant a "*" signer
as B; forge "$B" "$A" "PAPAYA"; srv_inject "$B" "$A"$'\n'"* $(cut -d' ' -f1,2 $SRV/op/identity.pub)" $SRV/op.age $SRV/op.sig; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "not an address" && ! grep -rqs '^\*' $IG/peers && ok "a newline-injected sender is REFUSED and no wildcard signer is written" || bad "newline sender: $RECV_OUT / $RECV_ERR"
# C (a real box) re-signs A's ciphertext as its own
jq -r .ciphertext "$CAPTURED" | base64 -d > resign.age; ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f $W/box/C/identity < resign.age > resign.sig
as B; srv_inject "$B" "$C" resign.age resign.sig "$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)"; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "re-attribution" && ok "A's ciphertext re-signed by C: C's signature verifies, the inner from does not match: REFUSED" || bad "re-sign: $RECV_OUT / $RECV_ERR"
# replay: the operator re-serves A's genuine message, first under its own id, then under a new one
jq -r .signature "$CAPTURED" | base64 -d > replay.sig
as B; srv_inject "$B" "$A" resign.age replay.sig; recv
[ -z "$RECV_OUT" ] && [ -z "$RECV_ERR" ] && [ "$(box_count "$B")" = 0 ] && ok "a replay under an id already handled is only acked again" || bad "replay same id: $RECV_OUT / $RECV_ERR"
srv_inject "$B" "$A" resign.age replay.sig "$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)"; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "replay" && ok "a replay under a NEW id is REFUSED by the seen-set (locally recomputed hash)" || bad "replay new id: $RECV_OUT / $RECV_ERR"
# a genuine new message listed under an id that is not its hash
jq -cn --arg f "$A" --arg t "$B" '{v:1, from:$f, to:$t, sent_at:(now | floor | todate), msg_id:"44444444-2222-4333-8444-555555555555", body:"wrong id"}' > wrongid.P; seal_as A "$B" wrongid.P
as B; srv_inject "$B" "$A" wrongid.P.age wrongid.P.sig "$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)"; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "not the SHA-256 of its ciphertext" && ok "a genuine message under an id that is not its hash: REFUSED" || bad "wrong id: $RECV_OUT / $RECV_ERR"
# a stale sent_at: older than the 33-day window
jq -cn --arg f "$A" --arg t "$B" '{v:1, from:$f, to:$t, sent_at:(now - 34*86400 | floor | todate), msg_id:"22222222-2222-4333-8444-555555555555", body:"old"}' > old.P; seal_as A "$B" old.P
as B; srv_inject "$B" "$A" old.P.age old.P.sig; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "older than 33 days" && ok "sent_at older than 33 days: REFUSED" || bad "stale: $RECV_OUT / $RECV_ERR"
# a key twice: jq would take the second from, another reader the first
printf '{"v":1,"from":"%s","from":"%s","to":"%s","sent_at":"%s","msg_id":"55555555-2222-4333-8444-555555555555","body":"twice"}' "$C" "$A" "$B" "$(jq -nr 'now | floor | todate')" > dup.P; seal_as A "$B" dup.P
as B; srv_inject "$B" "$A" dup.P.age dup.P.sig; recv
[ -z "$RECV_OUT" ] && printf '%s' "$RECV_ERR" | grep -q "no key twice" && ok "an envelope with a key twice: REFUSED" || bad "duplicate key: $RECV_OUT / $RECV_ERR"
[ "$(ls $IG/quarantine | wc -l)" = 7 ] && [ "$(ls $IG/inbox | wc -l)" = 3 ] && ok "every refusal quarantined, never delivered: 7 quarantined (the two refusals of A's ciphertext share its hash), 3 delivered" || bad "quarantine count $(ls $IG/quarantine | wc -l)"
# a body with the line breaks some readers split on, raw: still one line, the same body
as A; printf 'a\302\205b\342\200\250c\342\200\251d' > seps; ig_send "$B" seps || bad "send seps"
as B; recv
[ "$(printf '%s' "$RECV_OUT" | wc -l)" = 0 ] && ! printf '%s' "$RECV_OUT" | LC_ALL=C grep -q $'\xc2\x85\|\xe2\x80\xa8\|\xe2\x80\xa9' && [ "$(printf '%s' "$RECV_OUT" | jq -r .body)" = "$(cat $W/seps)" ] && ok "U+0085, U+2028 and U+2029 in a body are escaped: one line, the same body" || bad "separators: $RECV_OUT"
# --- 5. the sender's checks: nothing is encrypted unless every one passes
as A; printf 'secret' > body3; n0=$(grep -c "^POST /v1/$B\$" $SRV/log)
MODE="evil-keys $B"; ig_send "$B" body3 2> err.txt || true; MODE=honest
grep -q "not signed by its identity" err.txt && [ "$(grep -c "^POST /v1/$B\$" $SRV/log)" = "$n0" ] && ok "the operator swaps B's prekey: REFUSED, nothing encrypted or sent" || bad "evil-keys: $(cat err.txt)"
ls $IG/outbox/*.json > /dev/null 2>&1 && bad "a ciphertext was left in the outbox" || ok "no ciphertext to the swapped key exists"
rm -f $IG/outbox/*.P                                                    # the refused message is abandoned
printf 'bad \377 byte' > badbody; ig_send "$B" badbody 2> err.txt
grep -q "not UTF-8" err.txt && [ "$(grep -c "^POST /v1/$B\$" $SRV/log)" = "$n0" ] && ! ls $IG/outbox/*.P > /dev/null 2>&1 && ok "a body that is not UTF-8 is REFUSED before anything is built or sent" || bad "non-UTF-8 body: $(cat err.txt)"
as D; MODE="evil-identity $B"; ig_send "$B" $W/body3 2> $W/err.txt || true; MODE=honest; rm -f $IG/outbox/*.P
grep -q "does not hash" $W/err.txt && [ ! -e $IG/peers/$B/identity.doc ] && ok "first contact, server-forged identity for the recipient: REFUSED" || bad "send first contact: $(cat $W/err.txt)"
# a key holder's PADDED identity document: it hashes to its own address, and a lenient server (this fake checks only the hash) accepts it
ssh-keygen -q -t ed25519 -N '' -C '' -f E.sigkey; printf 'irongall-v1\n%s\n \n' "$(cut -d' ' -f1,2 E.sigkey.pub)" > E.doc; EA=$(sha256sum < E.doc | cut -c1-64)
age-keygen $PQ -o E.agekey 2> /dev/null; printf 'irongall-prekey-v1\n%s\n1\n%s\n%s\n' "$EA" "$(age-keygen -y E.agekey)" "$NA" > E.prekey
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$EA" -f E.sigkey < E.prekey > E.prekey.sig
as A; jq -n --arg i "$(ig_b64 E.doc)" --arg p "$(ig_b64 E.prekey)" --arg s "$(ig_b64 E.prekey.sig)" '{identity:$i, prekey:$p, prekey_signature:$s}' > E.json
ig_api PUT "/v1/$EA" E.json > /dev/null && echo active > $SRV/$EA/state || bad "padded registration setup"
ig_send "$EA" body3 2> err.txt || true; rm -f $IG/outbox/*.P
grep -q "93-byte" err.txt && [ "$(grep -c "^POST /v1/$EA\$" $SRV/log)" = 0 ] && [ ! -e $IG/peers/$EA/identity.doc ] && ok "a padded identity document that hashes to its own address is REFUSED: one key never gets a second address" || bad "padded identity: $(cat err.txt)"
as A; printf 'irongall-prekey-v1\n%s\n9\n%s\n2020-01-01T00:00:00Z\n' "$B" "$(sed -n 4p $SRV/$B/prekey.txt)" > $SRV/forged.txt
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$B" -f $W/box/B/identity < $SRV/forged.txt > $SRV/forged.sig
MODE="forged $B"; ig_send "$B" body3 2> err.txt || true; MODE=honest; rm -f $IG/outbox/*.P
grep -q "expired" err.txt && [ "$(cat $IG/peers/$B/serial)" = 1 ] && ok "an expired prekey, validly signed, higher serial: REFUSED, and its serial is not recorded" || bad "expired: $(cat err.txt)"
printf 'irongall-prekey-v1\n%s\n9\n%s\nnever\n' "$B" "$(sed -n 4p $SRV/$B/prekey.txt)" > $SRV/forged.txt
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$B" -f $W/box/B/identity < $SRV/forged.txt > $SRV/forged.sig
MODE="forged $B"; ig_send "$B" body3 2> err.txt || true; MODE=honest; rm -f $IG/outbox/*.P
grep -q "no valid not_after" err.txt && ok "a not_after of never: REFUSED by senders too" || bad "never: $(cat err.txt)"
# --- 6. the outbox: an entry that can never go moves to outbox/failed/; one that may yet go stays; flush tries them all
as A; SEND_FAILS="410 revoked"; ig_send "$B" body3 2> err.txt; SEND_FAILS=
grep -q "outbox/failed" err.txt && [ "$(ls $IG/outbox/failed/*.P | wc -l)" = 1 ] && ! ls $IG/outbox/*.P > /dev/null 2>&1 && ok "refused for good (revoked): moved to outbox/failed/" || bad "revoked: $(cat err.txt)"
SEND_FAILS="503 unavailable"; ig_send "$B" body3 2> err.txt; ig_send "$C" body3 2>> err.txt; SEND_FAILS=
[ "$(ls $IG/outbox/*.P | wc -l)" = 2 ] && grep -q "kept in the outbox" err.txt && ok "a transient failure keeps the entry in the outbox" || bad "transient: $(cat err.txt)"
first=$(ls $IG/outbox/*.P | head -n1); first=${first%.P}; last=$(basename "$(ls $IG/outbox/*.P | tail -n1)"); last=${last%%.*}
n0=$(box_count "$last"); cp $first.json held.json; printf 'not json' > $first.json      # the entry flush tries first now fails
ig_flush 2> err.txt && bad "flush reported success over a bad entry"; cp held.json $first.json
[ "$(box_count "$last")" = $((n0 + 1)) ] && ok "flush tries every entry: one that fails does not stop the next" || bad "flush stopped: $(cat err.txt)"
ig_flush 2> err.txt && [ $(($(box_count "$B") + $(box_count "$C"))) = 2 ] && ! ls $IG/outbox/*.P > /dev/null 2>&1 && ok "flush delivers what is left, once" || bad "flush: $(cat err.txt)"
as B; recv; as C; recv
jq -cn --arg f "$A" --arg t "$B" '{v:1, from:$f, to:$t, sent_at:(now - 33*86400 - 60 | floor | todate), msg_id:"66666666-2222-4333-8444-555555555555", body:"stuck"}' > $W/box/A/outbox/$B.stuck.P
as A; ig_flush 2> err.txt
grep -q "older than 33 days" err.txt && [ "$(box_count "$B")" = 0 ] && [ -e $IG/outbox/failed/$B.stuck.P ] && ok "an entry older than 33 days is never posted: moved to outbox/failed/" || bad "stuck: $(cat err.txt)"
# --- 7. the server's prekey rules
as B; printf 'irongall-prekey-v1\n%s\n5\n%s\nnever\n' "$B" "$(age-keygen -y $IG/prekeys/1.agekey)" > never.txt
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$B" -f $IG/identity < never.txt > never.sig
jq -n --arg p "$(ig_b64 never.txt)" --arg g "$(ig_b64 never.sig)" '{prekey:$p, prekey_signature:$g}' > never.json
ig_api PUT "/v1/$B/prekey" never.json > /dev/null 2>&1 && bad "never accepted" || [ "$(jq -r .code $IG/error.json)" = bad_key ] && ok "the server refuses not_after never (bad_key)" || bad "never code"
age-keygen $PQ -o far.agekey 2> /dev/null; printf 'irongall-prekey-v1\n%s\n5\n%s\n%s\n' "$B" "$(age-keygen -y far.agekey)" "$(jq -nr 'now + 40*86400 | floor | todate')" > far.txt
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$B" -f $IG/identity < far.txt > far.sig
jq -n --arg p "$(ig_b64 far.txt)" --arg g "$(ig_b64 far.sig)" '{prekey:$p, prekey_signature:$g}' > far.json
ig_api PUT "/v1/$B/prekey" far.json > /dev/null 2>&1 && bad "40 days accepted" || ok "the server refuses a not_after more than 33 days away"
printf 'irongall-prekey-v1\n%s\n5\n%s\n%s\n' "$B" "$(age-keygen -y $IG/prekeys/1.agekey)" "$NA" > same.txt
ssh-keygen -q -Y sign -n "irongall-prekey-v1:$B" -f $IG/identity < same.txt > same.sig
jq -n --arg p "$(ig_b64 same.txt)" --arg g "$(ig_b64 same.sig)" '{prekey:$p, prekey_signature:$g}' > same.json
ig_api PUT "/v1/$B/prekey" same.json > /dev/null 2>&1 && bad "re-signed key accepted" || ok "the server refuses a renewal that re-signs the SAME key: every renewal is a new key"
# --- 8. renewal: a NEW key, serial 2; the epoch bumps; senders move on; rollback refused; 409 stale_prekey
as B; OLD_TOKEN=$(cat $IG/token); cp $IG/prekeys/1.agekey key1.agekey
ig_rekey $NOPQ && [ "$(sed -n 3p $SRV/$B/prekey.txt)" = 2 ] && [ "$(cat $IG/token)" != "$OLD_TOKEN" ] && [ "$(cat $IG/serial)" = 2 ] && ok "ig_rekey: serial 2, a new key, a new token (the epoch bumped), and the box records serial 2" || bad "rekey"
[ "$(sed -n 4p $SRV/$B/prekey.txt)" != "$(age-keygen -y $IG/prekeys/1.agekey)" ] && ok "the renewed prekey is a different key" || bad "same key"
as A; printf 'after rotation' > body4; ig_send "$B" body4 && [ "$(cat $IG/peers/$B/serial)" = 2 ] && ok "A sends to serial 2; the address did not move" || bad "send after rekey"
as B; recv; printf '%s' "$RECV_OUT" | jq -e '.body == "after rotation"' > /dev/null && ok "B decrypts it" || bad "recv after rekey: $RECV_OUT / $RECV_ERR"
as A; MODE="rollback $B"; ig_send "$B" body3 2> err.txt || true; MODE=honest; rm -f $IG/outbox/*.P
grep -q "rollback" err.txt && ok "rollback: B's genuine serial-1 statement is REFUSED once serial 2 was seen" || bad "rollback: $(cat err.txt)"
as B; n0=$(grep -c "^PUT /v1/$B/prekey\$" $SRV/log); MODE="rollback $B"; ig_rekey $NOPQ 2> err.txt; MODE=honest
grep -q "rollback" err.txt && [ "$(grep -c "^PUT /v1/$B/prekey\$" $SRV/log)" = "$n0" ] && ok "rollback of the box's own prekey: ig_rekey refuses, publishes nothing" || bad "own rollback: $(cat err.txt)"
as C; echo "$B" > $SRV/stale-once; printf 'via a stale cache' > $W/body5
ig_send "$B" $W/body5 2> $W/err.txt && grep -q stale_prekey $W/err.txt && [ "$(cat $IG/peers/$B/serial)" = 2 ] && ok "a sender handed serial 1 gets 409 stale_prekey and re-encrypts the SAME envelope to serial 2" || bad "stale_prekey: $(cat $W/err.txt)"
as B; recv; printf '%s' "$RECV_OUT" | jq -e '.body == "via a stale cache"' > /dev/null && ok "and B receives it once" || bad "stale recv: $RECV_OUT / $RECV_ERR"
IG=$W/box/B; ig_api GET "/v1/$B/messages" "" -H "Authorization: Bearer $OLD_TOKEN" > /dev/null 2>&1 && bad "old token accepted" || [ "$(jq -r .code $IG/error.json)" = token_stale ] && ok "the token from before the renewal is dead (token_stale)" || bad "old token code"
# --- 9. forward secrecy: a retired prekey is deleted at its not_after + 33 days, then its mail is unrecoverable
as B; age -d -i key1.agekey < resign.age > /dev/null && age -d -i $IG/prekeys/1.agekey < resign.age > /dev/null && ok "control: mail to the retired key decrypts while it is retained" || bad "retained"
sed -i "5s/.*/$(jq -nr 'now - 34*86400 | floor | todate')/" $IG/prekeys/1.txt     # pretend its not_after was 34 days ago
ig_prune; [ ! -e $IG/prekeys/1.agekey ] && [ -e $IG/prekeys/2.agekey ] && ok "ig_prune deletes the retired key past not_after + 33 days, keeps the current one" || bad "prune"
age -d -i $IG/prekeys/2.agekey < resign.age > /dev/null 2>&1 && bad "old mail still decryptable" || ok "after deletion, mail to the retired key is unrecoverable from the box's keys"
cp $IG/prekeys/2.txt held2.txt; sed -i "5s/.*/$(jq -nr 'now - 34*86400 | floor | todate')/" $IG/prekeys/2.txt
ig_prune; [ -e $IG/prekeys/2.agekey ] && ok "ig_prune never deletes the newest key, even past its deletion time: it decrypts the box's token" || bad "prune deleted the newest key"
cp held2.txt $IG/prekeys/2.txt
# --- 10. restore without a token or prekeys: the identity alone renews the prekey
as B; rm -f $W/box/B/prekeys/* $W/box/B/token
ig_rekey $NOPQ && [ "$(sed -n 3p $SRV/$B/prekey.txt)" = 3 ] && [ -s $IG/token ] && ok "lost prekeys and token: ig_rekey with the identity alone publishes serial 3 and recovers a token" || bad "restore"
as A; printf 'after restore' > body6; ig_send "$B" body6 && as B && recv && printf '%s' "$RECV_OUT" | jq -e '.body == "after restore"' > /dev/null && ok "mail flows again after the restore" || bad "after restore: $RECV_OUT / $RECV_ERR"
# --- 11. pagination, token refresh, the lock, a sender with no box, a fault in the box itself
as A; for i in 1 2 3; do printf 'page %s' $i > p$i; ig_send "$B" p$i || bad "send p$i"; done
as B; echo igt1_stale > $IG/token; PAGE=2; recv; PAGE=50
[ "$(printf '%s\n' "$RECV_OUT" | awk NF | wc -l)" = 3 ] && [ "$(box_count "$B")" = 0 ] && ok "pages of 2: ig_recv follows next_cursor and drains all 3; a stale token was refreshed on the way" || bad "pagination: $RECV_OUT / $RECV_ERR"
as B; mkdir $IG/lock; ig_recv 2> err.txt && bad "second consumer ran" || grep -q "one consumer per box" err.txt && ok "a second consumer is refused while the lock is held" || bad "lock"
(sleep 2; rmdir $IG/lock) & ig_rekey $NOPQ 2> err.txt && [ "$(sed -n 3p $SRV/$B/prekey.txt)" = 4 ] && ok "ig_rekey waits for a drain's lock, then renews" || bad "rekey under the lock: $(cat err.txt)"
wait
ssh-keygen -q -t ed25519 -N '' -C '' -f G.sigkey; printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 G.sigkey.pub)" > G.doc; G=$(sha256sum < G.doc | cut -c1-64)
forge "$B" "$G" "from a box that is gone"; as B; srv_inject "$B" "$G" $SRV/op.age $SRV/op.sig; recv
[ $RECV_RC = 0 ] && [ "$(box_count "$B")" = 0 ] && printf '%s' "$RECV_ERR" | grep -q "no identity for $G" && ok "mail from an address with no box is REFUSED, and does not stall the drain" || bad "no such sender: $RECV_RC $RECV_OUT / $RECV_ERR"
as A; printf 'kept' > body7; ig_send "$B" body7 || bad "send body7"
ls $W/box/B/quarantine > $W/quarantine.before
as B; mkdir $W/held; mv $IG/prekeys/*.agekey $W/held/; recv; mv $W/held/*.agekey $IG/prekeys/
[ $RECV_RC != 0 ] && [ "$(box_count "$B")" = 1 ] && ls $IG/quarantine | diff -q - $W/quarantine.before > /dev/null && printf '%s' "$RECV_ERR" | grep -q "no prekeys" && ok "a fault in the box itself (its prekeys gone) stops the drain: nothing judged, nothing acked" || bad "local fault: $RECV_RC / $RECV_ERR"
recv; printf '%s' "$RECV_OUT" | jq -e '.body == "kept"' > /dev/null && [ "$(box_count "$B")" = 0 ] && ok "once fixed, the next drain delivers it" || bad "after the fault: $RECV_OUT / $RECV_ERR"
# --- 12. the optional fields, sent/, and aliases
as A; printf 'the answer' > body8; R=11111111-2222-4333-8444-555555555555; S=22222222-2222-4333-8444-555555555555
ig_send --subject "re: yours" --reply-to $R --supersedes $S "$B" body8 || bad "send with options"
as B; recv
printf '%s' "$RECV_OUT" | jq -e --arg r $R --arg s $S '.subject == "re: yours" and .in_reply_to == $r and .supersedes == $s and .body == "the answer"' > /dev/null && ok "--subject, --reply-to and --supersedes reach the recipient, in the line it delivers" || bad "options: $RECV_OUT / $RECV_ERR"
as A; n0=$(grep -c "^POST /v1/$B\$" $SRV/log)
ig_send --reply-to "$B" "$B" body8 2> err.txt && bad "a 64-character id was taken as a msg_id"; grep -q "not a msg_id" err.txt || bad "not a msg_id: $(cat err.txt)"
ig_send --supersedes 2> err.txt && bad "an option with no value was taken"; grep -q "needs a value" err.txt || bad "no value: $(cat err.txt)"
ig_send --urgent yes "$B" body8 2> err.txt && bad "an unknown option was taken"; grep -q "unknown option --urgent" err.txt || bad "unknown option: $(cat err.txt)"
printf 'bad \377 subject' > badsubject; ig_send --subject "$(cat badsubject)" "$B" body8 2> err.txt && bad "a subject that is not UTF-8 was taken"; grep -q "not UTF-8" err.txt || bad "subject: $(cat err.txt)"
[ "$(grep -c "^POST /v1/$B\$" $SRV/log)" = "$n0" ] && ! ls $IG/outbox/*.P > /dev/null 2>&1 && ok "a --reply-to that is not a msg_id, an option with no value, an unknown option and a subject that is not UTF-8 are REFUSED before anything is built" || bad "a refused option made mail"
for f in $IG/sent/*.json; do
  [ "$(wc -l < "$f")" = 0 ] && [ "$(stat -c %a "$f")" = 600 ] && jq -e --arg n "$(basename "$f" .json)" --arg a "$A" '.to + "." + .msg_id == $n and .from == $a' "$f" > /dev/null || bad "sent/ entry $f"
  [ "$(sed -n 2p "$SRV/$(jq -r .to "$f")/dedupe/$(jq -r .receipt.id "$f")")" = "$(jq -c .receipt "$f")" ] || bad "the receipt in $f is not the server's"
done
ok "sent/ keeps every message the server took: one line each, named <address>.<msg_id>, with the server's receipt"
f=$(grep -l '"subject":"re: yours"' $IG/sent/*.json); [ "$(jq -c 'del(.receipt)' "$f")" = "$(jq -c . $W/box/B/inbox/$(jq -r .receipt.id "$f").json)" ] && ok "a sent line is the line its recipient delivered, plus the receipt" || bad "sent line: $(cat "$f")"
for p in $IG/outbox/failed/*.P; do [ ! -e "$IG/sent/$(basename "$p" .P).json" ] || bad "a message refused for good is in sent/: $p"; done; ok "a message that never went is not in sent/"
as A; [ "$(ig_alias bob "$IG_BASE/to/$B")" = "bob $B" ] && [ "$(ig_alias)" = "bob $B" ] && [ "$(stat -c %a $IG/aliases)" = 600 ] && ok "ig_alias names a peer for this box, in a 0600 file, and lists it" || bad "alias"
printf 'to bob' > body9; ig_send bob body9 || bad "send to an alias"
as B; recv; printf '%s' "$RECV_OUT" | jq -e --arg a "$A" '.body == "to bob" and .from == $a' > /dev/null && ok "ig_send takes the alias" || bad "alias send: $RECV_OUT / $RECV_ERR"
as A; n0=$(grep -c "^POST " $SRV/log)
ig_alias bob "$C" 2> err.txt && bad "an alias was moved"; grep -q "already names $B" err.txt && [ "$(ig_alias bob "$B")" = "bob $B" ] && [ "$(wc -l < $IG/aliases)" = 1 ] && ok "a name is never moved to another address, and naming the same one again adds nothing" || bad "alias moved: $(cat err.txt)"
for N in Bob "" -x "$B" "$IG_BASE/to/$B" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; do ig_alias "$N" "$B" 2> err.txt && bad "named '$N'"; grep -q "not an alias" err.txt || bad "name '$N': $(cat err.txt)"; done
[ "$(wc -l < $IG/aliases)" = 1 ] && ok "a name that is not 1 to 32 of a-z, 0-9, '.', '_' and '-' is REFUSED: never an address, never a link" || bad "a bad name was written"
ig_send carol body9 2> err.txt && bad "sent to an alias nobody made"; grep -q "no alias named carol" err.txt && ok "an alias nobody made is REFUSED" || bad "carol: $(cat err.txt)"
echo "bob $C" >> $IG/aliases; ig_send bob body9 2> err.txt && bad "sent to a name with two addresses"; sed -i '$d' $IG/aliases
grep -q "an alias naming one address" err.txt && [ "$(grep -c "^POST " $SRV/log)" = "$n0" ] && ! ls $IG/outbox/*.P > /dev/null 2>&1 && ok "a name with two addresses names neither, and no refused alias made mail" || bad "two addresses: $(cat err.txt)"
echo "--- $PASS PASS, 0 FAIL (KEYTYPE=$KEYTYPE)"
