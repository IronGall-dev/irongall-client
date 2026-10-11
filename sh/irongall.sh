#!/usr/bin/env bash
# irongall.sh: the irongall client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol, checks and on-disk box as the Go client in this repo, so either can run a box. It fails CLOSED:
# a failed check prints one "REFUSED: <reason>" line and stops, and every API error prints its code and hint.
# Get it from https://github.com/IronGall-dev/irongall-client at a commit you have read, never from the irongall.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash irongall.sh init [--no-pq]                  make and register this box; prints its link, $IG_BASE/to/<address>
#   bash irongall.sh addr                            print it again: give it to whoever should write to this box
#   bash irongall.sh send <link> [body file]         one message (the body from stdin without a file); a bare address works too
#   bash irongall.sh flush                           retry what is still in outbox/
#   bash irongall.sh recv                            verified mail only, one JSON line each; refused mail goes to quarantine/
#   bash irongall.sh rekey [--no-pq]                 a new prekey: at least monthly, as a prekey is valid for 33 days
#
# Or source it at the top of every shell call and call the ig_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, there is no MCP server, and
# each step runs several programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches --no-pq boxes only), OpenSSH
# >= 8.1, curl >= 7.76, jq >= 1.6, iconv, and coreutils (sha256sum, base64, od, sync).

# recipe: setup
set -o pipefail; umask 077
IG_BASE=${IG_BASE:-https://irongall.dev}
IG=${IRONGALL_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/irongall/${IRONGALL_BOX:-default}}   # one box per directory; never the working directory
ig_refuse(){ printf 'REFUSED: %s\n' "$*" >&2; return 1; }
ig_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
ig_b64(){ base64 < "$1" | tr -d '\n'; }
ig_now(){ date -u +%s; }   # the one clock every check reads
ig_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
ig_api(){ # <METHOD> <PATH> [JSON file] [curl args…] → the body on stdout. Any non-2xx: prints its code, detail (the limit hit, the seconds to wait) and hint, keeps it in $IG/error.json, returns 1
  local m=$1 p=$2 f=${3-}; shift 2; [ $# -gt 0 ] && shift
  rm -f "$IG/error.json"
  curl -sS --max-time 60 --fail-with-body -X "$m" ${f:+-H 'Content-Type: application/json' --data-binary "@$f"} "$@" "$IG_BASE$p" > "$IG/response.json" && { cat "$IG/response.json"; return 0; }
  mv "$IG/response.json" "$IG/error.json"; jq -r '"ERROR \(.status) \(.code): \([.detail, .hint] | map(select(. != null and . != "")) | join("; "))"' "$IG/error.json" >&2 2> /dev/null || cat "$IG/error.json" >&2; return 1
}
ig_code(){ jq -r .code "$IG/error.json" 2> /dev/null; }   # the code of the last API error
ig_opt(){ [ -z "$1" ] || [ "$1" = --no-pq ] || ig_refuse "unknown option $1: the only one is --no-pq (no post-quantum encryption, X25519 only)"; }
ig_owner(){ # ig_api as this box's owner: adds the token; on 401 token_stale, fetches the current token and retries once
  ig_api "$1" "$2" "${3-}" -H "Authorization: Bearer $(cat "$IG/token")" && return 0
  [ "$(ig_code)" = token_stale ] || return 1
  ig_api POST "/v1/$(cat "$IG/address")/token" > "$IG/token.json" && ig_token "$IG/token.json" || return 1
  ig_api "$1" "$2" "${3-}" -H "Authorization: Bearer $(cat "$IG/token")"
}
ig_token(){ # <response file> → $IG/token, decrypted with this box's prekeys
  local ids=() k; for k in "$IG"/prekeys/*.agekey; do [ -e "$k" ] && ids+=(-i "$k"); done
  jq -er .token "$1" | base64 -d | age -d "${ids[@]}" > "$IG/token.new" && mv "$IG/token.new" "$IG/token" || ig_refuse "the response's token is missing or does not decrypt with this box's prekeys"
}
ig_lock(){ # [seconds] → takes $IG/lock, one consumer per box, waiting up to that long while another holds it
  local end=$((SECONDS + ${1:-0}))
  [ -s "$IG/address" ] || { ig_refuse "no box in $IG: run init first"; return 1; }
  until mkdir "$IG/lock" 2> /dev/null; do
    [ "$SECONDS" -lt "$end" ] || { ig_refuse "another consumer holds $IG/lock: one consumer per box (remove it if stale)"; return 1; }
    sleep 1
  done
}

# recipe: keys and registration
ig_prekey(){ # <serial> [--no-pq] → prekeys/<serial>.agekey and its signed statement: a NEW key, valid for 33 days. A re-run reuses the key a failed attempt left, whatever its type
  local A p="$IG/prekeys/$1"; A=$(cat "$IG/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  if [ ! -e "$p.agekey" ]; then if [ "${2-}" = --no-pq ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null || ig_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a box with --no-pq)" || return 1; fi
  printf 'irongall-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$(age-keygen -y "$p.agekey")" "$(jq -nr --argjson t "$(ig_now)" '$t + 33*86400 | todate')" > "$p.txt" &&
  ssh-keygen -q -Y sign -n "irongall-prekey-v1:$A" -f "$IG/identity" < "$p.txt" > "$p.txt.sig"      # stdin to stdout: never a stale .sig
}
ig_init(){ # [--no-pq] → creates this box, or finishes a half-done init; registers and activates it; prints its link
  ig_opt "${1-}" || return 1
  mkdir -p "$IG/prekeys" "$IG/peers" "$IG/inbox" "$IG/quarantine" "$IG/outbox" && printf '*\n' > "$IG/.gitignore" || return 1
  [ -e "$IG/identity" ] || ssh-keygen -q -t ed25519 -N '' -C '' -f "$IG/identity" < /dev/null || return 1
  printf 'irongall-v1\n%s\n' "$(cut -d' ' -f1,2 "$IG/identity.pub")" > "$IG/identity.doc"
  sha256sum < "$IG/identity.doc" | cut -c1-64 > "$IG/address" && ig_prekey 1 "${1-}" || return 1
  local A p="$IG/prekeys/1"; A=$(cat "$IG/address")
  if [ ! -s "$IG/token" ]; then
    jq -n --arg i "$(ig_b64 "$IG/identity.doc")" --arg p "$(ig_b64 "$p.txt")" --arg s "$(ig_b64 "$p.txt.sig")" '{identity:$i, prekey:$p, prekey_signature:$s}' > "$IG/register.json"
    ig_api PUT "/v1/$A" "$IG/register.json" > "$IG/token.json" && ig_token "$IG/token.json" || return 1
  fi
  ig_owner GET "/v1/$A/messages" > /dev/null && ig_addr      # the first token-authenticated call ACTIVATES the box
}
ig_addr(){ local a; a=$(cat "$IG/address") && echo "$IG_BASE/to/$a"; }      # the box's link: what to give whoever should write to it
ig_dest(){ # <link or address> → the address: 64 hex, or taken from a link to this box's server, $IG_BASE/to/<address>
  local a=${1#"$IG_BASE/to/"}
  ig_hex "$a" && { echo "$a"; return 0; }
  [[ $1 != *://* || $1 = "$IG_BASE/"* ]] || { ig_refuse "a link to another server: this box's server is $IG_BASE"; return 1; }
  ig_refuse "not an address, or a link to one: $1"
}

# recipe: verify a peer
ig_idcheck(){ # <identity document> [address] → 0 only for exactly the 93-byte two-line document, its Ed25519 key canonical and not of small order (and hashing to the address, given one)
  local f=$1 k
  [ "$(wc -c < "$f")" -eq 93 ] && [ "$(sed -n 1p "$f")" = irongall-v1 ] && sed -n 2p "$f" | grep -Eqx 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}' || return 1
  [ -z "${2-}" ] || [ "$(sha256sum < "$f" | cut -c1-64)" = "$2" ] || return 1
  k=$(sed -n 2p "$f" | cut -d' ' -f2 | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')
  [[ ! $k =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1      # y >= p: not canonical
  case $k in      # the eight points of small order, and the two with x = 0 marked negative
    0100000000000000000000000000000000000000000000000000000000000000 | 0100000000000000000000000000000000000000000000000000000000000080 | \
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f | ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | \
    0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000080 | \
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 | 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 | \
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a | c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;
  esac
}
ig_pin(){ # <address> <identity response> → peers/<address>/signers from the PINNED identity: hash-checked at first contact, and a pin always wins
  local B=$1 d="$IG/peers/$1" f="$IG/peers/$1/identity.doc"
  ig_hex "$B" || ig_refuse "not an address: $B" || return 1
  if [ ! -e "$f" ]; then
    f="$d/new.doc"; mkdir -p "$d" && jq -er .identity "$2" 2> /dev/null | base64 -d > "$f" 2> /dev/null || ig_refuse "no identity for $B in the response" || return 1
    [ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || ig_refuse "the identity the server sent does not hash to $B" || return 1
  fi
  ig_idcheck "$f" || ig_refuse "$B's identity is not exactly the 93-byte two-line document with a valid Ed25519 key" || return 1
  [ "$f" = "$d/identity.doc" ] || mv "$f" "$d/identity.doc" || return 1
  printf '%s %s\n' "$B" "$(sed -n 2p "$d/identity.doc")" > "$d/signers"      # exactly one line, from checked bytes, never from server text
}
ig_prekeycheck(){ # <statement> <signature> <address> <signers file> → "<serial> <age recipient> <not_after as Unix time>" only for five LF-ended lines naming that address, signed by its identity, holding a key age will encrypt to; otherwise the reason, and 1
  local p=$1 B=$3 s k na
  ssh-keygen -Y verify -f "$4" -I "$B" -n "irongall-prekey-v1:$B" -s "$2" < "$p" > /dev/null 2>&1 || { echo "$B's prekey is not signed by its identity"; return 1; }
  [ "$(wc -l < "$p")" -eq 5 ] && [ "$(tail -c 1 "$p" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$p")" = irongall-prekey-v1 ] && [ "$(sed -n 2p "$p")" = "$B" ] ||
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=$(sed -n 3p "$p"); [[ $s =~ ^[1-9][0-9]{0,17}$ ]] || { echo "$B's prekey serial is malformed"; return 1; }
  k=$(sed -n 4p "$p"); age -r "$k" < /dev/null > /dev/null 2>&1 || { echo "$B's prekey is not an age key that age will encrypt to"; return 1; }
  na=$(ig_time "$(sed -n 5p "$p")") || { echo "$B's prekey has no valid not_after"; return 1; }
  echo "$s $k $na"
}
ig_resolve(){ # <address> → prints "<serial> <age recipient>" only when EVERY check passes; otherwise there is nothing to encrypt to
  local B=$1 d="$IG/peers/$1" r s na
  ig_hex "$B" || ig_refuse "not an address: $B" || return 1
  mkdir -p "$d" && ig_api GET "/v1/$B/identity" > "$d/identity.json" && ig_pin "$B" "$d/identity.json" || return 1
  jq -er .prekey "$d/identity.json" | base64 -d > "$d/prekey.txt" && jq -er .prekey_signature "$d/identity.json" | base64 -d > "$d/prekey.sig" || ig_refuse "no prekey for $B in the response" || return 1
  r=$(ig_prekeycheck "$d/prekey.txt" "$d/prekey.sig" "$B" "$d/signers") || ig_refuse "$r" || return 1
  s=${r%% *}; na=${r##* }
  [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  [ "$na" -gt "$(ig_now)" ] || ig_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  echo "$s" > "$d/serial"; r=${r#* }; echo "$s ${r% *}"
}

# recipe: send
ig_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
ig_send(){ # <link or address> [body file] → one logical message, its envelope built ONCE. To retry, run ig_flush, never ig_send again
  local B f=${2-} A id; A=$(cat "$IG/address") && B=$(ig_dest "$1") || return 1
  mkdir -p "$IG/outbox" || return 1
  [ -n "$f" ] || { f="$IG/body.txt"; cat > "$f" || return 1; }
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || ig_refuse "the body is not UTF-8 text" || return 1
  id=$(ig_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(ig_now)" --rawfile body "$f" '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, body:$body}' > "$IG/outbox/$B.$id.P" || return 1
  ig_post "$B" "$IG/outbox/$B.$id"
}
ig_seal(){ # <address> <outbox stem> → <stem>.json: <stem>.P encrypted to the VERIFIED prekey, and signed for that recipient only
  local B=$1 o=$2 r; r=$(ig_resolve "$B") || return 1
  age -r "${r#* }" < "$o.P" > "$o.age" && ssh-keygen -q -Y sign -n "irongall-msg-v1:$B" -f "$IG/identity" < "$o.age" > "$o.sig" || return 1
  jq -n --arg from "$(cat "$IG/address")" --argjson n "${r%% *}" --arg c "$(ig_b64 "$o.age")" --arg s "$(ig_b64 "$o.sig")" '{from:$from, prekey_serial:$n, ciphertext:$c, signature:$s}' > "$o.json"
}
ig_post(){ # <address> <outbox stem> → POSTs it, sealing it first; on 409 stale_prekey, re-encrypts the SAME envelope, once. One that can never be delivered moves to outbox/failed/
  local B=$1 o=$2 sa
  if sa=$(ig_time "$(jq -r .sent_at "$o.P" 2> /dev/null)") && [ "$sa" -lt $(($(ig_now) - 33*86400)) ]; then      # the server would take it, and every recipient refuses it
    ig_failed "$o"; ig_refuse "its envelope is older than 33 days, and every recipient refuses that: moved to outbox/failed/"; return 1
  fi
  { [ -e "$o.json" ] || ig_seal "$B" "$o"; } && ig_api POST "/v1/$B" "$o.json" > /dev/null && { rm -f "$o.P" "$o.age" "$o.sig" "$o.json"; return 0; }
  if [ "$(ig_code)" = stale_prekey ]; then ig_seal "$B" "$o" && ig_api POST "/v1/$B" "$o.json" > /dev/null && { rm -f "$o.P" "$o.age" "$o.sig" "$o.json"; return 0; }; fi
  case $(ig_code) in
    revoked | sender_revoked | bad_address | too_large | conflict) ig_failed "$o"; echo "it can never be delivered: moved to outbox/failed/" >&2 ;;
    *) echo "kept in the outbox: retry with ig_flush" >&2 ;;
  esac
  return 1
}
ig_failed(){ # <outbox stem> → moves its files to outbox/failed/, where ig_flush no longer sees them. Delete them there to drop the message
  local f; mkdir -p "$IG/outbox/failed" || return 1
  for f in "$1.P" "$1.age" "$1.sig" "$1.json"; do [ ! -e "$f" ] || mv "$f" "$IG/outbox/failed/" || return 1; done
}
ig_flush(){ # re-POSTs every message still in the outbox, unchanged: a retry gets the original receipt. One that fails never stops the others
  local f n rc=0; for f in "$IG"/outbox/*.P; do [ -e "$f" ] || continue; n=$(basename "$f" .P); ig_post "${n%%.*}" "${f%.P}" || rc=1; done; return $rc
}

# recipe: receive
ig_recv(){ # drains the box, every page. ACCEPT → inbox/ and one line on stdout. REFUSED → quarantine/, never delivered. Both are acked
  ig_lock || return 1
  ig_drain; local rc=$?; rmdir "$IG/lock"; ig_prune; return $rc
}
ig_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain
  local B c="" n i id; B=$(cat "$IG/address") || return 1
  if [ -e "$IG/seen" ]; then awk -v c=$(($(ig_now) - 33*86400)) '$2 >= c' "$IG/seen" > "$IG/seen.new" && mv "$IG/seen.new" "$IG/seen" && sync "$IG/seen" "$IG" || return 1; fi
  while :; do
    ig_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$IG/list.json" && n=$(jq -er '.messages | length' "$IG/list.json") || return 1
    for ((i = 0; i < n; i++)); do
      id=$(jq -r ".messages[$i].id" "$IG/list.json"); ig_hex "$id" || continue
      if ! grep -q "^$id " "$IG/seen" 2> /dev/null; then ig_one "$B" "$id" || return 1; fi   # an id already handled is only acked again
      ig_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(ig_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$IG/list.json"); [ -n "$c" ] || return 0
  done
}
ig_one(){ # <me> <id> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this box, so it is not acked
  local B=$1 id=$2 m="$IG/msg" A why rc h
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P"
  ig_owner GET "/v1/$B/messages/$id" > "$m.json" || { [ "$(ig_code)" = no_such_message ]; return; }      # already gone
  A=$(jq -r .from "$m.json")
  if ig_hex "$A" && [ ! -e "$IG/peers/$A/identity.doc" ]; then      # first contact: fetch what to pin; a sender with no box has nothing, and is refused
    mkdir -p "$IG/peers/$A" && ig_api GET "/v1/$A/identity" > "$IG/peers/$A/identity.json" || case $(ig_code) in no_such_mailbox | revoked) rm -f "$IG/peers/$A/identity.json" ;; *) return 1 ;; esac
  fi
  h=$(jq -er .ciphertext "$m.json" 2> /dev/null | base64 -d 2> /dev/null | sha256sum | cut -c1-64)      # files are named by the hash computed here, never the server's id
  why=$(ig_judge "$B" "$A" "$m"); rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) ig_line "$m.P" > "$IG/inbox/$h.json" && sync "$IG/inbox/$h.json" "$IG/inbox" && ig_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       cat "$IG/inbox/$h.json" && echo ;;
    2) echo "duplicate of a message already delivered, not delivered again: $h" >&2 ;;
    3) echo "$why: nothing is judged or acked until this box is fixed" >&2; return 1 ;;
    *) cp "$m.json" "$IG/quarantine/$h.json" && sync "$IG/quarantine/$h.json" "$IG/quarantine" || return 1
       echo "REFUSED $h: $why" >&2 ;;
  esac
}
ig_judge(){ # <me> <sender> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with the reason on stdout; 3 a fault of this box, no verdict
  local B=$1 A=$2 m=$3 ids=() k h why
  jq -er .ciphertext "$m.json" | base64 -d > "$m.age" && jq -er .signature "$m.json" | base64 -d > "$m.sig" || { echo "malformed message"; return 1; }
  why=$(ig_pin "$A" "$IG/peers/$A/identity.json" 2>&1) || { echo "${why#REFUSED: }"; return 1; }
  ssh-keygen -Y verify -f "$IG/peers/$A/signers" -I "$A" -n "irongall-msg-v1:$B" -s "$m.sig" < "$m.age" > /dev/null 2>&1 || { echo "the signature does not verify for $A"; return 1; }
  for k in "$IG"/prekeys/*.agekey; do [ -e "$k" ] || continue; [ -r "$k" ] || { echo "cannot read $k"; return 3; }; ids+=(-i "$k"); done
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.P" 2> /dev/null || { echo "it does not decrypt with this box's prekeys"; return 1; }
  ig_envcheck "$m.P" "$A" "$B" || return 1
  [ ! -e "$IG/seen" ] || [ -r "$IG/seen" ] || { echo "cannot read $IG/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$IG/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$IG/seen" 2> /dev/null || return 2
}
ig_envcheck(){ # <envelope> <signer> <this box> → 0 only for one UTF-8 JSON object, keys exact and none twice, v the number 1, from the signer, to this box, a msg_id, a body, string optional fields, and sent_at no older than 33 days; otherwise the reason, and 1
  local e=$1 sa
  iconv -f UTF-8 -t UTF-8 < "$e" > /dev/null 2>&1 || { echo "the envelope is not UTF-8"; return 1; }
  [ "$(jq -n --stream '[inputs | select((length == 2 and (.[0] | length) == 1) or (length == 1 and (.[0] | length) == 2))] | length' "$e" 2> /dev/null)" = "$(jq length "$e" 2> /dev/null)" ] ||
    { echo "the envelope is not one JSON object with no key twice"; return 1; }      # its members, counted as streamed, against its length: a key twice (jq keeps the last, another reader the first) or a second value breaks the count
  jq -e --arg a "$2" --arg b "$3" '.v == 1 and .from == $a and .to == $b and has("body") and (.msg_id | type == "string" and test("\\A[0-9a-f-]{36}\\z")) and all(.subject, .in_reply_to, .supersedes, .pad; . == null or type == "string")' "$e" > /dev/null 2>&1 ||
    { echo "the inner from/to do not match the signer and this box (re-attribution), or the envelope is malformed"; return 1; }
  sa=$(ig_time "$(jq -r .sent_at "$e")") && [ "$sa" -ge $(($(ig_now) - 33*86400)) ] || { echo "sent_at is older than 33 days, or malformed"; return 1; }
}
ig_line(){ # <checked envelope> → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there)
  jq -j '{v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {}) | tojson | gsub("\u0085"; "\\u0085") | gsub("\u2028"; "\\u2028") | gsub("\u2029"; "\\u2029")' "$1"
}
ig_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$IG/seen" ] || new=$IG
  printf '%s %s %s %s\n' "$3" "$(ig_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$IG/seen" && sync "$IG/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
ig_rekey(){ # [--no-pq] → publishes a NEW prekey at the next serial, under the lock (waiting up to a minute for a drain). Needs no token, so it also recovers a box that lost its prekeys
  ig_opt "${1-}" && ig_lock 60 || return 1
  ig_renew "${1-}"; local rc=$?; rmdir "$IG/lock"; return $rc
}
ig_renew(){
  local A r s; A=$(cat "$IG/address") || return 1; mkdir -p "$IG/prekeys"
  ig_api GET "/v1/$A/identity" > "$IG/self.json" || return 1
  jq -er .prekey "$IG/self.json" | base64 -d > "$IG/self.txt" && jq -er .prekey_signature "$IG/self.json" | base64 -d > "$IG/self.sig" || ig_refuse "the server sent no prekey for this box" || return 1
  printf '%s %s\n' "$A" "$(cut -d' ' -f1,2 "$IG/identity.pub")" > "$IG/self.signers"
  r=$(ig_prekeycheck "$IG/self.txt" "$IG/self.sig" "$A" "$IG/self.signers") || ig_refuse "this box's current prekey, as served: $r" || return 1
  s=${r%% *}
  [ "$s" -ge "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || ig_refuse "rollback: the server serves this box's prekey serial $s, below $(cat "$IG/serial"), which this box published" || return 1
  s=$((s + 1)); rm -f "$IG/prekeys/$s.txt" "$IG/prekeys/$s.txt.sig"; ig_prekey "$s" "${1-}" || return 1
  jq -n --arg p "$(ig_b64 "$IG/prekeys/$s.txt")" --arg g "$(ig_b64 "$IG/prekeys/$s.txt.sig")" '{prekey:$p, prekey_signature:$g}' > "$IG/rekey.json"
  ig_api PUT "/v1/$A/prekey" "$IG/rekey.json" > "$IG/token.json" || return 1
  [ "$s" -le "$(cat "$IG/serial" 2> /dev/null || echo 0)" ] || echo "$s" > "$IG/serial" || return 1
  ig_token "$IG/token.json" && ig_prune
}
ig_prune(){ # deletes every retired prekey past its deletion time: its not_after + the 33 days mail is kept. After that, mail encrypted to it is unrecoverable. (The Go client also deletes them sooner.)
  local f n top na; top=$(ls "$IG/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$IG"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest: it decrypts the box's token
    na=$(ig_time "$(sed -n 5p "$f")") || continue
    [ "$(ig_now)" -lt $((na + 33*86400)) ] || rm -f "$IG/prekeys/$n.agekey"
  done
}

# Run as a command, not sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case ${1-} in
    init | addr | send | flush | recv | rekey) cmd=ig_$1; shift; "$cmd" "$@"; exit ;;
    *) sed -n '9,14p' "$0" | sed 's/^# *//' >&2; exit 2 ;;
  esac
fi
