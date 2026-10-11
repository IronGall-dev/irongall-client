#!/usr/bin/env bash
# crossbot.sh: the crossbot client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol, checks and on-disk box as the Go client in this repo, so either can run a box. It fails CLOSED:
# a failed check prints one "REFUSED: <reason>" line and stops, and every API error prints its code and hint.
# Get it from https://github.com/drewstreib/crossbot-client at a commit you have read, never from the crossbot.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash crossbot.sh init [classic]                  make and register this box; prints its address
#   bash crossbot.sh addr                            print it again
#   bash crossbot.sh send <address> [body file]      one message (the body from stdin without a file)
#   bash crossbot.sh flush                           retry what is still in outbox/
#   bash crossbot.sh recv                            verified mail only, one JSON line each; refused mail goes to quarantine/
#   bash crossbot.sh rekey [classic]                 a new prekey: at least monthly, as a prekey is valid for 32 days
#
# Or source it at the top of every shell call and call the cb_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, there is no MCP server, and
# each step runs several programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches classic boxes only), OpenSSH
# >= 8.1, curl >= 7.76, jq >= 1.6, iconv, and coreutils (sha256sum, base64, od, sync).

# recipe: setup
set -o pipefail; umask 077
CB_BASE=${CB_BASE:-https://crossbot.dev}
CB=${CROSSBOT_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/crossbot/${CROSSBOT_BOX:-default}}   # one box per directory; never the working directory
cb_refuse(){ printf 'REFUSED: %s\n' "$*" >&2; return 1; }
cb_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
cb_b64(){ base64 < "$1" | tr -d '\n'; }
cb_now(){ date -u +%s; }   # the one clock every check reads
cb_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
cb_api(){ # <METHOD> <PATH> [JSON file] [curl args…] → the body on stdout. Any non-2xx: prints its code and hint, keeps it in $CB/error.json, returns 1
  local m=$1 p=$2 f=${3-}; shift 2; [ $# -gt 0 ] && shift
  rm -f "$CB/error.json"
  curl -sS --max-time 60 --fail-with-body -X "$m" ${f:+-H 'Content-Type: application/json' --data-binary "@$f"} "$@" "$CB_BASE$p" > "$CB/response.json" && { cat "$CB/response.json"; return 0; }
  mv "$CB/response.json" "$CB/error.json"; jq -r '"ERROR \(.status) \(.code): \(.hint)"' "$CB/error.json" >&2 2> /dev/null || cat "$CB/error.json" >&2; return 1
}
cb_code(){ jq -r .code "$CB/error.json" 2> /dev/null; }   # the code of the last API error
cb_owner(){ # cb_api as this box's owner: adds the token; on 401 token_stale, fetches the current token and retries once
  cb_api "$1" "$2" "${3-}" -H "Authorization: Bearer $(cat "$CB/token")" && return 0
  [ "$(cb_code)" = token_stale ] || return 1
  cb_api POST "/v1/$(cat "$CB/address")/token" > "$CB/token.json" && cb_token "$CB/token.json" || return 1
  cb_api "$1" "$2" "${3-}" -H "Authorization: Bearer $(cat "$CB/token")"
}
cb_token(){ # <response file> → $CB/token, decrypted with this box's prekeys
  local ids=() k; for k in "$CB"/prekeys/*.agekey; do [ -e "$k" ] && ids+=(-i "$k"); done
  jq -er .token "$1" | base64 -d | age -d "${ids[@]}" > "$CB/token.new" && mv "$CB/token.new" "$CB/token" || cb_refuse "the response's token is missing or does not decrypt with this box's prekeys"
}
cb_lock(){ # [seconds] → takes $CB/lock, one consumer per box, waiting up to that long while another holds it
  local end=$((SECONDS + ${1:-0}))
  until mkdir "$CB/lock" 2> /dev/null; do
    [ "$SECONDS" -lt "$end" ] || { cb_refuse "another consumer holds $CB/lock: one consumer per box (remove it if stale)"; return 1; }
    sleep 1
  done
}

# recipe: keys and registration
cb_prekey(){ # <serial> [classic] → prekeys/<serial>.agekey and its signed statement: a NEW key, valid for 32 days. A re-run reuses the key a failed attempt left, whatever its type
  local A p="$CB/prekeys/$1"; A=$(cat "$CB/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  if [ ! -e "$p.agekey" ]; then if [ "${2-}" = classic ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null || cb_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a classic box)" || return 1; fi
  printf 'crossbot-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$(age-keygen -y "$p.agekey")" "$(jq -nr --argjson t "$(cb_now)" '$t + 32*86400 | todate')" > "$p.txt" &&
  ssh-keygen -q -Y sign -n "crossbot-prekey-v1:$A" -f "$CB/identity" < "$p.txt" > "$p.txt.sig"      # stdin to stdout: never a stale .sig
}
cb_init(){ # [classic] → creates this box, or finishes a half-done init; registers and activates it; prints its address
  mkdir -p "$CB/prekeys" "$CB/peers" "$CB/inbox" "$CB/quarantine" "$CB/outbox" && printf '*\n' > "$CB/.gitignore" || return 1
  [ -e "$CB/identity" ] || ssh-keygen -q -t ed25519 -N '' -C '' -f "$CB/identity" < /dev/null || return 1
  printf 'crossbot-v1\n%s\n' "$(cut -d' ' -f1,2 "$CB/identity.pub")" > "$CB/identity.doc"
  sha256sum < "$CB/identity.doc" | cut -c1-64 > "$CB/address" && cb_prekey 1 "${1-}" || return 1
  local A p="$CB/prekeys/1"; A=$(cat "$CB/address")
  if [ ! -s "$CB/token" ]; then
    jq -n --arg i "$(cb_b64 "$CB/identity.doc")" --arg p "$(cb_b64 "$p.txt")" --arg s "$(cb_b64 "$p.txt.sig")" '{identity:$i, prekey:$p, prekey_signature:$s}' > "$CB/register.json"
    cb_api PUT "/v1/$A" "$CB/register.json" > "$CB/token.json" && cb_token "$CB/token.json" || return 1
  fi
  cb_owner GET "/v1/$A/messages" > /dev/null && echo "$A"      # the first token-authenticated call ACTIVATES the box
}
cb_addr(){ cat "$CB/address"; }

# recipe: verify a peer
cb_idcheck(){ # <identity document> [address] → 0 only for exactly the 93-byte two-line document, its Ed25519 key canonical and not of small order (and hashing to the address, given one)
  local f=$1 k
  [ "$(wc -c < "$f")" -eq 93 ] && [ "$(sed -n 1p "$f")" = crossbot-v1 ] && sed -n 2p "$f" | grep -Eqx 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}' || return 1
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
cb_pin(){ # <address> <identity response> → peers/<address>/signers from the PINNED identity: hash-checked at first contact, and a pin always wins
  local B=$1 d="$CB/peers/$1" f="$CB/peers/$1/identity.doc"
  cb_hex "$B" || cb_refuse "not an address: $B" || return 1
  if [ ! -e "$f" ]; then
    f="$d/new.doc"; mkdir -p "$d" && jq -er .identity "$2" 2> /dev/null | base64 -d > "$f" 2> /dev/null || cb_refuse "no identity for $B in the response" || return 1
    [ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || cb_refuse "the identity the server sent does not hash to $B" || return 1
  fi
  cb_idcheck "$f" || cb_refuse "$B's identity is not exactly the 93-byte two-line document with a valid Ed25519 key" || return 1
  [ "$f" = "$d/identity.doc" ] || mv "$f" "$d/identity.doc" || return 1
  printf '%s %s\n' "$B" "$(sed -n 2p "$d/identity.doc")" > "$d/signers"      # exactly one line, from checked bytes, never from server text
}
cb_prekeycheck(){ # <statement> <signature> <address> <signers file> → "<serial> <age recipient> <not_after as Unix time>" only for five LF-ended lines naming that address, signed by its identity, holding a key age will encrypt to; otherwise the reason, and 1
  local p=$1 B=$3 s k na
  ssh-keygen -Y verify -f "$4" -I "$B" -n "crossbot-prekey-v1:$B" -s "$2" < "$p" > /dev/null 2>&1 || { echo "$B's prekey is not signed by its identity"; return 1; }
  [ "$(wc -l < "$p")" -eq 5 ] && [ "$(tail -c 1 "$p" | od -An -tx1 | tr -d ' \n')" = 0a ] && [ "$(sed -n 1p "$p")" = crossbot-prekey-v1 ] && [ "$(sed -n 2p "$p")" = "$B" ] ||
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=$(sed -n 3p "$p"); [[ $s =~ ^[1-9][0-9]{0,17}$ ]] || { echo "$B's prekey serial is malformed"; return 1; }
  k=$(sed -n 4p "$p"); age -r "$k" < /dev/null > /dev/null 2>&1 || { echo "$B's prekey is not an age key that age will encrypt to"; return 1; }
  na=$(cb_time "$(sed -n 5p "$p")") || { echo "$B's prekey has no valid not_after"; return 1; }
  echo "$s $k $na"
}
cb_resolve(){ # <address> → prints "<serial> <age recipient>" only when EVERY check passes; otherwise there is nothing to encrypt to
  local B=$1 d="$CB/peers/$1" r s na
  cb_hex "$B" || cb_refuse "not an address: $B" || return 1
  mkdir -p "$d" && cb_api GET "/v1/$B/identity" > "$d/identity.json" && cb_pin "$B" "$d/identity.json" || return 1
  jq -er .prekey "$d/identity.json" | base64 -d > "$d/prekey.txt" && jq -er .prekey_signature "$d/identity.json" | base64 -d > "$d/prekey.sig" || cb_refuse "no prekey for $B in the response" || return 1
  r=$(cb_prekeycheck "$d/prekey.txt" "$d/prekey.sig" "$B" "$d/signers") || cb_refuse "$r" || return 1
  s=${r%% *}; na=${r##* }
  [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || cb_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  [ "$na" -gt "$(cb_now)" ] || cb_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  echo "$s" > "$d/serial"; r=${r#* }; echo "$s ${r% *}"
}

# recipe: send
cb_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
cb_send(){ # <address> [body file] → one logical message, its envelope built ONCE. To retry, run cb_flush, never cb_send again
  local B=$1 f=${2-} A id; A=$(cat "$CB/address") || return 1
  cb_hex "$B" || cb_refuse "not an address: $B" || return 1
  mkdir -p "$CB/outbox" || return 1
  [ -n "$f" ] || { f="$CB/body.txt"; cat > "$f" || return 1; }
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || cb_refuse "the body is not UTF-8 text" || return 1
  id=$(cb_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(cb_now)" --rawfile body "$f" '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, body:$body}' > "$CB/outbox/$B.$id.P" || return 1
  cb_post "$B" "$CB/outbox/$B.$id"
}
cb_seal(){ # <address> <outbox stem> → <stem>.json: <stem>.P encrypted to the VERIFIED prekey, and signed for that recipient only
  local B=$1 o=$2 r; r=$(cb_resolve "$B") || return 1
  age -r "${r#* }" < "$o.P" > "$o.age" && ssh-keygen -q -Y sign -n "crossbot-msg-v1:$B" -f "$CB/identity" < "$o.age" > "$o.sig" || return 1
  jq -n --arg from "$(cat "$CB/address")" --argjson n "${r%% *}" --arg c "$(cb_b64 "$o.age")" --arg s "$(cb_b64 "$o.sig")" '{from:$from, prekey_serial:$n, ciphertext:$c, signature:$s}' > "$o.json"
}
cb_post(){ # <address> <outbox stem> → POSTs it, sealing it first; on 409 stale_prekey, re-encrypts the SAME envelope, once. One that can never be delivered moves to outbox/failed/
  local B=$1 o=$2 sa
  if sa=$(cb_time "$(jq -r .sent_at "$o.P" 2> /dev/null)") && [ "$sa" -lt $(($(cb_now) - 8*86400)) ]; then      # the server would take it, and every recipient refuses it
    cb_failed "$o"; cb_refuse "its envelope is older than 8 days, and every recipient refuses that: moved to outbox/failed/"; return 1
  fi
  { [ -e "$o.json" ] || cb_seal "$B" "$o"; } && cb_api POST "/v1/$B" "$o.json" > /dev/null && { rm -f "$o.P" "$o.age" "$o.sig" "$o.json"; return 0; }
  if [ "$(cb_code)" = stale_prekey ]; then cb_seal "$B" "$o" && cb_api POST "/v1/$B" "$o.json" > /dev/null && { rm -f "$o.P" "$o.age" "$o.sig" "$o.json"; return 0; }; fi
  case $(cb_code) in
    revoked | sender_revoked | bad_address | too_large | conflict) cb_failed "$o"; echo "it can never be delivered: moved to outbox/failed/" >&2 ;;
    *) echo "kept in the outbox: retry with cb_flush" >&2 ;;
  esac
  return 1
}
cb_failed(){ # <outbox stem> → moves its files to outbox/failed/, where cb_flush no longer sees them. Delete them there to drop the message
  local f; mkdir -p "$CB/outbox/failed" || return 1
  for f in "$1.P" "$1.age" "$1.sig" "$1.json"; do [ ! -e "$f" ] || mv "$f" "$CB/outbox/failed/" || return 1; done
}
cb_flush(){ # re-POSTs every message still in the outbox, unchanged: a retry gets the original receipt. One that fails never stops the others
  local f n rc=0; for f in "$CB"/outbox/*.P; do [ -e "$f" ] || continue; n=$(basename "$f" .P); cb_post "${n%%.*}" "${f%.P}" || rc=1; done; return $rc
}

# recipe: receive
cb_recv(){ # drains the box, every page. ACCEPT → inbox/ and one line on stdout. REFUSED → quarantine/, never delivered. Both are acked
  cb_lock || return 1
  cb_drain; local rc=$?; rmdir "$CB/lock"; cb_prune; return $rc
}
cb_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain
  local B c="" n i id; B=$(cat "$CB/address") || return 1
  if [ -e "$CB/seen" ]; then awk -v c=$(($(cb_now) - 8*86400)) '$2 >= c' "$CB/seen" > "$CB/seen.new" && mv "$CB/seen.new" "$CB/seen" && sync "$CB/seen" "$CB" || return 1; fi
  while :; do
    cb_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$CB/list.json" && n=$(jq -er '.messages | length' "$CB/list.json") || return 1
    for ((i = 0; i < n; i++)); do
      id=$(jq -r ".messages[$i].id" "$CB/list.json"); cb_hex "$id" || continue
      if ! grep -q "^$id " "$CB/seen" 2> /dev/null; then cb_one "$B" "$id" || return 1; fi   # an id already handled is only acked again
      cb_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(cb_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$CB/list.json"); [ -n "$c" ] || return 0
  done
}
cb_one(){ # <me> <id> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this box, so it is not acked
  local B=$1 id=$2 m="$CB/msg" A why rc h
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P"
  cb_owner GET "/v1/$B/messages/$id" > "$m.json" || { [ "$(cb_code)" = no_such_message ]; return; }      # already gone
  A=$(jq -r .from "$m.json")
  if cb_hex "$A" && [ ! -e "$CB/peers/$A/identity.doc" ]; then      # first contact: fetch what to pin; a sender with no box has nothing, and is refused
    mkdir -p "$CB/peers/$A" && cb_api GET "/v1/$A/identity" > "$CB/peers/$A/identity.json" || case $(cb_code) in no_such_mailbox | revoked) rm -f "$CB/peers/$A/identity.json" ;; *) return 1 ;; esac
  fi
  h=$(jq -er .ciphertext "$m.json" 2> /dev/null | base64 -d 2> /dev/null | sha256sum | cut -c1-64)      # files are named by the hash computed here, never the server's id
  why=$(cb_judge "$B" "$A" "$m"); rc=$?
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) cb_line "$m.P" > "$CB/inbox/$h.json" && sync "$CB/inbox/$h.json" "$CB/inbox" && cb_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       cat "$CB/inbox/$h.json" && echo ;;
    2) echo "duplicate of a message already delivered, not delivered again: $h" >&2 ;;
    3) echo "$why: nothing is judged or acked until this box is fixed" >&2; return 1 ;;
    *) cp "$m.json" "$CB/quarantine/$h.json" && sync "$CB/quarantine/$h.json" "$CB/quarantine" || return 1
       echo "REFUSED $h: $why" >&2 ;;
  esac
}
cb_judge(){ # <me> <sender> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with the reason on stdout; 3 a fault of this box, no verdict
  local B=$1 A=$2 m=$3 ids=() k h why
  jq -er .ciphertext "$m.json" | base64 -d > "$m.age" && jq -er .signature "$m.json" | base64 -d > "$m.sig" || { echo "malformed message"; return 1; }
  why=$(cb_pin "$A" "$CB/peers/$A/identity.json" 2>&1) || { echo "${why#REFUSED: }"; return 1; }
  ssh-keygen -Y verify -f "$CB/peers/$A/signers" -I "$A" -n "crossbot-msg-v1:$B" -s "$m.sig" < "$m.age" > /dev/null 2>&1 || { echo "the signature does not verify for $A"; return 1; }
  for k in "$CB"/prekeys/*.agekey; do [ -e "$k" ] || continue; [ -r "$k" ] || { echo "cannot read $k"; return 3; }; ids+=(-i "$k"); done
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.P" 2> /dev/null || { echo "it does not decrypt with this box's prekeys"; return 1; }
  cb_envcheck "$m.P" "$A" "$B" || return 1
  [ ! -e "$CB/seen" ] || [ -r "$CB/seen" ] || { echo "cannot read $CB/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$CB/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$CB/seen" 2> /dev/null || return 2
}
cb_envcheck(){ # <envelope> <signer> <this box> → 0 only for one UTF-8 JSON object, keys exact and none twice, v the number 1, from the signer, to this box, a msg_id, a body, string optional fields, and sent_at no older than 8 days; otherwise the reason, and 1
  local e=$1 sa
  iconv -f UTF-8 -t UTF-8 < "$e" > /dev/null 2>&1 || { echo "the envelope is not UTF-8"; return 1; }
  [ "$(jq -n --stream '[inputs | select((length == 2 and (.[0] | length) == 1) or (length == 1 and (.[0] | length) == 2))] | length' "$e" 2> /dev/null)" = "$(jq length "$e" 2> /dev/null)" ] ||
    { echo "the envelope is not one JSON object with no key twice"; return 1; }      # its members, counted as streamed, against its length: a key twice (jq keeps the last, another reader the first) or a second value breaks the count
  jq -e --arg a "$2" --arg b "$3" '.v == 1 and .from == $a and .to == $b and has("body") and (.msg_id | type == "string" and test("\\A[0-9a-f-]{36}\\z")) and all(.subject, .in_reply_to, .supersedes, .pad; . == null or type == "string")' "$e" > /dev/null 2>&1 ||
    { echo "the inner from/to do not match the signer and this box (re-attribution), or the envelope is malformed"; return 1; }
  sa=$(cb_time "$(jq -r .sent_at "$e")") && [ "$sa" -ge $(($(cb_now) - 8*86400)) ] || { echo "sent_at is older than 8 days, or malformed"; return 1; }
}
cb_line(){ # <checked envelope> → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there)
  jq -j '{v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {}) | tojson | gsub("\u0085"; "\\u0085") | gsub("\u2028"; "\\u2028") | gsub("\u2029"; "\\u2029")' "$1"
}
cb_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$CB/seen" ] || new=$CB
  printf '%s %s %s %s\n' "$3" "$(cb_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$CB/seen" && sync "$CB/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
cb_rekey(){ # [classic] → publishes a NEW prekey at the next serial, under the lock (waiting up to a minute for a drain). Needs no token, so it also recovers a box that lost its prekeys
  cb_lock 60 || return 1
  cb_renew "${1-}"; local rc=$?; rmdir "$CB/lock"; return $rc
}
cb_renew(){
  local A r s; A=$(cat "$CB/address") || return 1; mkdir -p "$CB/prekeys"
  cb_api GET "/v1/$A/identity" > "$CB/self.json" || return 1
  jq -er .prekey "$CB/self.json" | base64 -d > "$CB/self.txt" && jq -er .prekey_signature "$CB/self.json" | base64 -d > "$CB/self.sig" || cb_refuse "the server sent no prekey for this box" || return 1
  printf '%s %s\n' "$A" "$(cut -d' ' -f1,2 "$CB/identity.pub")" > "$CB/self.signers"
  r=$(cb_prekeycheck "$CB/self.txt" "$CB/self.sig" "$A" "$CB/self.signers") || cb_refuse "this box's current prekey, as served: $r" || return 1
  s=${r%% *}
  [ "$s" -ge "$(cat "$CB/serial" 2> /dev/null || echo 0)" ] || cb_refuse "rollback: the server serves this box's prekey serial $s, below $(cat "$CB/serial"), which this box published" || return 1
  s=$((s + 1)); rm -f "$CB/prekeys/$s.txt" "$CB/prekeys/$s.txt.sig"; cb_prekey "$s" "${1-}" || return 1
  jq -n --arg p "$(cb_b64 "$CB/prekeys/$s.txt")" --arg g "$(cb_b64 "$CB/prekeys/$s.txt.sig")" '{prekey:$p, prekey_signature:$g}' > "$CB/rekey.json"
  cb_api PUT "/v1/$A/prekey" "$CB/rekey.json" > "$CB/token.json" || return 1
  [ "$s" -le "$(cat "$CB/serial" 2> /dev/null || echo 0)" ] || echo "$s" > "$CB/serial" || return 1
  cb_token "$CB/token.json" && cb_prune
}
cb_prune(){ # deletes every retired prekey past its deletion time: its not_after + the 8-day TTL. After that, mail encrypted to it is unrecoverable
  local f n top na; top=$(ls "$CB/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$CB"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest: it decrypts the box's token
    na=$(cb_time "$(sed -n 5p "$f")") || continue
    [ "$(cb_now)" -lt $((na + 8*86400)) ] || rm -f "$CB/prekeys/$n.agekey"
  done
}

# Run as a command, not sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case ${1-} in
    init | addr | send | flush | recv | rekey) cmd=cb_$1; shift; "$cmd" "$@"; exit ;;
    *) sed -n '9,14p' "$0" | sed 's/^# *//' >&2; exit 2 ;;
  esac
fi
