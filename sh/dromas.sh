#!/usr/bin/env bash
# dromas.sh: the dromas client in stock tools (bash, age, ssh-keygen, curl, jq, iconv and coreutils).
#
# The same protocol and checks as the Go client in this repo, on a box of its own: the proof that a box made of stock tools exchanges mail with a
# Go box (AGENTS.md § The shell client), not a client to run. It fails CLOSED:
# a failed check prints an error line, "REFUSED: <reason>", and stops (recv refuses that one message with a refused line, its code and its words, and goes on), and every API error prints its status and its code, and none of the server's words.
# It prints JSON lines, as the Go client does, each with its "type" first: what a command did and met on stdout, and on stderr the
# line that says it failed ("error", here sometimes more than one), that its command line was wrong ("usage_error"), or that it waits.
# Get it from https://github.com/dromas-dev/dromas-client at a commit you have read, never from the dromas.dev
# server: a server that could hand you this script could hand you one without its checks.
#
#   bash dromas.sh init [--no-pq]                  make and register this box; prints its link, $DR_BASE/to/<address>
#   bash dromas.sh addr                            print it again: give it to whoever should write to this box
#   bash dromas.sh send <link> [file]             one message (the body from stdin without a file); a link or an address. Posted now or not at all: nothing waits
#   bash dromas.sh recv                            verified mail, a "mail" line each; refused mail goes to quarantine/, with a "refused" line
#   bash dromas.sh prekey renew [--no-pq]          a new prekey, working key and certificate: at least monthly, as a prekey is valid for 33 days, or within the lifetime a prekey-lifetime file sets
#   bash dromas.sh help [<command>]                this, or a command's lines; --help after a command does the same, and runs nothing
#   The README has the rest: https://github.com/dromas-dev/dromas-client#readme
#
# Or source it at the top of every shell call and call the dr_* functions. Agent tools run each command in a fresh
# shell, so all state lives in files in the box's directory, never in variables.
#
# It gives up conveniences the Go client has: recv drains once and never waits for mail, and each step runs several
# programs. Needs bash >= 4, age >= 1.3 (1.2 makes and reaches --no-pq boxes only; Ubuntu to 26.04 and Debian 13
# ship older, and go install filippo.io/age/cmd/...@v1.3.2 is current), OpenSSH >= 9.1 (the first to take a
# certificate's validity and a time to verify at in UTC), curl >= 7.84 (--fail-with-body, and -w with %header),
# jq >= 1.7.1 (1.7.0 can abort on a number a sender writes, CVE-2023-50246; Ubuntu 24.04's fixed jq prints jq-1.7),
# iconv, and coreutils (sha256sum, base64, od, sync). Dates go through jq, never date -d, and base64 is never -w0.

# recipe: setup
set -o pipefail; umask 077
export LC_ALL=C   # every pattern and tool reads bytes, as the Go client does: under another locale [0-9] can take a digit that is not ASCII, and [A-Z] can miss I
DR_BASE=${DR_BASE:-https://dromas.dev}
DR=${DR_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/dromas-sh/${DR_BOX:-default}}   # one box per directory, of this script's own: never the Go client's (its DROMAS_HOME and ~/.config/dromas/, dr_ownbox), and never the working directory
DR_LOCK_WAIT=${DR_LOCK_WAIT:-120}   # how many seconds a command waits for the box's lock while another command of the box holds it: what apt waits for its own lock when no one is at a terminal
DR_P256='ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGD+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2eQP+EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk='   # a P-256 key, box C's identity in this repo's testdata/vectors/ (RFC 6979 §A.2.5's published test key), for dr_senders to ask ssh-keygen to read
dr_senders(){ # → the identity key types dr_idcheck verifies on this build, as a JSON list. A box declares them with each prekey it publishes, and the server then refuses it mail from a box whose identity is of any other type (PROTOCOL.md §7): ssh-ed25519, and ecdsa-sha2-nistp256 only where this build's ssh-keygen reads a P-256 key. One built without OpenSSL reads none, so dr_idcheck refuses every P-256 identity there (PROTOCOL.md Appendix A), and a box that declared the type would be sent mail it then refuses
  if ssh-keygen -l -f - <<< "$DR_P256" > /dev/null 2>&1; then echo '["ssh-ed25519","ecdsa-sha2-nistp256"]'; else echo '["ssh-ed25519"]'; fi
}
dr_out(){ jq -cn --arg type "$1" "${@:2}" '$ARGS.named'; }      # <type> [--arg <name> <text> | --argjson <name> <JSON>]… → one line of JSON on stdout, its type first and then each member in turn, as the Go client prints one: what a command did or met on the way
dr_err(){ jq -cn --arg m "$*" '{type:"error", message:$m}' >&2; }      # <words> → the line on stderr that says a command failed, in this script's own words
dr_refuse(){ dr_err "REFUSED: $*"; return 1; }
dr_hex(){ [[ $1 =~ ^[0-9a-f]{64}$ ]]; }
dr_b64(){ base64 < "$1" | tr -d '\n'; }
dr_now(){ date -u +%s; }   # the one clock every check reads
dr_time(){ # <timestamp> → its Unix time, only for exactly YYYY-MM-DDTHH:MM:SSZ naming a real time
  local s; [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  s=$(jq -nr --arg t "$1" '$t | fromdateiso8601 | select(todate == $t)' 2> /dev/null) && [ -n "$s" ] && echo "$s"
}
dr_api(){ # <METHOD> <PATH> [body file] [curl args…] → the body on stdout, as curl -o wrote it. The body file is sent as it is: a message's ciphertext, POSTed to …/messages, as application/octet-stream (PROTOCOL.md §11.10), and any other body as JSON. Any non-2xx: an error line with its status, its code (dr_code) and the wait its Retry-After asks for, and nothing the server wrote: its detail, hint and title are for a person reading the body (PROTOCOL.md §11.3). No answer at all: an error line with curl's words. Keeps the answer in $DR/error.json and what curl read of it in $DR/error.meta (dr_status), returns 1
  local m=$1 p=$2 f=${3-} t=application/json s c w; local -a np=(); shift 2; [ $# -gt 0 ] && shift
  [[ "$m $p" == "POST /v1/"*"/messages?"* ]] && t=application/octet-stream
  dr_tls "$DR_BASE" || return 1
  dr_here "$DR_BASE" localhost && np=(--noproxy '*')      # a server on this machine is called directly, whatever proxy the environment names, as Go's ProxyFromEnvironment never proxies localhost or a loopback address
  rm -f "$DR/error.json" "$DR/error.meta" "$DR/response.body" "$DR/response.meta"
  curl -q -sS "${np[@]}" --max-time 60 --max-filesize 16777216 --fail-with-body -o "$DR/response.body" -w '%{response_code}\n%header{retry-after}\n%header{date}\n' -X "$m" ${f:+-H "Content-Type: $t" --data-binary "@$f"} "$@" "$DR_BASE$p" > "$DR/response.meta" 2> "$DR/curl.err" &&
    [[ $(sed -n 1p "$DR/response.meta") = 2?? ]] && { cat "$DR/response.body"; return 0; }      # -q first, or curl reads the user's .curlrc, where location, insecure or proxy change what is called. Only a 2xx is an answer: curl, which follows no redirect without -L, exits 0 on a 3xx too. The status and the two headers are the final answer's own, as curl read it: never a 1xx's line or a trailer, which the Go client never reads either
  mv "$DR/response.body" "$DR/error.json" 2> /dev/null; mv "$DR/response.meta" "$DR/error.meta" 2> /dev/null
  s=$(dr_status); c=$(dr_code); w=$(dr_wait); q=; u=
  [ "$c" = rate_limited ] && q=$(dr_member quota_id "$DR_QUOTAS") && u=$(dr_member subject '["box","ip"]')
  [ -n "$s" ] || { dr_err "no answer from $DR_BASE"; return 1; }      # curl's words, which can quote what the server sent (a certificate's name), are not printed
  jq -cn --argjson s "$s" --arg c "$c" --arg w "$w" --arg q "$q" --arg u "$u" '{type:"error", status:$s} + (if $c != "" then {code:$c} else {} end) + (if $q != "" then {quota_id:$q} else {} end) + (if $u != "" then {subject:$u} else {} end) + (if $w != "" then {retry_after:($w | tonumber)} else {} end) +
    {message:("ERROR \($s)" + (if $c != "" then " \($c)" elif $s >= 300 and $s <= 399 then ": a redirect, which this client never follows: the API answers where it is called" else ": an answer this client does not know" end) + (if $q != "" then ": the limit \($q)" else "" end) + (if $u == "box" then ", counted against this box" elif $u == "ip" then ", counted against this machine'"'"'s IP address" else "" end) + (if $w != "" then "; the server asks to wait \($w) seconds" else "" end))}' >&2; return 1
}
DR_TYPE='tag:dromas.dev,2026-10-26:errors/'      # an error's type is this and its code, which names the problem and resolves to nothing (PROTOCOL.md §11.3): a code counts only beside its own
DR_CODES='{"bad_request":400,"bad_address":400,"bad_encoding":400,"identity_mismatch":400,"bad_key":400,"prekey_not_new":400,"prekey_time":400,"unsupported_key_type":400,"not_age":400,"wrong_recipient_type":400,"bad_revocation":400,"unauthorized":401,"pass_expired":401,"certificate_not_current":401,"certificate_revoked":401,"unknown_sender":403,"sender_revoked":403,"sender_not_allowed":403,"sender_key_type":403,"adopt_key_refused":403,"no_such_mailbox":404,"no_such_message":404,"not_revoked":404,"conflict":409,"box_changed":409,"stale_prekey":409,"prekey_expired":409,"request_timeout":408,"revoked":410,"precondition_failed":412,"too_large":413,"rate_limited":429,"fetch_paced":429,"refetch_spent":429,"pair_full":429,"mailbox_full":429,"mailbox_busy":429,"unavailable":503}'      # every code, and its status (PROTOCOL.md §11.3)
DR_QUOTAS='["polls","pages","calls","sends","renewals","certificates","certificate_revocations","registrations","registrations_range","misses","sends_before_pass","requests"]'      # every limit a rate_limited may name in quota_id (PROTOCOL.md §11.5)
dr_member(){ jq -r --arg m "$1" --argjson known "$2" '.[$m] | strings | select(. as $v | $known | index([$v])) ' "$DR/error.json" 2> /dev/null; }      # <member> <known values, a JSON array> → the last API error's string member, only when it is one of them: a client shows no value it does not know (PROTOCOL.md §11.3)
dr_status(){ sed -n '1{/^[0-9][0-9][0-9]$/p;}' "$DR/error.meta" 2> /dev/null | grep -vx 000; }      # the status of the last API error. error.meta is what curl's -w read of the final answer, a line each: its status (000 for none), then its Retry-After and its Date, each the first given, trimmed, as Go's Header.Get reads one
dr_code(){ local s; s=$(dr_status) && [ -n "$s" ] && dr_shape "$DR/error.json" problem && jq -r --argjson codes "$DR_CODES" --argjson s "$s" --arg t "$DR_TYPE" '(.code | strings) as $c | select($codes[$c] == $s and .type == $t + $c) | $c' "$DR/error.json" 2> /dev/null; }   # the code of the last API error: one this client knows, under its own status, beside its own type, from an answer the Go client would read the same. Any other is no code
dr_wait(){ sed -n '2{/^[0-9]\{1,\}$/p;}' "$DR/error.meta" 2> /dev/null | sed 's/^0*\([0-9]\)/\1/' | awk '$1 > 0 { print ($1 > 86400 ? 86400 : $1) }'; }      # the seconds the last API error's Retry-After asks to wait, as a number of at most a day, or nothing. It is delay-seconds, digits alone (PROTOCOL.md §11.3): an HTTP-date asks for no wait
dr_dated(){ local d; d=$(sed -n '3{/^[A-Za-z0-9 ,:]*$/p;}' "$DR/error.meta" 2> /dev/null) && [ -n "$d" ] && jq -nr --arg d "$d" '$d | strptime("%a, %d %b %Y %H:%M:%S GMT") | mktime | todate' 2> /dev/null; }      # the time the last API error's Date header gives, the server's word
dr_shape(){ # <answer> <box|list|record|receipt|problem> → 0 only for one JSON object of that kind, each member this script reads of its type, and null as if the member were left out. An integer is from 0 to 2^53 - 1 and jq gives it back as digits, since bash reads it. A byte member is a string, read by dr_bytes. Members it does not read are ignored
  jq -en --arg k "$2" 'def s: . == null or type == "string"; def n: . == null or (type == "number" and . == floor and . >= 0 and . <= 9007199254740991 and (tostring | test("\\A(0|[1-9][0-9]*)\\z")));
    def record: all(.identity, .revocation_signature, .revoked_certificates, .revoked_certificates_signature; s);
    [inputs] | length == 1 and (.[0] | type == "object" and
    {box: all(.identity, .prekey, .prekey_signature, .revoked_certificates, .revoked_certificates_signature; s),
     list: ((.next_cursor | . == null or (type == "string" and test("\\A[A-Za-z0-9_-]+\\z"))) and (.messages | . == null or (type == "array" and all(.[]; . == null or (type == "object" and (.id | s) and (.size | n and (. // 0) <= 16777216)))))),
     record: record,
     receipt: all(.id, .received_at, .expires_at; s),
     problem: (all(.type, .code; s) and (.record | . == null or (type == "object" and record)))}[$k])' "$1" > /dev/null 2>&1
}
dr_bytes(){ # <answer> <member> <file> → the member's bytes into the file, only for base64 in its one encoding (RFC 4648 §3): padded, nothing outside the alphabet, a line break included, and the unused bits zero, which is what encoding the bytes again gives back. So a field has one text whatever base64 -d takes (GNU's refuses one unpadded, uutils' takes it), and the identity a plain/ vector carries is refused as the Go client refuses it. A member null or left out is no bytes. 1 for anything else
  jq -ejr --arg m "$2" '.[$m] | if . == null then "" else strings end' "$1" > "$3.b64" 2> /dev/null && base64 -d < "$3.b64" > "$3" 2> /dev/null && [ "$(dr_b64 "$3" | sha256sum)" = "$(sha256sum < "$3.b64")" ] || { rm -f "$3.b64"; return 1; }
  rm -f "$3.b64"
}
dr_opt(){ [ -z "$1" ] || [ "$1" = --no-pq ] || dr_refuse "unknown option $1: the only one is --no-pq (no post-quantum encryption, X25519 only)"; }
dr_stamp(){ jq -nr --argjson t "$1" '$t | strftime("%Y%m%d%H%M%SZ")'; }      # <Unix time> → the time as ssh-keygen takes one, in UTC
dr_asc(){ printf %s "$1" | od -An -v -tx1 | tr -d ' \n'; }      # <text> → its bytes in hex
dr_owner(){ # <METHOD> <PATH> [body file] [curl args…] → dr_api as this box: adds its pass. If the server refuses the pass (it ran out sooner by the server's clock, or is under a certificate the server no longer takes), signs another and tries once more. A pass refused twice for its time is the clock: it says what this one reads, beside the server's words
  local p; p=$(dr_pass) || return 1
  dr_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  case $(dr_code) in unauthorized | pass_expired | certificate_not_current | certificate_revoked) ;; *) return 1 ;; esac
  rm -f "$DR/pass"; p=$(dr_pass) && dr_api "$1" "$2" "${3-}" -H "Authorization: $p" "${@:4}" && return 0
  dr_clock; return 1
}
dr_taken(){ # → the reading of this machine's clock a server took, in Unix time: the date of the pass in $DR/pass, which the call dr_owner made, or the renewal dr_renew sent, carried once the server answered it: its not_after less the ten minutes a pass is signed for. Every deletion by the clock is by one, never by a reading of the clock (PROTOCOL.md §12.4): a clock far off is stopped at its pass, and one that jumps or steps back while a call is in flight deletes nothing by where it went
  local na; na=$(dr_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$DR/pass" 2> /dev/null)") && echo $((na - 600))
}
dr_look(){ # <address> → dr_api GET of a box from this box's server (GET /v1/<address>), with no pass: the read is public, and a server reads none on it (PROTOCOL.md §11.8)
  dr_api GET "/v1/$1"
}
dr_clock(){ # after a call the server refused: if it refused the pass, or a prekey statement, for its time, says what the server dates its answer and what this machine's clock reads. A new pass does not cure that, so it is nearly always a clock. The date is the server's word: a clock set by a server's lie makes an ended certificate valid again, so this sends its reader to a time source of their own
  local d; case $(dr_code) in pass_expired | prekey_time) ;; *) return 0 ;; esac
  d=$(dr_dated) && d="the server dates its answer $d, and "
  dr_err "${d}this machine's clock reads $(jq -nr --argjson t "$(dr_now)" '$t | todate'). A server refuses a pass from a clock 10 minutes or more behind its own, or more than 50 ahead, a certificate made by a clock more than 50 ahead, and a prekey statement dated more than an hour ahead of it. Check this machine's clock against a time source you trust, not against the server"
}
dr_server(){ # <URL> → the server's name, as a pass names it: the URL's host, lowercase, and its port only when that is not the scheme's default, as an origin is written (PROTOCOL.md §8): the port as a number, and none for https on 443 or http on 80. A user and an @ before the host are no part of it, as Go's url.Parse has it
  local s=${1%%://*} h=${1#*://} p=
  h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  if [[ $h =~ ^(.*):([0-9]*)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}; fi      # an IPv6 address ends in ], so a colon there begins no port
  [ -z "$p" ] || { p=$((10#$p)); case ${s,,}:$p in https:443 | http:80) ;; *) h+=:$p ;; esac; }
  echo "$h"
}
dr_here(){ # <URL> [localhost] → 0 when the URL's host is this machine by its address, an IPv4 address in 127.0.0.0/8 or [::1], and with localhost, that name too. Other spellings of an IPv6 loopback address are read as no address of this machine
  local h=${1#*://}; h=${h%%[/?#]*}; h=${h##*@}; h=${h,,}
  [[ $h =~ ^(.*):[0-9]*$ ]] && h=${BASH_REMATCH[1]}      # an IPv6 address ends in ], so a colon there begins no port
  [[ $h = '[::1]' || $h =~ ^127(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ || ( ${2-} = localhost && $h = localhost ) ]]
}
dr_tls(){ # <URL> → 0 when it is a server this box may call: https, or http only to a server on this machine, by its address: an IPv4 address in 127.0.0.0/8, or [::1]. A name is not, since localhost is what a resolver says it is (RFC 8252 §8.3), so that a pass, or the address a lookup asks about, never crosses a network in the clear (PROTOCOL.md §11.1). Otherwise a refusal, and 1
  [[ ${1,,} = https://?* ]] || { [[ ${1,,} = http://?* ]] && dr_here "$1"; } ||
    dr_refuse "$(printf '%.80s' "$1") is not a server this client calls: one is https, or http only to this machine, by its address (127.0.0.0/8, ::1)"
}
dr_pass(){ # [serial] → the Authorization value of a call as this box, unless it holds its own revocation (dr_finished). Without a serial: the pass kept in $DR/pass while it has more than 30 seconds left and no more than the ten minutes it was signed for, otherwise a new one, signed by the working key in use and kept. With one: a pass signed by that working key, for the call that publishes its prekey, left in $DR/pass.new until the server has taken it
  local A n=${1-} na h; A=$(cat "$DR/address") || return 1
  dr_finished || { dr_done $?; return 1; }
  if [ -z "$n" ]; then
    na=$(dr_time "$(sed -n 's/.* not_after="\([^"]*\)".*/\1/p' "$DR/pass" 2> /dev/null)") && [ $((na - $(dr_now))) -gt 30 ] && [ $((na - $(dr_now))) -le 600 ] && { cat "$DR/pass"; return; }      # more than ten minutes left: this machine's clock has gone back since it was signed, so a new one, dated by the clock as it is
    n=$(cat "$DR/serial" 2> /dev/null) || dr_refuse "this box has published no prekey: run init, or rekey for a box restored from its identity" || return 1
  fi
  h=$(dr_server "$DR_BASE"); na=$(jq -nr --argjson t "$(dr_now)" '$t + 600 | todate')      # who is calling, which server, and until when: ten minutes
  printf 'dromas-pass-v1\n%s\n%s\n%s\n' "$A" "$h" "$na" | ssh-keygen -q -Y sign -n "dromas-pass-v1:$A" -f "$DR/work/$n-cert.pub" > "$DR/pass.sig" 2> /dev/null ||
    dr_refuse "this box cannot sign a pass with working key $n: rekey makes a new working key, certificate and prekey" || return 1
  printf 'dromas-pass address="%s", not_after="%s", signature="%s"\n' "$A" "$na" "$(dr_b64 "$DR/pass.sig")" > "$DR/pass.new" || return 1
  [ -n "${1-}" ] || mv "$DR/pass.new" "$DR/pass" || return 1
  cat "$DR/pass${1:+.new}"
}
dr_lock(){ # <command> [args] → runs that dr_ command with $DR/lock, the box's lock, held, once the box's directories and identity files are made (dr_dirs, dr_identity), as the Go client's Open makes them: so a box restored from its identity alone runs. Every command that writes the box runs so, from start to end, so one runs at a time and none reads a file another is writing. While another holds it, says so once and waits up to $DR_LOCK_WAIT seconds. If the command dies, the shell's EXIT trap removes it; a kill -9 leaves it behind
  local end=$((SECONDS + DR_LOCK_WAIT)) said= me=$DR outer=${DR_HELD-} trap rc
  [ -s "$DR/identity" ] || { dr_refuse "no box in $DR: run init first"; return 1; }
  dr_ownbox || return 1
  until mkdir "$me/lock" 2> /dev/null; do
    [ -n "$said" ] || { jq -cn '{type:"waiting", for:"lock", message:"waiting for this box'"'"'s lock: another command of this box is running, and a box'"'"'s commands write its files one at a time"}' >&2; said=1; }
    [ "$SECONDS" -lt "$end" ] || { dr_refuse "another command of this box held its lock, $me/lock, for as long as a command waits for it. If none is running, one that crashed left it behind: remove it"; return 1; }
    sleep 1
  done
  trap=$(trap -p EXIT); DR_HELD=$me; trap 'rmdir "$DR_HELD/lock" 2> /dev/null' EXIT
  dr_dirs && dr_identity && "$@"; rc=$?
  rmdir "$me/lock"; DR_HELD=$outer; eval "${trap:-trap - EXIT}"; return $rc      # and the caller's own EXIT trap back
}
dr_ownbox(){ [ ! -e "$DR/state" ] || dr_refuse "$DR holds a state file: it is a box of the Go client, which this script never runs, since the two keep their records apart and would undo each other's: set DR_HOME to a directory of this script's own"; }      # whether $DR is a box of this script's, by the one file only the Go client makes
dr_held(){ [ "${DR_HELD-}" = "$DR" ]; }      # whether this shell holds this box's lock: a command another command runs works under its caller's
dr_dirs(){ mkdir -p "$DR/work" "$DR/prekeys" "$DR/peers" "$DR/inbox" "$DR/quarantine" "$DR/sent"; }      # the box's directories, made where they are missing, as the Go client's Open makes them: by init, and by every command that writes the box (dr_lock)
dr_identity(){ # → identity.pub, identity.doc and address, the identity as the box's other files name it: identity.pub made again from the identity where it is missing or empty, then the document and its SHA-256, each written beside and moved into place only where its bytes differ (dr_put), as the Go client's Open writes them. So a box restored from its identity alone gets all three, init run again rewrites nothing a command beside it reads, and a crash leaves no file empty
  local a
  [ -s "$DR/identity.pub" ] || { ssh-keygen -y -f "$DR/identity" < /dev/null > "$DR/id.pub" && dr_put "$DR/id.pub" "$DR/identity.pub"; } || dr_refuse "ssh-keygen cannot read this box's identity, $DR/identity, to make identity.pub" || return 1
  printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 "$DR/identity.pub")" > "$DR/id.doc" || return 1
  cmp -s "$DR/id.doc" "$DR/identity.doc" || { { dr_idcheck "$DR/id.doc"; [ $? != 1 ]; } || dr_refuse "this box's identity.pub is not a key an identity document holds: $DR/identity.pub" || return 1; dr_put "$DR/id.doc" "$DR/identity.doc" || return 1; }      # checked before it is written: a document out of form, from an identity.pub that is, would give the box another address
  a=$(sha256sum < "$DR/id.doc" | cut -c1-64) && rm -f "$DR/id.doc" "$DR/id.pub" || return 1
  printf '%s\n' "$a" | cmp -s - "$DR/address" || dr_putline "$DR/address" "$a"
}

# recipe: keys and registration
dr_work(){ # <serial> → work/<serial>, .pub and -cert.pub: a NEW working key, and the certificate this box's identity gives it, with that serial, good from an hour ago for 64 days: the 31 it signs mail for, the longest month, and the 33 the last of that mail may wait. The working key signs what the box says; the identity signs certificates and nothing else
  local A w="$DR/work/$1" t; A=$(cat "$DR/address") || return 1; mkdir -p "$DR/work" || return 1
  [ -s "$w" ] && [ -s "$w-cert.pub" ] && return 0
  rm -f "$w" "$w.pub" "$w-cert.pub"; t=$(dr_now)
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$w" < /dev/null &&
  ssh-keygen -q -s "$DR/identity" -I dromas-cert-v1 -n "$A" -z "$1" -V "$(dr_stamp $((t - 3600))):$(dr_stamp $((t + 64*86400)))" -O clear "$w.pub"      # one principal, the address; no option and no extension. It starts an hour back, as -V -1h:+64d dates one, so that a verifier whose clock is behind this one takes it at once
}
dr_lifetime(){ # → the seconds each new prekey of this box is valid for: what its prekey-lifetime file names, a number of seconds alone on its line from 97200 (a day and three hours) to 2851200 (33 days), or 2851200 when it has none. A file that names anything else is a refusal, never the default: no prekey is signed until it is put right (PROTOCOL.md §12.4)
  local l; [ -e "$DR/prekey-lifetime" ] || { echo 2851200; return 0; }
  l=$(cat "$DR/prekey-lifetime" 2> /dev/null) && [[ $l =~ ^[1-9][0-9]{0,9}$ ]] && { printf '%s\n' "$l" | cmp -s - "$DR/prekey-lifetime" || printf '%s' "$l" | cmp -s - "$DR/prekey-lifetime"; } && [ "$l" -ge 97200 ] && [ "$l" -le 2851200 ] && echo "$l" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    dr_refuse "this box's prekey-lifetime file names no lifetime: one is a number of seconds, alone on its line, from 97200 (a day and three hours) to 2851200 (33 days)"
}
dr_prekey(){ # <serial> [--no-pq] → prekeys/<serial>.agekey and its statement, signed by a NEW working key (dr_work): a NEW key, valid for the box's prekey lifetime (dr_lifetime), and prekeys/<serial>.made, when it was signed: a statement an earlier attempt left is sent again only while it was made for no longer than the box's lifetime (dr_renew). A re-run reuses the key a failed attempt left, whatever its type, unless it is empty
  local A p="$DR/prekeys/$1" l t k; A=$(cat "$DR/address") || return 1
  [ -s "$p.txt.sig" ] && return 0
  dr_finished || { dr_done $?; return 1; }      # the one path to this box's certificates and statements: a box that holds its own revocation makes neither, init and prekey renew alike
  l=$(dr_lifetime) || return 1
  [ -s "$p.agekey" ] || { rm -f "$p.agekey"; if [ "${2-}" = --no-pq ]; then age-keygen -o "$p.agekey"; else age-keygen -pq -o "$p.agekey"; fi 2> /dev/null; } || dr_refuse "age-keygen failed: post-quantum needs age >= 1.3 (or make a box with --no-pq)" || return 1      # an empty key file, as a crash before the sync below leaves one, is no key, and no statement names it, so it is made again, as the Go client does
  k=$(age-keygen -y "$p.agekey" 2> /dev/null) || dr_refuse "age-keygen cannot read $p.agekey, the key this box began prekey $1 with (a post-quantum one needs age >= 1.3)" || return 1      # never a statement with no key in it, which a server refuses at every try
  dr_work "$1" && t=$(dr_now) || return 1
  printf 'dromas-prekey-v1\n%s\n%s\n%s\n%s\n' "$A" "$1" "$k" "$(jq -nr --argjson t "$t" --argjson l "$l" '$t + $l | todate')" > "$p.txt" &&
  jq -nr --argjson t "$t" '$t | todate' > "$p.made" &&      # before the signature: a statement is signed once its record is there
  ssh-keygen -q -Y sign -n "dromas-prekey-v1:$A" -f "$DR/work/$1-cert.pub" < "$p.txt" > "$p.txt.sig" &&      # stdin to stdout: never a stale .sig
  sync "$DR/work/$1" "$DR/work/$1.pub" "$DR/work/$1-cert.pub" "$DR/work" && sync "$p.agekey" "$p.txt" "$p.made" "$p.txt.sig" "$DR/prekeys"      # the working key first, each file in turn: a signed statement is never on disk without the key its pass needs      # on disk before any upload publishes the statement: a key lost to a crash after that is mail nobody can read
}
dr_init(){ # [--no-pq] → creates this box, or finishes a half-done init, and registers it; prints its address and link. The registration carries a pass the new working key signs, so the box is in use at once
  dr_opt "${1-}" || return 1
  dr_ownbox || return 1
  dr_dirs && dr_putline "$DR/.gitignore" '*' || return 1      # the box ignores itself, wherever it is
  [ -s "$DR/identity" ] || { rm -f "$DR/identity" "$DR/identity.pub"; ssh-keygen -q -t ed25519 -N '' -C '' -f "$DR/identity" < /dev/null; } || return 1      # an empty identity, as a crash before the sync below leaves one, is no key, and nothing was registered with it, so it is made again, as the Go client does
  if dr_held; then dr_identity; else dr_lock true; fi && sync "$DR/identity" "$DR/identity.pub" "$DR" || return 1      # identity.doc and address made under the box's lock, as every command that writes the box makes them (dr_lock): a command beside init reads them. The identity on disk before it is registered
  [ ! -s "$DR/serial" ] || { dr_addr; return; }      # registered already
  local A n p h c; A=$(cat "$DR/address")
  n=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); [ -n "$n" ] || n=$(dr_now); [ "$n" -ge 1 ] || n=1; p="$DR/prekeys/$n"      # the box's first prekey, working key and certificate take their number as every later one does, from this machine's clock in seconds (dr_renew): a second machine handed the same identity then makes no certificate of a serial this one used. An attempt that got as far as a key keeps the number it took, so a registration whose answer was lost is sent again as it was
  if c=$(dr_cert "$p.txt.sig" "$DR/identity.doc" "$A" 2> /dev/null) && c=${c#* } && [ "${c% *}" -gt $(($(dr_now) - 3600)) ]; then      # a first statement an earlier attempt left, under a certificate that began less than an hour before this machine's clock: made while the clock read ahead of where it reads now, as a pass made then is not used either (PROTOCOL.md §12.4), so a reader whose clock a server takes may not have reached its start. The working key, its certificate and the statement are made again. The prekey's own key stays: a server may have taken a registration whose answer was lost, and then mail may be waiting that only this key opens
    rm -f "$p.txt" "$p.made" "$p.txt.sig" "$DR/work/$n" "$DR/work/$n.pub" "$DR/work/$n-cert.pub" "$DR/pass.new"
  fi
  dr_prekey "$n" "${1-}" || return 1
  jq -n --arg i "$(dr_b64 "$DR/identity.doc")" --arg p "$(dr_b64 "$p.txt")" --arg s "$(dr_b64 "$p.txt.sig")" --argjson k "$(dr_senders)" '{identity:$i, prekey:$p, prekey_signature:$s, sender_key_types:$k}' > "$DR/register.json"
  h=$(dr_pass "$n") && { dr_api PUT "/v1/$A" "$DR/register.json" -H "Authorization: $h" > /dev/null || { dr_clock; dr_own; false; }; } && mv "$DR/pass.new" "$DR/pass" && dr_putline "$DR/serial" "$n" && dr_addr
}
dr_addr(){ local a; dr_held || { [ -s "$DR/identity" ] && [ -s "$DR/address" ]; } || { dr_lock dr_addr; return; }; a=$(cat "$DR/address") && dr_out box --arg address "$a" --arg link "$DR_BASE/to/$a"; }      # the box's address and its link: what to give whoever should write to it. Read with no lock; with no box, dr_lock's refusal, and a box restored from its identity alone has its files made under the lock first (dr_identity), as the Go client's Open makes them
dr_dest(){ # <link or address> → the address: 64 hex, or taken from a link to this box's server, $DR_BASE/to/<address>
  local a=${1#"$DR_BASE/to/"}
  dr_hex "$a" && { echo "$a"; return 0; }
  [[ $1 != *://* || $1 = "$DR_BASE/"* ]] || { dr_refuse "a link to another server: this box's server is $DR_BASE"; return 1; }
  dr_refuse "not an address or a link to one: $1"
}

# recipe: verify a peer
dr_keycheck(){ # <32 bytes in hex> → 0 only for an Ed25519 key that is a canonical point, not of small order
  [[ $1 =~ ^[0-9a-f]{64}$ && ! $1 =~ ^(e[d-f]|f[0-9a-f])(ff){30}(7f|ff)$ ]] || return 1      # y >= p: not canonical
  case $1 in      # the eight points of small order, and the two with x = 0 marked negative
    0100000000000000000000000000000000000000000000000000000000000000 | 0100000000000000000000000000000000000000000000000000000000000080 | \
    ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f | ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff | \
    0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000080 | \
    26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 | 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 | \
    c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a | c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa) return 1 ;;
  esac
  age -r "ssh-ed25519 $(printf "$(printf %s "0000000b$(dr_asc ssh-ed25519)00000020$1" | sed 's/../\\x&/g')" | base64 | tr -d '\n')" < /dev/null > /dev/null 2>&1      # a point on the curve: age decodes the key as the Go client's edwards25519 does, and refuses 32 bytes that are no point, which ssh-keygen reads as a key
}
dr_idcheck(){ # <identity document> [address] → 0 only for a two-line document whose key is in its one encoding and passes its type's checks (and hashing to the address, given one). 2 for a well-formed document of a key type this script does not verify: nothing is wrong with it, and nothing it signed can be checked here. 1 for anything else
  local f=$1 l t fp
  l=$(sed -n 2p "$f"); t=${l%% *}
  [ "$(printf 'dromas-v1\n%s\n' "$l" | sha256sum)" = "$(sha256sum < "$f")" ] || return 1      # exactly the tag line and one more, each ending in LF, and not a byte else: the file against itself rebuilt from its second line. A shell variable drops a NUL, so a test of the variable alone would pass a file that holds one
  [ -z "${2-}" ] || [ "$(sha256sum < "$f" | cut -c1-64)" = "$2" ] || return 1
  # the form every type shares: a key type's name (printable ASCII with no comma, at most 64 characters), one space, and the base64, in its one encoding, of a wire key that begins with that name
  grep -Eqx '[!-+.-~-]{1,64} [A-Za-z0-9+/]+={0,2}' <<< "$l" && [ "$(printf %s "${l#* }" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "${l#* }" ] &&
    [ "$(printf %s "${l#* }" | base64 -d | head -c $((4 + ${#t})) | od -An -v -tx1 | tr -d ' \n')" = "$(printf %08x "${#t}")$(dr_asc "$t")" ] || return 1
  case $t in ssh-ed25519 | ecdsa-sha2-nistp256) ;; *) return 2 ;; esac
  # the key in its one encoding: ssh-keygen reads it, and its fingerprint, the SHA-256 of the key as OpenSSH writes it back, is the SHA-256 of these bytes. ssh-keygen refuses a P-256 point off the curve, compressed, at infinity or with a coordinate not below the field's size, which is all a P-256 key is held to (PROTOCOL.md §4.1). Up to 10.2p1 it also refuses one with a coordinate of 128 bits or fewer, or of the group's order less one or more, which the protocol takes: a known variance (PROTOCOL.md Appendix A)
  fp=$(ssh-keygen -l -E sha256 -f - <<< "$l" 2> /dev/null | awk '{print $2}') && fp=${fp#SHA256:} && [ -n "$fp" ] &&
    [ "$(printf '%s=' "$fp" | base64 -d | od -An -v -tx1 | tr -d ' \n')" = "$(printf %s "${l#* }" | base64 -d | sha256sum | cut -c1-64)" ] || return 1
  case $t in      # then the type's own checks: an Ed25519 key canonical and not of small order
    ssh-ed25519) dr_keycheck "$(printf %s "${l#* }" | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n')" ;;
  esac
}
dr_sigmax(){ case $(sed -n 2p "$1" | cut -d' ' -f1) in ssh-ed25519 | ecdsa-sha2-nistp256) echo 4096 ;; *) return 1 ;; esac; }      # <identity document> → the most bytes a signature by a box of its key type may be, every byte of the file (PROTOCOL.md §3.2): each type states its own. Nothing for a type this script does not verify
dr_bound(){ local m; m=$(dr_sigmax "$2") && [ "$(wc -c < "$1")" -le "$m" ]; }      # <signature file> <identity document> → 0 only for a signature no longer than its identity's key type allows
dr_blob(){ # <signature file> → the SSHSIG blob it armors, in hex, read as ssh-keygen -Y verify reads it (OpenSSH's sshsig_dearmor), and only if the file is at most 4096 bytes in all, the most any identity key type allows (dr_sigmax): the BEGIN line first, ending in LF or CRLF; then base64 in its one encoding, with space, tab, LF, VT, FF and CR skipped wherever they are; then LF and the END line, after which nothing is read; one NUL may be the last byte before that LF, as OpenSSH's sshbuf_dup_string takes it. 1 for anything else, any other NUL included. The bytes are read as hex, never through a shell variable, which would drop a NUL
  local h b e t B E
  [ "$(wc -c < "$1")" -le 4096 ] || return 1      # the bound counts every byte of the file, what follows the END line too
  B=$(printf %s '-----BEGIN SSH SIGNATURE-----' | od -An -v -tx1 | tr -s ' \n' '  '); E=$(printf '\n%s' '-----END SSH SIGNATURE-----' | od -An -v -tx1 | tr -s ' \n' '  ')
  h=$(od -An -v -tx1 < "$1" | tr -s ' \n' '  ')      # every byte as " xx", and one space at the end: a match of " xx … xx " falls on whole bytes
  [[ $h == "$B"* ]] || return 1; h=" ${h#"$B"}"
  case $h in " 0d 0a "*) h=${h#" 0d 0a"} ;; " 0a "*) h=${h#" 0a"} ;; *) return 1 ;; esac
  b=${h%%"$E"*}; [ "$b" != "$h" ] || return 1      # up to the first LF and END line
  b=${b%" 00"}      # one NUL as its last byte
  for e in 20 09 0a 0b 0c 0d; do b=${b// $e/}; done
  [[ $b =~ ^( (3[0-9]|4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a]|2b|2f|3d))*$ ]] || return 1      # nothing left but the base64 alphabet and its padding
  t=$(printf "${b// /\\x}")
  [ -n "$t" ] && [ "$(printf %s "$t" | base64 -d 2> /dev/null | base64 | tr -d '\n')" = "$t" ] || return 1      # in its one encoding: padded, and the unused bits of the last character zero, as OpenSSH's decoder holds it
  printf %s "$t" | base64 -d | od -An -v -tx1 | tr -d ' \n'
}
dr_s(){ # <an SSH signature in hex: its type as a string, then its bytes as one> → 1 only for an Ed25519 signature that is not 64 bytes, or whose S is not below the group's order L: such a signature is invalid (RFC 8032 §5.1.7), and ssh-keygen before the cut PROTOCOL.md Appendix A gives takes one with L added to S. Its type may end in one NUL, as OpenSSH reads it. 0 for any other, which ssh-keygen judges
  local s="" i a b o= e L=1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
  e=$(dr_asc ssh-ed25519)
  [ "${1:0:30}" = "0000000b$e" ] && o=30; [ "${1:0:32}" = "0000000c${e}00" ] && o=32
  [ -n "$o" ] || return 0
  [ ${#1} -eq $((o + 136)) ] && [ "${1:o:8}" = 00000040 ] || return 1
  for ((i = o + 134; i >= o + 72; i -= 2)); do s+=${1:i:2}; done      # S is the signature's last 32 bytes, little-endian: here it is read the other way round, to compare with L
  for i in 0 8 16 24 32 40 48 56; do a=$((16#${s:i:8})); b=$((16#${L:i:8})); [ "$a" -lt "$b" ] && return 0; [ "$a" -gt "$b" ] && return 1; done
  return 1
}
dr_sshsig(){ # <signature file> → 0 only for a signature dr_blob reads that is an SSHSIG of version 0 or 1 (OpenSSH refuses only a higher one), five fields and nothing after them, whose own signature passes dr_s. It leaves the blob in x and its signing key in k, both in hex, for its caller, whose locals they are. The reserved field is read and skipped, as OpenSSH does: ssh-keygen verifies over an empty one
  local o=20 l v
  x=$(dr_blob "$1") && [[ ${x:0:20} =~ ^5353485349470000000[01]$ ]] || return 1      # "SSHSIG", version 0 or 1
  dr_str && k=$v && dr_str && dr_str && dr_str && dr_str && dr_s "$v" && [ "$o" -eq "${#x}" ]      # the signing key, the namespace, reserved, the hash, the signature: and nothing after
}
dr_cert(){ # <signature> <identity document> <address> → "<serial> <valid after> <valid before>", as Unix times, for the certificate the signature carries, only if it is in its one form (below) and names that identity as its signer. Its fields are read from its bytes, in order: ssh-keygen -Y verify takes a certificate with a critical option, or with extensions out of their order, and checks no key id. Whether the identity's signature on it is good, and whether it holds now, are dr_certified's
  local x o=20 l v k n a b      # x: the bytes being read, in hex; o: how far into them; v: the field just read
  dr_sshsig "$1" || return 1; x=$k; o=0      # the signing key: here, the certificate
  dr_str && [ "$v" = "$(dr_asc ssh-ed25519-cert-v01@openssh.com)" ] || return 1      # a certificate for an Ed25519 key
  dr_str || return 1      # the nonce
  dr_str && k=$v && dr_keycheck "$k" || return 1      # the working key, held to the identity's own key checks
  dr_u64 && n=$v && [ "$n" -ge 1 ] && [ "$n" -le 9007199254740991 ] || return 1      # the serial: from 1 to 2^53 - 1, as a prekey's
  [ "${x:o:8}" = 00000001 ] || return 1; o=$((o + 8))      # a user certificate
  dr_str && [ "$v" = "$(dr_asc dromas-cert-v1)" ] || return 1      # the key id
  dr_str && [ "$v" = "00000040$(dr_asc "$3")" ] || return 1      # exactly one principal: the address
  dr_u64 && a=$v && dr_u64 && b=$v || return 1      # valid after, valid before
  dr_str && [ -z "$v" ] || return 1      # no critical option: one a verifier does not know is refused, and none is known here
  dr_str && dr_exts "$v" && dr_str || return 1      # the extensions, each ignored, as one a verifier does not know is; then reserved, whatever it holds, ignored too
  dr_str && [ "$v" = "$(sed -n 2p "$2" | cut -d' ' -f2 | base64 -d | od -An -v -tx1 | tr -d ' \n')" ] && [ "$v" != "0000000b$(dr_asc ssh-ed25519)00000020$k" ] || return 1      # signed by the identity's key, byte for byte, which is never the working key
  dr_str && dr_s "$v" && [ "$o" -eq "${#x}" ] || return 1      # the identity's signature on it, and nothing after
  echo "$n $a $b"
}
dr_exts(){ # dr_cert's: <a certificate's extensions, in hex> → 0 only for them in their one encoding, as the Go client's library reads them: each name once, in lexical order, and its value nothing or one string that is not empty. What each says is never read: none is known here
  local x=$1 o=0 l v n p=
  while [ "$o" -lt "${#x}" ]; do
    dr_str && n=$v && { [ -z "$p" ] || [ "$p" \< "$n" ]; } && dr_str || return 1      # the name, after the last; [ compares bytes, as their hex compares
    [ -z "$v" ] || { [[ ${v:0:8} =~ ^[0-9a-f]{8}$ ]] && [ $((16#${v:0:8})) -gt 0 ] && [ $((8 + 2 * 16#${v:0:8})) -eq ${#v} ]; } || return 1      # the value
    p=$n
  done
}
dr_str(){ [[ ${x:o:8} =~ ^[0-9a-f]{8}$ ]] || return 1; l=$((16#${x:o:8} * 2)); [ $((o + 8 + l)) -le ${#x} ] || return 1; v=${x:o+8:l}; o=$((o + 8 + l)); }      # dr_cert's: the next length-prefixed string of x, in hex, into v
dr_u64(){ [[ ${x:o:16} =~ ^[0-7][0-9a-f]{15}$ ]] || return 1; v=$((16#${x:o:16})); o=$((o + 16)); }      # dr_cert's: the next 64-bit number of x into v. One with its top bit set is no time and no serial here
dr_certified(){ # <address> <identity document> <namespace> <signature> <message> [at] → "<certificate serial> <its valid before>" only for a signature by a working key under a certificate of that identity that holds at the time given (now, without one): begun, not ended, and ending at most 64 days and an hour on. 1 otherwise; 2 when all that fails is that it has ended, 3 that it has not begun. A signature by the identity itself, or by a key with no certificate, is refused
  local A=$1 r n a b t=${6:-$(dr_now)}
  dr_bound "$4" "$2" && r=$(dr_cert "$4" "$2" "$A") || return 1; read -r n a b <<< "$r"
  printf '%s cert-authority %s\n' "$A" "$(sed -n 2p "$2")" > "$DR/signers"      # ONE line, built from checked bytes: only a certificate this identity signed, for this address
  ssh-keygen -Y verify -f "$DR/signers" -I "$A" -n "$3" -s "$4" -O verify-time="$(dr_stamp $((a > 0 ? a : 1)))" < "$5" > /dev/null 2>&1 || return 1      # the two signatures, the identity's on the certificate and the working key's on the message, judged where the certificate begins (a second in, for one that begins at 0: ssh-keygen takes no verify-time of 0); the time is the next line's
  [ "$a" -le "$t" ] || return 3; [ "$t" -lt "$b" ] || return 2; [ "$b" -le $((t + 64*86400 + 3600)) ] || return 1
  echo "$n $b"
}
dr_bech32(){ # <string> → its human-readable part, only for a Bech32 string (BIP 173) as age writes a recipient: in lowercase, its checksum good, and its data whole bytes, with fewer than five bits left over and those zero. age takes one of any length, where BIP 173 stops at 90, and so does this. 1 for anything else
  local s=$1 h d cs=qpzry9x8gf2tvdw0s3jn54khce6mua7l v=() i c k m n chk=1 top g=(0x3b6a57b2 0x26508e6d 0x1ea119fa 0x3d4233dd 0x2a1462b3)
  [[ $s = *1* ]] || return 1; h=${s%1*}; d=${s##*1}; [ ${#h} -ge 1 ] && [ ${#d} -ge 6 ] || return 1      # split at the last 1: a part before it, and six characters of checksum at least after it
  for ((i = 0; i < ${#h}; i++)); do c=$(printf %d "'${h:i:1}"); ((c >= 33 && c <= 126 && (c < 65 || c > 90))) || return 1; v+=($((c >> 5))); done; v+=(0)      # printable ASCII, no capital
  for ((i = 0; i < ${#h}; i++)); do v+=($(($(printf %d "'${h:i:1}") & 31))); done
  for ((i = 0; i < ${#d}; i++)); do k=${cs%%"${d:i:1}"*}; [ ${#k} -lt 32 ] || return 1; v+=(${#k}); done      # each character's value is its place in the alphabet
  for k in "${v[@]}"; do top=$((chk >> 25)); chk=$((((chk & 0x1ffffff) << 5) ^ k)); for i in 0 1 2 3 4; do ((top >> i & 1)) && chk=$((chk ^ g[i])); done; done
  n=$((${#d} - 6)); c=$((n * 5 % 8)); k=$((n > 0 ? v[${#v[@]} - 7] : 0)); m=$(((1 << c) - 1))      # the bits left over are the low bits of the last data character
  ((chk == 1 && c < 5 && (k & m) == 0)) || return 1
  printf '%s\n' "$h"
}
dr_prekeycheck(){ # <statement> <signature> <address> <identity document> [at] → "<serial> <age recipient> <not_after as Unix time> <certificate serial>" only for five LF-ended lines naming that address, signed by a working key its identity certified, not outliving that certificate, holding a key age will encrypt to; otherwise the reason, and 1. 2, with the reason, for one good in every other way whose key is a well-formed age recipient of a type this script cannot encrypt to: its Bech32 human-readable part begins age, and is neither X25519's age nor the hybrid's age1pq. Nothing is wrong with such a statement (PROTOCOL.md §6), so its key's type is the last thing checked
  local p=$1 B=$3 s k na c L
  c=$(dr_certified "$B" "$4" "dromas-prekey-v1:$B" "$2" "$p" ${5-}); case $? in 0) ;;
    2) echo "$B's prekey: the certificate the prekey is signed under has ended"; return 1 ;;
    3) echo "$B's prekey: the certificate the prekey is signed under has not begun, by the clock that checked it"; return 1 ;;
    *) echo "$B's prekey is not signed by a working key its identity certified, under a certificate that holds now"; return 1 ;;
  esac
  mapfile -t L < "$p"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$p")" ] && [ ${#L[@]} -eq 5 ] && [ "${L[0]}" = dromas-prekey-v1 ] && [ "${L[1]}" = "$B" ] ||      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
    { echo "the prekey statement is not $B's: five lines, each ending in LF"; return 1; }
  s=${L[2]}; [[ $s =~ ^[1-9][0-9]{0,15}$ ]] && [ "$s" -le 9007199254740991 ] || { echo "$B's prekey serial is malformed"; return 1; }      # from 1 to 2^53 - 1, as every serial is written
  na=$(dr_time "${L[4]}") || { echo "$B's prekey has no valid not_after"; return 1; }
  [ "$na" -le "${c#* }" ] || { echo "$B's prekey statement outlives the certificate it is signed under"; return 1; }
  k=${L[3]}
  case $(dr_bech32 "$k") in      # the key's type is its human-readable part, read before age is: age 1.3 encrypts to more types than the protocol defines, and to an SSH key
    age | age1pq) if ! age -r "$k" < /dev/null > /dev/null 2>&1; then
        if [[ $k = age1pq1* ]]; then echo "$B's prekey is post-quantum, and this age ($(age --version 2> /dev/null)) cannot encrypt to one: that takes age >= 1.3"; else echo "$B's prekey is not an age key that age will encrypt to"; fi; return 1
      fi ;;
    age*) echo "$B's prekey is an age recipient of a type this script cannot encrypt to, so nothing is sent"; return 2 ;;
    *) echo "$B's prekey is not an age key that age will encrypt to"; return 1 ;;
  esac
  echo "$s $k $na ${c% *}"
}
dr_resolve(){ # <address> [the box dr_lookup read] → prints "<serial> <age recipient> <certificate serial>" only when EVERY check passes; otherwise there is nothing to encrypt to. The identity is the pinned one, or at first contact the served one, kept only once its prekey statement has verified. Without a box read for it, it reads one, and keeps what verifies of the revocation of certificates it carries before the statement is checked against it
  local B=$1 d="$DR/peers/$1" f r s k na c sc
  dr_hex "$B" || dr_refuse "not an address" || return 1
  dr_gone "$B"; case $? in      # a peer this box holds a revocation of is refused before anything is asked, whatever the server now serves for it
    0) dr_err "REVOKED: $B is revoked, for good, and the revocation verifies: ask its owner for their new address"; return 1 ;;
    3) dr_refuse "the revocation kept for $B does not verify"; return 1 ;;
  esac
  if [ -n "${2-}" ] && [ -s "$2" ]; then cp "$2" "$DR/peer.json" || return 1
  else dr_look "$B" > "$DR/peer.json" || return 1
    dr_isbox "$DR/peer.json" && jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/peer.json" > "$DR/rev.json" ||
      dr_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
    dr_take "$B"; [ $? != 3 ] || dr_refuse "what this box keeps about $B does not verify, or could not be written" || return 1
  fi
  dr_shape "$DR/peer.json" box && dr_bytes "$DR/peer.json" identity "$DR/new.doc" && dr_bytes "$DR/peer.json" prekey "$DR/peer.txt" && dr_bytes "$DR/peer.json" prekey_signature "$DR/peer.sig" ||
    dr_refuse "the server's answer for $B is not one this client reads: one JSON object, each byte field base64" || return 1
  f="$d/identity.doc"      # a pin always wins
  [ -e "$f" ] || { f="$DR/new.doc"; [ -s "$f" ] || dr_refuse "no identity for $B in the response" || return 1; }
  [ "$(sha256sum < "$f" | cut -c1-64)" = "$B" ] || dr_refuse "the identity the server sent does not hash to $B" || return 1
  dr_idcheck "$f"; case $? in 0) ;;
    2) dr_refuse "$B's identity is of a key type this script does not verify, so nothing it signs can be checked here and nothing is sent"; return 1 ;;
    *) dr_refuse "$B's identity is not a two-line identity document in the one form of its key type, with a valid key"; return 1 ;;
  esac
  [ -s "$DR/peer.txt" ] && [ -s "$DR/peer.sig" ] || dr_refuse "no prekey for $B in the response" || return 1
  r=$(dr_prekeycheck "$DR/peer.txt" "$DR/peer.sig" "$B" "$f"); case $? in 0) ;;
    2) jq -cn --arg m "REFUSED: $r" '{type:"error", code:"unsupported_prekey_type", message:$m}' >&2; return 1 ;;      # a refusal with a code of its own: nothing is wrong with the statement
    *) dr_refuse "$r"; return 1 ;;
  esac
  read -r s k na c <<< "$r"
  sc=$(cat "$d/cert-serial" 2> /dev/null || echo 0)      # a box's statements are ordered by their certificate first, then by their own serial: a later certificate outranks any serial under an earlier one, so a box that moved to a new certificate is followed whatever serial it publishes
  [ "$c" -ge "$sc" ] || dr_refuse "rollback: $B's prekey is signed under certificate $c, below one already seen" || return 1
  [ "$c" -gt "$sc" ] || [ "$s" -ge "$(cat "$d/serial" 2> /dev/null || echo 0)" ] || dr_refuse "rollback: $B's prekey serial $s is below one already seen" || return 1
  dr_certrevoked "$B" "$c"; case $? in      # by what this box holds: only the identity's own signature revokes a certificate
    0) dr_refuse "$B's prekey is signed under a certificate its identity has revoked: its owner must publish a new one"; return 1 ;;
    3) dr_refuse "the revocation of certificates kept for $B does not verify"; return 1 ;;
  esac
  [ "$na" -gt "$(dr_now)" ] || dr_refuse "$B's prekey has expired: its owner must publish a new one" || return 1
  dr_meet "$B" "$f" && dr_putline "$d/serial" "$s" && dr_putline "$d/cert-serial" "$c" && dr_put "$DR/peer.txt" "$d/prekey.txt" && dr_put "$DR/peer.sig" "$d/prekey.sig" || return 1      # recorded only after every check passed
  echo "$s $k $c"
}
dr_put(){ local d; d=$(dirname "$2") && cp "$1" "$2.new" && sync "$2.new" && mv "$2.new" "$2" && sync "$d"; }      # <file> <path> → <path> holds the file's bytes, on disk before this returns: written beside it, synced, moved into place, and its directory synced, as the Go client's writeFile does. A crash leaves the old file or the new one, never an empty one
dr_putline(){ local d; d=$(dirname "$1") && printf '%s\n' "$2" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d"; }      # <path> <value> → dr_put of the value alone on its line
dr_putout(){ local d; d=$(dirname "$1") && "${@:2}" > "$1.new" && sync "$1.new" && mv "$1.new" "$1" && sync "$d" || { rm -f "$1.new"; return 1; }; }      # <path> <command> [args] → dr_put of what the command prints: a command that fails or is stopped midway leaves no file cut short
dr_meet(){ local d="$DR/peers/$1"; mkdir -p "$d" && { [ -e "$d/identity.doc" ] || dr_put "$2" "$d/identity.doc"; }; }      # <address> <its checked identity document> → pinned, unless it is already: called only for an identity that signed something this box verified

# recipe: revocation
dr_revcheck(){ # <address> <identity document> <signature> → 0 only for a revocation of that address: the document hashes to it and is one this script verifies, and the signature is that identity's OWN over the fixed statement. The signers line names the identity's key with no cert-authority, so a working key's signature, which carries a certificate, is not taken: a working key can be stolen without the identity, and must not end the address
  local x k
  dr_idcheck "$2" "$1" && dr_bound "$3" "$2" && dr_sshsig "$3" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$DR/signers"
  printf 'dromas-revoke-v1\n%s\n' "$1" | ssh-keygen -Y verify -f "$DR/signers" -I "$1" -n "dromas-revoke-v1:$1" -s "$3" > /dev/null 2>&1
}
dr_gone(){ # <address> → 0 if this box holds a revocation of it: peers/<address>/revoke.sig beside its pinned identity, or revoked.sig for this box's own. It is checked again each time. 1 if none is kept. 3 if one is kept and does not verify: a fault of this box, never a quiet "not revoked"
  local d="$DR/peers/$1/identity.doc" s="$DR/peers/$1/revoke.sig"
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || { d="$DR/identity.doc"; s="$DR/revoked.sig"; }
  [ -e "$s" ] || return 1
  dr_revcheck "$1" "$d" "$s" || return 3
}
dr_certscheck(){ # <address> <identity document> <statement> <signature> → the serial it revokes through, only for a revocation of that address's certificates: signed by its identity's OWN key, as a revocation of the address is (no cert-authority, so a certificate cannot revoke another, or itself), and in its one exact form, the tag, the address and a serial, each on a line ending in LF, and nothing else. The serial is from 1 to 2^53 - 1 with no leading zero, compared by bash, whose numbers are exact there where awk's are not
  local L x k
  dr_idcheck "$2" "$1" && dr_bound "$4" "$2" && dr_sshsig "$4" || return 1
  printf '%s %s\n' "$1" "$(sed -n 2p "$2")" > "$DR/signers"
  ssh-keygen -Y verify -f "$DR/signers" -I "$1" -n "dromas-revoke-certs-v1:$1" -s "$4" < "$3" > /dev/null 2>&1 || return 1
  mapfile -t L < "$3"
  [ "$(printf '%s\n' "${L[@]}" | sha256sum)" = "$(sha256sum < "$3")" ] || return 1      # the file against itself rebuilt from its lines: every line ends in LF, and nothing is in it that a shell variable drops (a NUL)
  [ ${#L[@]} -eq 3 ] && [ "${L[0]}" = dromas-revoke-certs-v1 ] && [ "${L[1]}" = "$1" ] && [[ ${L[2]} =~ ^[1-9][0-9]{0,15}$ ]] && [ "${L[2]}" -le 9007199254740991 ] || return 1
  echo "${L[2]}"
}
dr_certskept(){ # <address> → the serial through which this box holds that address's certificates revoked, checked again as it is read. It is kept as the record that carries it, one line of JSON {type, identity, revoked_certificates, revoked_certificates_signature}: peers/<address>/revoked-certs.json beside the pinned identity, or revoked-certs.json for this box's own. 1 if none is kept. 3 if one is kept and does not verify under the identity this box holds for the address: a fault of this box, never a quiet "nothing revoked"
  local d="$DR/peers/$1/identity.doc" f="$DR/peers/$1/revoked-certs.json"
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || { d="$DR/identity.doc"; f="$DR/revoked-certs.json"; }
  [ -e "$f" ] || return 1
  dr_shape "$f" record && dr_bytes "$f" revoked_certificates "$DR/kept.certs" && dr_bytes "$f" revoked_certificates_signature "$DR/kept.csig" &&
    dr_certscheck "$1" "$d" "$DR/kept.certs" "$DR/kept.csig" || return 3
}
dr_certrevoked(){ # <address> <certificate serial> → 0 if the address's identity has revoked the certificate, by what this box holds. 1 if nothing is kept, or what is kept runs below it. 3 if what is kept does not verify
  local x
  x=$(dr_certskept "$1") || return
  [ "$2" -le "$x" ]
}
dr_keepcerts(){ # <address> <identity document> <statement> <signature> → keeps the revocation of the address's certificates, if it verifies and runs through a higher serial than the one this box holds: the highest stands, and a certificate once revoked stays so. One that does not verify, or runs no higher, changes nothing. 1 only for a fault of this box
  local f="$DR/peers/$1/revoked-certs.json" v h
  [ "$1" != "$(cat "$DR/address" 2> /dev/null)" ] || f="$DR/revoked-certs.json"
  v=$(dr_certscheck "$1" "$2" "$3" "$4") || return 0
  h=$(dr_certskept "$1"); case $? in 0) [ "$v" -gt "$h" ] || return 0 ;; 1) ;; *) return 1 ;; esac
  [ "$f" = "$DR/revoked-certs.json" ] || dr_meet "$1" "$2" || return 1
  dr_b64 "$2" > "$f.i" && dr_b64 "$3" > "$f.l" && dr_b64 "$4" > "$f.g" && jq -cn --rawfile i "$f.i" --rawfile l "$f.l" --rawfile g "$f.g" '{type:"revocation_record", identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$f.new" && sync "$f.new" && mv "$f.new" "$f" && sync "$(dirname "$f")" && rm -f "$f.i" "$f.l" "$f.g"      # one file, moved into place whole and on disk before anything reads it: a statement is never kept without the signature that goes with it
}
dr_keep(){ # <address> <its identity document> <signature> → the revocation, kept for good: called only once dr_revcheck took it. A revoked address stays revoked
  if [ "$1" = "$(cat "$DR/address" 2> /dev/null)" ]; then dr_put "$3" "$DR/revoked.sig"; else dr_meet "$1" "$2" && dr_put "$3" "$DR/peers/$1/revoke.sig"; fi
}
dr_record(){ # <record> → the address it is a revocation of, only if it verifies; its parts are left in $DR/rev.doc and $DR/rev.sig. A record is one line of JSON, {type, identity, revocation_signature}: its type, revocation_record, which this script does not read, then the identity document and the signature, each base64
  local A
  dr_isrecord "$1" && dr_bytes "$1" identity "$DR/rev.doc" && dr_bytes "$1" revocation_signature "$DR/rev.sig" || return 1
  A=$(sha256sum < "$DR/rev.doc" | cut -c1-64) && dr_revcheck "$A" "$DR/rev.doc" "$DR/rev.sig" && echo "$A"
}
dr_isrecord(){ # <file> → 0 only for a record: an answer dr_shape takes as a record, and each of its four byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  dr_shape "$1" record || return 1
  for m in identity revocation_signature revoked_certificates revoked_certificates_signature; do dr_bytes "$1" $m "$DR/record.part" || { r=1; break; }; done
  rm -f "$DR/record.part"; return $r
}
dr_isbox(){ # <file> → 0 only for a box: an answer dr_shape takes as a box, and each of its byte members base64, or left out. What it holds is checked by whoever uses it
  local m r=0
  dr_shape "$1" box || return 1
  for m in identity prekey prekey_signature revoked_certificates revoked_certificates_signature; do dr_bytes "$1" $m "$DR/box.part" || { r=1; break; }; done
  rm -f "$DR/box.part"; return $r
}
dr_take(){ # <address> → keeps what verifies of $DR/rev.json, a server's answer about the address: a revocation of its certificates, of the address, or both. 0: this box now holds a revocation of the address. 1: it does not: what the answer showed of one does not verify, which counts as nothing shown. 3: a fault of this box
  if dr_bytes "$DR/rev.json" identity "$DR/rev.doc" && dr_bytes "$DR/rev.json" revoked_certificates "$DR/rev.certs" && [ -s "$DR/rev.certs" ] &&
    dr_bytes "$DR/rev.json" revoked_certificates_signature "$DR/rev.csig"; then      # a revocation of certificates rides in the same record. It is taken or not on its own: the address may well go on
    dr_keepcerts "$1" "$DR/rev.doc" "$DR/rev.certs" "$DR/rev.csig" || return 3
  fi
  [ "$(dr_record "$DR/rev.json")" = "$1" ] || return 1
  dr_keep "$1" "$DR/rev.doc" "$DR/rev.sig" || return 3
}
dr_lookup(){ # <address> → reads the address's box from this box's server (GET /v1/<address>, dr_look), and keeps what verifies of the revocations it carries. A box served carries the revocation of its certificates the server holds, and a revoked address is answered 410 revoked with its record. The box served is left in $DR/box.json, for the seal that follows. 0: this box holds a revocation of the address, and that is final. 1: none: the server served the box, or holds no such box, or said revoked and showed nothing that verifies, which comes to the same: only the identity's own signature revokes. 2: no answer from the box's own server, which is not "none". 3: a fault of this box: what it keeps for the address does not verify, or cannot be written
  local r
  rm -f "$DR/box.json"
  dr_gone "$1"; case $? in 0) return 0 ;; 3) return 3 ;; esac
  if dr_look "$1" > "$DR/look.json" 2> "$DR/read.err"; then dr_isbox "$DR/look.json" || return 2; mv "$DR/look.json" "$DR/box.json"      # a 2xx that is no box is no answer, as one that is no JSON is
    jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/box.json" > "$DR/rev.json" && dr_take "$1"; r=$?; [ $r = 1 ] || return $r
  else case $(dr_code) in
    revoked) dr_takerecord "$1"; r=$?; [ $r = 1 ] || return $r ;;      # the record it carries proves itself, or counts as nothing shown
    no_such_mailbox) ;;
    *) cat "$DR/read.err" >&2; return 2 ;; esac; fi      # no answer: its error line, the status, the code and the wait, and none of the server's words
  return 1
}
dr_takerecord(){ # <address> → keeps what verifies of the record a 410 revoked carries, in $DR/error.json: dr_take's answer, or 1 where it carries no record
  jq -ce '.record | objects' "$DR/error.json" > "$DR/rev.json" 2> /dev/null && dr_isrecord "$DR/rev.json" || return 1
  dr_take "$1"
}
dr_finished(){ # → 0 while this box may act as its address. 1: it holds its own revocation, which verifies, and signs nothing more as that address, no pass, no mail and no certificate, whatever any server answers: a server that never saw the revocation would take it all (PROTOCOL.md §12.5). It still asks, keeps and publishes the record, which carry no pass. 3: the one it keeps does not verify, a fault of this box, which stops the same
  dr_gone "$(cat "$DR/address" 2> /dev/null)"; case $? in 1) return 0 ;; 0) return 1 ;; *) return 3 ;; esac
}
dr_done(){ # <what dr_finished returned> → says on stderr why this box acts as its address no more
  case $1 in
    1) dr_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box and give its address to those who write to this one" ;;
    *) dr_refuse "this box's own revocation (revoked.sig) does not verify: a fault of this box, which acts as its address no more until it is put right" ;;
  esac
  return 1
}
dr_own(){ # after a call as this box failed: if the server said this box is revoked, asks it for the revocation, and says which it is. A server's word revokes nothing
  [ "$(dr_code)" = revoked ] || return 0
  if dr_lookup "$(cat "$DR/address")"; then dr_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box and give its address to those who write to this one"
  else dr_err "the server showed no revocation of this box that verifies, so this box does not take itself as revoked"; fi
}

# recipe: send
dr_uuid(){ local h; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" $(( 0x${h:16:1} & 3 | 8 )) "${h:17:3}" "${h:20:12}"; }
dr_send(){ # <link or address> [body file] → one message, posted now or not at all: its envelope built once, then sealed and posted (dr_post), and nothing kept to post again. A send that fails says so and leaves nothing: run it again, and if the first post's answer was lost its reader gets two messages, under two msg_ids
  dr_held || { dr_lock dr_send "$@"; return; }
  local B f A id
  f=${2-}; A=$(cat "$DR/address") && B=$(dr_dest "${1-}") || return 1
  { if [ -n "$f" ]; then cat < "$f"; else cat; fi; } > "$DR/body.new" 2> /dev/null && mv "$DR/body.new" "$DR/body.txt" || { rm -f "$DR/body.new"; dr_err "the body${f:+ file $f} could not be read: nothing is sent"; return 1; }; f="$DR/body.txt"      # read ONCE, from the file named or stdin, into a new file moved into place: every check below and the envelope read these bytes, so a body from a pipe is sent, one changed after its check is not, and a body named $DR/body.txt is not emptied before it is read
  iconv -f UTF-8 -t UTF-8 < "$f" > /dev/null 2>&1 || dr_refuse "the body is not UTF-8 text" || return 1
  id=$(dr_uuid) || return 1
  jq -cn --arg from "$A" --arg to "$B" --arg id "$id" --argjson t "$(dr_now)" --arg i "$(dr_b64 "$DR/identity.doc")" --rawfile body "$f" \
    '{v:1, from:$from, to:$to, sent_at:($t|todate), msg_id:$id, identity:$i, body:$body}' > "$DR/send.P" 2> /dev/null || { rm -f "$DR/send.P"; dr_err "the envelope could not be built: nothing is sent"; return 1; }      # ONE line, ending in a line feed: exactly the bytes that are signed. It carries this box's identity document, so its reader need not ask the server who wrote it
  why=$(dr_envcheck "$DR/send.P" "$A" "$B") || { rm -f "$DR/send.P"; dr_refuse "nothing is sent, since its reader would refuse this message: ${why#*: }"; return 1; }      # read back as its reader will, and as dr_seal does
  dr_post "$B" "$DR/send"; local rc=$?; rm -f "$DR/send.P"; return $rc
}
dr_agehead(){ if [[ $1 = age1pq1* ]]; then echo 1627; else echo 168; fi; }      # <age recipient> → the size of an age file's header for one key of its type: its fields are fixed-size, so it never varies
dr_sealed(){ echo $(($(dr_agehead "$2") + 16 + $1 + 16 * ($1 > 65536 ? ($1 + 65535) / 65536 : 1))); }      # <plaintext bytes> <age recipient> → the size of the age file holding them: the header, a 16-byte nonce, and a 16-byte tag after each 64 KiB chunk
dr_blocks(){ # <size> → the size rounded up to a whole number of blocks. A block is 1/16 of the size, rounded up to a power of two, and never under 1 KiB: 1 KiB blocks up to 16 KiB, 2 KiB up to 32 KiB, and on
  local b=1024; while [ $((16 * b)) -lt "$1" ]; do b=$((b * 2)); done; echo $((($1 + b - 1) / b * b))
}
dr_padding(){ # <message bytes: the envelope's line and its signature> <age recipient> → "<padding bytes> <age file size>": the padding after the signature that makes the age file a whole number of blocks, so the server sees a message's size only to within a block. A message already on a block gets none
  local n=$1 s c; s=$(dr_blocks "$(dr_sealed "$n" "$2")"); c=$((s - $(dr_agehead "$2") - 16))      # what a file of that size has for its chunks, each with its tag
  echo "$((c - 16 * (c > 65552 ? (c + 65551) / 65552 : 1) - n)) $s"
}
dr_seal(){ # <address> <envelope stem> [the box dr_lookup read] → what to post: $DR/seal.age, the envelope <stem>.P dated at this post ($DR/seal.P: its sent_at this clock, and nothing else changed, as a signed request's time is when it was signed, made anew for each attempt), signed for that recipient only, by the working key in use, then the line, the signature and the padding encrypted to the recipient's VERIFIED prekey; and $DR/seal.query, the query that names that prekey. It is git's layout for a signed tag: the signed bytes as they are, then the signature block. The envelope is read as its recipient will read it first. A seal is made for one post and never kept: dr_post seals the envelope again for its one retry
  local B=$1 o=$2 s="$DR/seal" A r k n f t c why ps pc d; rm -f "$s.P" "$s.sig" "$s.age" "$s.query"; A=$(cat "$DR/address") && n=$(cat "$DR/serial") || return 1
  why=$(dr_envcheck "$o.P" "$A" "$B") && [ "$(wc -l < "$o.P")" -eq 1 ] && [ "$(jq -r .identity "$o.P")" = "$(dr_b64 "$DR/identity.doc")" ] || dr_refuse "the envelope is not one this box made for that address${why:+: $why}" || return 1
  d=$(jq -nr --argjson t "$(dr_now)" '$t | todate') && jq -c --arg d "$d" '.sent_at = $d' "$o.P" > "$s.P" || return 1      # written again by jq, as dr_send wrote it: the script seals only an envelope it has just built
  why=$(dr_envcheck "$s.P" "$A" "$B") && [ "$(wc -l < "$s.P")" -eq 1 ] && jq -e --arg d "$d" --slurpfile w "$o.P" '.sent_at == $d and del(.sent_at) == ($w[0] | del(.sent_at))' "$s.P" > /dev/null 2>&1 ||
    dr_refuse "the envelope does not read back as itself once dated at this post${why:+: $why}" || return 1
  c=$(dr_cert "$DR/prekeys/$n.txt.sig" "$DR/identity.doc" "$A") && [ $((${c##* } - $(dr_now))) -gt $((33*86400)) ] ||      # the certificate in use: the one this box's published prekey is signed under
    dr_refuse "this box's certificate ends within 33 days, too soon to sign mail that may wait that long (or it has no working key): rekey makes a new one" || return 1
  dr_certrevoked "$A" "${c%% *}"; case $? in      # a certificate this box's own identity has revoked signs no mail: every reader that holds the revocation refuses it, whatever this box's server took. That is the remedy's window while its renewal waits (PROTOCOL.md §12.6): the entry waits too
    0) dr_refuse "this box's identity has revoked the certificate it signs under, so mail signed now would be refused: prekey renew publishes the new one first"; return 1 ;;
    1) ;;
    *) dr_refuse "this box's own revocation of its certificates does not verify"; return 1 ;;
  esac
  r=$(dr_resolve "$B" "${3-}") && read -r ps k pc <<< "$r" && [ -n "$pc" ] || return 1
  ssh-keygen -q -Y sign -n "dromas-msg-v1:$B" -f "$DR/work/$n-cert.pub" < "$s.P" > "$s.sig" && tail -n 1 "$s.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||
    dr_refuse "the working key did not sign the message whole: nothing is sent" || return 1      # ssh-keygen does not check its write to stdout: a full disk leaves the file short and exits 0
  read -r f t <<< "$(dr_padding $(($(wc -c < "$s.P") + $(wc -c < "$s.sig"))) "$k")" && [ -n "$t" ] || return 1
  { cat "$s.P" "$s.sig" && head -c "$f" /dev/zero | tr '\0' .; } | age -r "$k" > "$s.age" || return 1
  [ "$(wc -c < "$s.age")" -eq "$t" ] || { rm -f "$s.age"; dr_refuse "the encrypted message is not the $t bytes its padding was made for: it is not sent at a size that tells its length"; return 1; }
  printf 'prekey_serial=%s&certificate_serial=%s\n' "$ps" "$pc" > "$s.query"      # the prekey is named by both serials, its own and its certificate's, written as the digits dr_resolve checked. The body is the age file as it is, and no signature is beside it: the server knows the sender from the pass the post carries
}
dr_post(){ # <address> <envelope stem> → seals it and POSTs it; on 409 stale_prekey, seals the SAME envelope again, once, to the box read again. Before each seal, the recipient's box is read (dr_lookup), and the seal is made to what this box then holds, dated after that read. A post that fails is told, and nothing is kept
  local B=$1 o=$2 c try
  dr_finished; case $? in      # a box that holds its own revocation can never deliver it: every reader that holds the revocation refuses its mail, whenever it was signed
    0) ;;
    1) dr_err "REVOKED: this box's own address is revoked, for good, and the revocation verifies, so its mail can never be delivered: nothing is sent"; return 1 ;;
    *) dr_done 3; return 1 ;;
  esac
  for try in first retry; do
    rm -f "$DR/error.json"
    dr_lookup "$B"; case $? in      # asked before every post, the retry's included: what verifies is kept, and "none held" is the server's word, kept nowhere
      0) dr_err "REVOKED: $B is revoked, for good, and the revocation verifies, so it can never be delivered: nothing is sent"; return 1 ;;
      1) rm -f "$DR/error.json" ;;      # its 404 is an answer, and not one about the message
      2) rm -f "$DR/error.json"; dr_err "the box $B could not be read, so nothing is sent"; return 1 ;;      # no answer is not "none held". Whatever code the failed lookup carried is no answer about the message
      *) dr_refuse "what this box keeps about $B does not verify, or could not be written: nothing is sent"; return 1 ;;
    esac
    dr_seal "$B" "$o" "$DR/box.json" && dr_owner POST "/v1/$B/messages?$(cat "$DR/seal.query")" "$DR/seal.age" > "$DR/receipt.json" && dr_receipt && { dr_sent "$B"; return; }      # sealed to the box the lookup read, and dated once it was read
    [ "$try" = first ] && [ "$(dr_code)" = stale_prekey ] || break      # a newer prekey: the same envelope, sealed again once, to the box read again
  done
  c=$(dr_code)
  case $c in revoked) dr_lookup "$B" ;; sender_revoked) dr_lookup "$(cat "$DR/address")" ;; esac      # a server's "revoked" is checked: with the revocation in hand it is final, and without one it is a call that failed
  if dr_gone "$B" || dr_gone "$(cat "$DR/address")"; then dr_err "REVOKED: the revocation verifies, so it can never be delivered: nothing is sent"; return 1; fi
  case $c in
    revoked | sender_revoked) dr_err "the server showed no revocation that verifies, so this box does not take that address as revoked: nothing is sent" ;;
    *) dr_err "nothing is sent" ;;
  esac
  return 1
}
dr_receipt(){ # → 0 only for a receipt in $DR/receipt.json that names the ciphertext this box posted, $DR/seal.age (its id the SHA-256 of it, PROTOCOL.md §11.10), and whose times are times. Anything else is no receipt, and nothing is recorded as sent
  dr_shape "$DR/receipt.json" receipt && jq -e --arg h "$(sha256sum < "$DR/seal.age" | cut -c1-64)" '.id == $h and all(.received_at, .expires_at; test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"))' "$DR/receipt.json" > /dev/null 2>&1 &&      # compared in jq: $(…) drops trailing LFs and every NUL, so a time is held to its form there before dr_time reads it
    dr_time "$(jq -r '.received_at | strings' "$DR/receipt.json")" > /dev/null && dr_time "$(jq -r '.expires_at | strings' "$DR/receipt.json")" > /dev/null && return 0
  dr_refuse "the server's receipt does not name the ciphertext this box posted, or its times are not times: it is not recorded as sent"
}
dr_sent(){ # <address> → sent/<address>.<msg_id>.json, one line, {"envelope":…,"receipt":…}: the envelope as the post that was taken dated and signed it ($DR/seal.P), as the recipient's inbox/ keeps it, and the server's receipt; and a sent line: the server's id, the msg_id and the address, both from the envelope posted. sent/ is yours to prune
  local m t; m=$(jq -r .msg_id "$DR/seal.P") && t="$DR/sent/$1.$m.json" || return 1
  mkdir -p "$DR/sent" && dr_putout "$t" dr_line "$DR/seal.P" "$DR/receipt.json" || { dr_err "sent, but not recorded in sent/"; return 1; }
  dr_out sent --arg id "$(jq -r .receipt.id "$t")" --arg msg_id "$m" --arg to "$1"
}

# recipe: receive
dr_recv(){ # drains the box, every page up to a drain's limits. ACCEPT → inbox/ and a mail line on stdout. REFUSED → quarantine/, never delivered, and a refused line on stdout. Both are acked
  dr_held || { dr_lock dr_recv "$@"; return; }
  DR_LISTED=; dr_drain; local rc=$?; [ -z "$DR_LISTED" ] || dr_prune "$DR_LISTED"; return $rc      # keys deleted by this clock only once the server has answered the list, so has taken a pass dated by it, and by that pass's date: a clock far ahead is stopped at its pass, one that moves while the list is in flight deletes nothing by where it went, and the keys that mail waits for stay (PROTOCOL.md §12.4)
}
dr_drain(){ # stops at a transient error or a fault of this box, leaving the rest on the server for the next drain. And at a number of messages and of pages (below): a server that lists mail without end costs one run that much
  local B c="" n i id k=0 pages=0; B=$(cat "$DR/address") || return 1
  dr_finished || { dr_done $?; return 1; }
  rm -f "$DR/asked"      # the senders this drain has asked the server about: one lookup each
  while :; do
    [ $((pages += 1)) -le 100 ] || { dr_out more --arg message "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
    dr_owner GET "/v1/$B/messages${c:+?cursor=$c}" > "$DR/list.json" || { dr_own; return 1; }
    [ "$pages" -gt 1 ] || { DR_LISTED=$(dr_taken) && dr_forget "$DR_LISTED"; } || return 1      # the replay set pruned by this clock only once the server has taken a pass dated by it, and by that pass's date (dr_taken): a drain that a clock far off would prune is stopped at its pass first. DR_LISTED tells dr_recv the same reading for the keys
    dr_shape "$DR/list.json" list && n=$(jq -r '.messages | length' "$DR/list.json") || { dr_err "the server's list of messages is not one this client reads: the mail stays on the server"; return 1; }
    for ((i = 0; i < n; i++)); do
      id=$(jq -r --argjson i "$i" '.messages[$i].id | strings | select(test("\\A[0-9a-f]{64}\\z"))' "$DR/list.json") && dr_hex "$id" || continue      # tested in jq: $(…) drops trailing LFs and every NUL
      [ $((k += 1)) -le 1000 ] || { dr_out more --arg message "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"; return 0; }
      if ! grep -q "^$id " "$DR/seen" 2> /dev/null; then jq -c --argjson i "$i" '.messages[$i]' "$DR/list.json" > "$DR/entry.json" && dr_one "$B" "$id" "$DR/entry.json" || return 1; fi   # an id already handled is only acked again
      dr_owner DELETE "/v1/$B/messages/$id" > /dev/null || [ "$(dr_code)" = no_such_message ] || return 1
    done
    c=$(jq -r '.next_cursor // empty' "$DR/list.json"); [ -n "$c" ] || return 0      # one or more of A-Z, a-z, 0-9, - and _ (dr_shape), so it goes into the next query as it is
  done
}
dr_one(){ # <me> <id> <its list entry> → 0 once the message is judged and its verdict is on disk; 1 on a transient error or a fault of this box, so it is not acked. The fetch answers the ciphertext alone, of the size the list gives; who sent it, on the server's word, and when, are the list entry's
  local B=$1 id=$2 m="$DR/msg" A why rc h z
  rm -f "$m.json" "$m.age" "$m.sig" "$m.P" "$m.T" "$m.doc"
  cp "$3" "$m.json" && z=$(jq -r '.size // 0' "$m.json") || return 1      # an integer from 0 to 16 MiB, the protocol's largest ciphertext, or null, which is 0 (dr_shape's list; PROTOCOL.md §11.10)
  if dr_owner GET "/v1/$B/messages/$id" "" --max-filesize $((z > 0 ? z : 1)) > "$m.age"; then :      # no more than the list says it holds, and every size up to 16 MiB, the protocol's largest ciphertext, which every reader takes; the list's form holds the size to it (dr_shape; PROTOCOL.md §11.10, §12.3)
  elif [ "$(dr_code)" = no_such_message ]; then return 0      # already gone
  elif [[ $(dr_status) != 2?? ]]; then return 1; fi      # a 2xx that curl cut short is a body past its size
  [ "$(wc -c < "$m.age" 2> /dev/null)" = "$z" ] || { dr_err "the server's answer for message $id is not the $z bytes of ciphertext its list gives: it stays on the server"; return 1; }      # an answer that breaks its form, the server's fault and not the sender's: no verdict, and no ack
  h=$(sha256sum < "$m.age" | cut -c1-64)      # files are named by the hash computed here, never the server's id
  rm -f "$DR/said"; why=$(dr_judge "$B" "$m"); rc=$?; cat "$DR/said" 2> /dev/null; rm -f "$DR/said"      # what the judge met on the way is printed here: its stdout is its verdict
  if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then [ "$h" = "$id" ] || { why="bad_id: the server's id for it is not the SHA-256 of its ciphertext"; rc=1; }; fi
  case $rc in
    0) A=$(jq -r .from "$m.P") && dr_putout "$DR/inbox/$h.json" dr_line "$m.P" && dr_seen "$A" "$m" "$h" || return 1      # stored, then seen, both on disk before the ack: a crash delivers again, never loses
       printf '{"type":"mail","id":"%s","envelope":' "$h" && cat "$DR/inbox/$h.json" && echo '}' ;;      # the envelope the line inbox/ keeps, as its bytes are (jq would write the line breaks dr_line escaped), and only inside "envelope", so a member it gains later never meets the line's own (#356)
    2) dr_out duplicate --arg id "$h" --arg message "a retry of a message already delivered: not delivered again" ;;
    3) dr_err "$why: nothing is judged or acked until this box is fixed"; return 1 ;;
    4) dr_err "$why: the message stays on the server, and the next recv asks again"; return 1 ;;
    *) dr_putout "$DR/quarantine/$h.json" dr_kept "$m" "$h" && dr_putline "$DR/quarantine/$h.reason" "$why" || return 1      # the message as served, its strings in base64 but those of their form, and beside it why: "<code>: <words>", this script's own words, never the message's
       dr_out refused --arg id "$h" --arg code "${why%%: *}" --arg message "${why#*: }" ;;
  esac
}
dr_kept(){ # <message stem> <id> → the message as quarantine/ keeps it: the id this script hashed, and the ciphertext its fetch answered, <stem>.age, in base64; none of the server's strings, so nothing the server chose is there to be read
  local rc; dr_b64 "$1.age" > "$1.b64" && jq -cj -n --rawfile c "$1.b64" --arg id "$2" '{id: $id, ciphertext: $c}'; rc=$?; rm -f "$1.b64"; return $rc      # base64 of the bytes, a file of ASCII, which jq carries as it is
}
dr_judge(){ # <me> <message stem> → 0 only if EVERY check passes, in this order; 2 for a resend of an accepted msg_id; 1 refused, with "<code>: <words>" on stdout, the words this script's own and never the message's; 3 a fault of this box, no verdict; 4 no answer from the server on whether the sender is revoked, no verdict. Who the sender is, is never asked of the server: the message carries what proves it. The one thing asked is whether a revocation of that sender exists, and the answer proves itself
  local B=$1 m=$2 ids=() k h A c f
  for k in "$DR"/prekeys/*.agekey; do [ -e "$k" ] || continue; age-keygen -y "$k" > /dev/null 2>&1 || { echo "cannot read the prekey key $k"; return 3; }; ids+=(-i "$k"); done      # a key file age cannot read is a fault of this box, which stops the drain: never a message refused for it
  [ ${#ids[@]} -gt 0 ] || { echo "this box has no prekeys"; return 3; }
  age -d "${ids[@]}" < "$m.age" > "$m.T" 2> /dev/null || { echo "undecryptable: it does not decrypt with this box's prekeys"; return 1; }
  A=$(dr_open "$B" "$m") || { echo "$A"; return 1; }      # the sender, proved by what was decrypted
  f=$(dr_floor 2> /dev/null) || { echo "$DR/seen-floor names no time"; return 3; }
  [ "$f" -eq 0 ] || [ "$(dr_time "$(jq -r .sent_at "$m.P")")" -ge $((f + 33*86400)) ] || { echo "stale: sent_at is before this box's replay set reaches back to, since its clock once read later than it does now"; return 1; }      # freshness has a floor too: a sent_at before the highest cutoff the replay set was pruned at may be a message whose line went, and so may one up to 33 days above it, a retry of such a message, dated afresh up to 33 days after its first copy (check 10 knows a retry by that copy's line). dr_open checked sent_at's grammar
  jq -e --arg a "$A" '.from == $a' "$m.json" > /dev/null 2>&1 || { echo "reattributed: the server lists it as from another box than the one that signed it"; return 1; }      # the server's from, compared in jq: $(…) drops trailing LFs and every NUL
  if ! grep -qx "$A" "$DR/asked" 2> /dev/null; then      # the server is asked once for each sender in a drain. That it holds none is an answer; no answer is not, and the message then stays where it is
    dr_lookup "$A" >> "$DR/said"; case $? in 0) ;; 1) echo "$A" >> "$DR/asked" ;; 3) echo "what this box keeps of its sender's revocations does not verify, or cannot be written"; return 3 ;; *) echo "whether its sender is revoked could not be asked"; return 4 ;; esac
  fi
  dr_gone "$A"; case $? in      # nobody can vouch for when a signature was made, so a revocation reaches back over everything that address signed
    0) echo "revoked: its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed"; return 1 ;;
    3) echo "the revocation kept for $A does not verify"; return 3 ;;
  esac
  c=$(dr_cert "$m.sig" "$m.doc" "$A") || { echo "cannot read the certificate of a signature that verified"; return 3; }
  dr_certrevoked "$A" "${c%% *}"; case $? in      # the same answer carried the sender's revocation of its certificates, if it has one: the address goes on, and what a revoked certificate signed is refused the same way
    0) echo "certificate_revoked: it is signed under a certificate its sender's identity has revoked: nothing signed under it is taken, whenever it was signed"; return 1 ;;
    3) echo "the revocation of certificates kept for $A does not verify"; return 3 ;;
  esac
  [ ! -e "$DR/seen" ] || [ -r "$DR/seen" ] || { echo "cannot read $DR/seen"; return 3; }
  h=$(sha256sum < "$m.age" | cut -c1-64)
  ! grep -q "^$h " "$DR/seen" 2> /dev/null || { echo "replay: this ciphertext was already received"; return 1; }
  dr_meet "$A" "$m.doc" || { echo "cannot write under $DR/peers"; return 3; }
  ! grep -q " $A $(jq -r .msg_id "$m.P")\$" "$DR/seen" 2> /dev/null || return 2
}
dr_open(){ # <me> <message stem> → the sender's address, only if what was decrypted, <stem>.T, is a message for this box that its sender signed; otherwise "<code>: <words>", and 1. It leaves the envelope in <stem>.P, its signature in <stem>.sig and the sender's identity document in <stem>.doc
  local B=$1 m=$2 A
  # Line 1 is the envelope, line 2 begins the signature, the first END line ends it, and nothing after that is read. Each part has one place; nothing is searched for. The END line is the first line that begins so, and it must end there, in a line feed
  head -n 1 "$m.T" > "$m.P"; sed -n '2,/^-----END SSH SIGNATURE-----/p' "$m.T" > "$m.sig"
  [ "$(tail -c 1 "$m.P" | od -An -tx1 | tr -d ' \n')" = 0a ] && head -n 1 "$m.sig" | cmp -s - <(printf -- '-----BEGIN SSH SIGNATURE-----\n') && tail -n 1 "$m.sig" | cmp -s - <(printf -- '-----END SSH SIGNATURE-----\n') ||      # each compared as bytes: $(…) drops a NUL
    { echo "bad_message: what was decrypted is not an envelope line and then a signature block"; return 1; }
  dr_envform "$m.P" || return 1
  jq -e '.from | . == null or type == "string"' "$m.P" > /dev/null 2>&1 || { echo "bad_envelope: the envelope is malformed: its from is not what that field holds"; return 1; }
  jq -e 'has("identity")' "$m.P" > /dev/null 2>&1 || { echo "bad_identity: the envelope carries no identity document"; return 1; }
  dr_bytes "$m.P" identity "$m.doc" && [ -s "$m.doc" ] || { echo "bad_identity: the envelope's identity is not base64 of an identity document"; return 1; }      # its bytes, compared as bytes
  dr_idcheck "$m.doc"; case $? in 0) ;;      # a well-formed document of a key type this script does not verify has its own code, once it is known to be the sender's
    2) jq -e --arg a "$(sha256sum < "$m.doc" | cut -c1-64)" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
       echo "unsupported_key_type: the sender's identity is of a key type this client does not verify"; return 1 ;;
    *) echo "bad_identity: the envelope's identity document breaks its format or its key checks"; return 1 ;;
  esac
  A=$(sha256sum < "$m.doc" | cut -c1-64)      # the sender: the hash of the identity document the envelope carries. The document proves itself, and the signature must now verify under it
  jq -e --arg a "$A" '.from == $a' "$m.P" > /dev/null 2>&1 || { echo "reattributed: the envelope's from is not the address of the identity it carries"; return 1; }
  dr_certified "$A" "$m.doc" "dromas-msg-v1:$B" "$m.sig" "$m.P" > /dev/null; case $? in      # over line 1 exactly as decrypted, never over anything rebuilt
    0) ;; 2) echo "bad_signature: the certificate of the key that signed it has ended"; return 1 ;;
    3) echo "bad_signature: the certificate of the key that signed it has not begun, by this machine's clock"; return 1 ;;
    *) echo "bad_signature: it is not signed for this box by a working key the sender's identity certified"; return 1 ;;
  esac
  dr_envcheck "$m.P" "$A" "$B" || return 1
  echo "$A"
}
dr_envform(){ # <envelope> → 0 only for one JSON object with no member named twice in any object in it: a name given twice could be read as two values of one signed text. Otherwise the reason, and 1
  local n; n=$(jq -n --stream '[inputs | if length == 2 then .[0] else .[0][:-1] end | select(length > 0 and (.[-1] | type) == "string")] | length' "$1" 2> /dev/null) &&      # every member of every object, as written: one named twice is counted twice here, and once below
    jq -en --argjson n "$n" '[inputs] | length == 1 and (.[0] | type == "object" and ([.. | objects | length] | add) == $n)' "$1" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is not one JSON object with no member named twice"; return 1; }
}
dr_envcheck(){ # <envelope> <signer> <this box> → 0 only for one JSON object, keys exact and none twice, checked in PROTOCOL.md §12.3 check 6's order: a body and fields that are strings, v the number 1, from the signer and to this box, a msg_id, and sent_at no older than 33 days and no more than an hour ahead; otherwise the reason, and 1
  local e=$1 sa
  dr_envform "$e" || return 1
  jq -e 'has("body") and all(.from, .to, .msg_id, .sent_at, .subject, .in_reply_to, .supersedes, .identity; . == null or type == "string") and .v == 1' "$e" > /dev/null 2>&1 ||
    { echo "bad_envelope: the envelope is malformed: a body, fields that are strings, and v the number 1"; return 1; }      # in PROTOCOL.md §12.3 check 6's order: a body and every member of its type, v, to, msg_id, then the time
  jq -e --arg a "$2" --arg b "$3" '.from == $a and .to == $b' "$e" > /dev/null 2>&1 || { echo "reattributed: the inner from/to do not match the signer and this box (re-attribution)"; return 1; }
  jq -e '.msg_id | type == "string" and test("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z")' "$e" > /dev/null 2>&1 || { echo "bad_envelope: the envelope has no valid msg_id"; return 1; }
  jq -e '.sent_at | strings | test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z")' "$e" > /dev/null 2>&1 && sa=$(dr_time "$(jq -r .sent_at "$e")") || { echo "bad_envelope: the envelope's sent_at is not a UTC timestamp to the second"; return 1; }      # its grammar tested in jq first: $(…) drops trailing LFs and every NUL
  [ "$sa" -ge $(($(dr_now) - 33*86400)) ] || { echo "stale: sent_at is older than 33 days"; return 1; }
  [ "$sa" -le $(($(dr_now) + 3600)) ] || { echo "future: sent_at is more than 60 minutes ahead of this machine's clock"; return 1; }
}
dr_line(){ # <checked envelope> [receipt] → the one line delivered: built from the checked fields, never the sender's bytes, with U+0085, U+2028 and U+2029 escaped (Python's splitlines and Node's readline end lines there), and every character of Unicode 18.0's Default_Ignorable_Code_Point, which nobody sees and a model reads (tag characters, BiDi controls, zero-width characters, variation selectors): the Go client's escapeUnseen, in its list and its form. With a receipt it is dr_sent's record, the envelope inside "envelope" and the receipt beside it
  jq -j --slurpfile r "${2:-/dev/null}" 'def h4: . as $n | [range(3; -1; -1) | ($n / pow(16; .) | floor) % 16] | map("0123456789abcdef"[.:. + 1]) | add;
    def dr_esc: if . > 65535 then (. - 65536) as $v | "\\u" + ((55296 + ($v / 1024 | floor)) | h4) + "\\u" + ((56320 + $v % 1024) | h4) else "\\u" + h4 end;      # a code point as JSON escapes it, lowercase, as Go writes it: a surrogate pair above U+FFFF
    ({v: 1, from, to, sent_at, msg_id, body} + ([{subject}, {in_reply_to}, {supersedes}] | map(select(.[] | . != null and . != "")) | add // {})) as $e | ($r[0] | if . then {envelope: $e, receipt: {id, received_at, expires_at}} else $e end) | tojson | gsub("(?<c>[\\x{85}\\x{2028}\\x{2029}\\x{AD}\\x{34F}\\x{61C}\\x{115F}-\\x{1160}\\x{17B4}-\\x{17B5}\\x{180B}-\\x{180F}\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2060}-\\x{206F}\\x{3164}\\x{FE00}-\\x{FE0F}\\x{FEFF}\\x{FFA0}\\x{FFF0}-\\x{FFF8}\\x{1BCA0}-\\x{1BCA3}\\x{1D173}-\\x{1D17A}\\x{E0000}-\\x{E0FFF}])"; .c | explode[0] | dr_esc)' "$1"
}
dr_forget(){ # <Unix time, one a server took (dr_taken)> → the replay set without the lines past 66 days and an hour from their sent_at by that reading: a retry, dated afresh, may be posted up to 33 days after a first copy that was delivered, and read up to 33 days after that, and an hour covers a clock that steps back as far as two clocks a server takes are apart. When it drops one, the floor rises to the cutoff first, so a clock that later reads further back still takes no message whose line went (dr_floor)
  local c=$(($1 - 66*86400 - 3600)) f; [ -e "$DR/seen" ] || return 0
  awk -v c="$c" '$2 >= c' "$DR/seen" > "$DR/seen.new" || return 1
  cmp -s "$DR/seen" "$DR/seen.new" && { rm -f "$DR/seen.new"; return 0; }      # nothing dropped: nothing written
  f=$(dr_floor) || return 1
  if [ "$f" -lt "$c" ]; then printf '%s\n' "$c" > "$DR/seen-floor.new" && sync "$DR/seen-floor.new" && mv "$DR/seen-floor.new" "$DR/seen-floor" && sync "$DR" || return 1; fi      # on disk before any line goes
  sync "$DR/seen.new" && mv "$DR/seen.new" "$DR/seen" && sync "$DR"      # on disk before it replaces the old one: a crash leaves the old set or the new, never an empty one
}
dr_floor(){ # → the highest cutoff a prune of the replay set has dropped a line at, from seen-floor, or 0 when it has none: a message sent before it, or less than 33 days after it, is stale whatever the clock now reads, since its line, or its first copy's, may be gone, as a Kerberos server that has lost its replay cache refuses until the window has passed (RFC 4120 §3.2.3). A file that names anything else is an error, never the default
  local f; [ -e "$DR/seen-floor" ] || { echo 0; return 0; }
  f=$(cat "$DR/seen-floor" 2> /dev/null) && [[ $f =~ ^(0|[1-9][0-9]{0,17})$ ]] && printf '%s\n' "$f" | cmp -s - "$DR/seen-floor" && echo "$f" ||      # compared with itself rebuilt: $(…) drops line feeds and NULs
    { dr_err "$DR/seen-floor names no time: it is a number of seconds and a line feed, written by recv"; return 1; }
}
dr_seen(){ # <sender> <message stem> <hash> → the message, in the replay set and on disk
  local new=; [ -e "$DR/seen" ] || new=$DR
  printf '%s %s %s %s\n' "$3" "$(dr_time "$(jq -r .sent_at "$2.P")")" "$1" "$(jq -r .msg_id "$2.P")" >> "$DR/seen" && sync "$DR/seen" ${new:+"$new"}
}

# recipe: new prekey (monthly)
dr_rekey(){ # [--no-pq] → publishes a new prekey, signed by a new working key under a new certificate, under the lock: a NEW key at a new number, which this machine's clock gives, or the statement an earlier run signed and the server did not take, sent again as it is. Needs only the identity (dr_lock makes the box's other files from it), so it also recovers a box that lost its prekeys or its working key
  dr_opt "${1-}" || return 1
  dr_held || { dr_lock dr_rekey "$@"; return; }
  dr_renew "${1-}"
}
dr_renew(){ # [--no-pq] → what dr_rekey does, the lock held. A serial is signed ONCE
  local A r s t na h c f cs p new x gone u w at; A=$(cat "$DR/address") || return 1; mkdir -p "$DR/prekeys"
  dr_finished || { dr_done $?; return 1; }
  dr_api GET "/v1/$A" > "$DR/self.json" 2> "$DR/self.err" || case $(dr_code) in
    no_such_mailbox) gone=1 ;;      # 404: the server holds no box here any more, past its record's expiry (PROTOCOL.md §13), so nothing is served to number above or to hold to its order, and the renewal goes as a registration
    revoked) dr_takerecord "$A"; [ $? != 3 ] || return 1; dr_finished || { dr_done $?; return 1; }; cat "$DR/self.err" >&2; return 1 ;;      # 410: the address's record, kept once it verifies, so the box signs nothing more here or at any server it is pointed at (PROTOCOL.md §12.5; #343)
    *) cat "$DR/self.err" >&2; return 1 ;;
  esac
  p=$(cat "$DR/serial" 2> /dev/null || echo 0)
  if [ -n "$gone" ]; then s=$p; else
    dr_shape "$DR/self.json" box && dr_bytes "$DR/self.json" identity "$DR/self.doc" && dr_bytes "$DR/self.json" prekey "$DR/self.txt" && dr_bytes "$DR/self.json" prekey_signature "$DR/self.sig" ||
      dr_refuse "the server's answer for this box is not one this client reads: one JSON object, each byte field base64" || return 1
    [ -s "$DR/self.txt" ] && [ -s "$DR/self.sig" ] || dr_refuse "the server sent no prekey for this box" || return 1
    c=$(dr_cert "$DR/self.sig" "$DR/identity.doc" "$A") && c=${c#* } && r=$(dr_prekeycheck "$DR/self.txt" "$DR/self.sig" "$A" "$DR/identity.doc" "${c% *}") || dr_refuse "this box's current prekey, as served: ${r:-it is not signed under a certificate of this identity}" || return 1      # its own record, judged where its certificate begins: whether this identity ever certified the key that signed it, even if that certificate has since ended
    s=${r%% *}; cs=${r##* }      # a box's statements are ordered by certificate first, then by serial, and this box gives a renewal's certificate and prekey one number: what it published is (p, p), and the server may serve nothing ordered before it
    [ "$cs" -gt "$p" ] || { [ "$cs" -eq "$p" ] && [ "$s" -ge "$p" ]; } || dr_refuse "rollback: the server serves this box's prekey serial $s under certificate $cs, before serial $p, which this box published" || return 1
    s=$((cs > p ? cs : p))
  fi
  if [ -n "$gone" ]; then      # what is held of this box's own revocations, at every renewal, so the certificate is numbered above them: from its server's answer, or for a box it holds no more, which carries none, from its revocations alone
    if dr_api GET "/v1/$A/revocations" > "$DR/rev.json" 2> "$DR/self.err"; then dr_isrecord "$DR/rev.json" || dr_refuse "the server's answer for this box's revocations is not one this client reads: a record, each byte field base64" || return 1; dr_take "$A"; [ $? != 3 ] || return 1      # a 2xx that is no record stops the renewal with a refusal, as one for the box's own read does
    else case $(dr_code) in not_revoked | no_such_mailbox) ;; *) cat "$DR/self.err" >&2; return 1 ;; esac; fi
  else jq -c '{identity, revoked_certificates, revoked_certificates_signature}' "$DR/self.json" > "$DR/rev.json" && dr_take "$A"; [ $? != 3 ] || return 1; fi
  dr_finished || { dr_done $?; return 1; }
  x=$(dr_certskept "$A"); case $? in      # above every serial this box's identity has revoked too: a certificate numbered there would be revoked as it was made
    0) [ "$x" -lt 9007199254740991 ] || dr_refuse "this box's identity has revoked its certificates through the highest serial there is, so no later certificate can be made: the address cannot renew" || return 1; [ "$x" -le "$s" ] || s=$x ;;
    1) ;;
    *) dr_refuse "the revocation of certificates kept for this box does not verify"; return 1 ;;
  esac
  t=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p; s/\.txt\.sig$//p' | sort -n | tail -n 1); new=1      # s is the highest number this box knows of, and the new statement goes above it: above the served CERTIFICATE's serial, never the served prekey's, since it is under a new certificate, which outranks any prekey serial under the one before. So a prekey published in this box's name at the highest serial there is holds nothing. t is the highest number this box began a prekey at
  if [ "${t:-0}" -gt "$s" ]; then s=$t; new=; [ ! -s "$DR/prekeys/$s.txt.sig" ] || { na=$(dr_time "$(sed -n 5p "$DR/prekeys/$s.txt")") && [ "$na" -gt "$(dr_now)" ] && [ -s "$DR/work/$s-cert.pub" ] && c=$(dr_cert "$DR/prekeys/$s.txt.sig" "$DR/identity.doc" "$A") && c=${c#* } && [ "${c% *}" -le $(($(dr_now) - 3600)) ] && u=$(dr_time "$(cat "$DR/prekeys/$s.made" 2> /dev/null)") && w=$(dr_lifetime 2> /dev/null) && [ $((na - u)) -le "$w" ]; } || new=1; fi      # a number an earlier run took, and that nothing has passed since, is kept. Signed and never seen published: sent again AS IT IS until it expires, then a new number. Signed again, the same key would get 33 more days from a server that keeps what it refuses. One under a certificate that began less than an hour before this clock was signed while the clock read ahead of where it reads now: a reader a server takes may not have reached its start, so it is spent too. Never signed: its key is used
  if [ -n "$new" ]; then [ "$s" -lt 9007199254740991 ] || dr_refuse "this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew" || return 1; t=$(dr_now); s=$((t > s ? t : s + 1)); fi      # a new number: this machine's clock, in seconds, or one above the highest this box knows of when the clock gives nothing higher. An identity is a key and keeps no record of what it signed, and a box restored from it knows only what the server shows: by the clock, its certificate is above every one made before, on whatever machine. A verifier never reads a serial as a time, it only compares two
  [ -s "$DR/prekeys/$s.txt.sig" ] || rm -f "$DR/prekeys/$s.txt" "$DR/prekeys/$s.made"; dr_prekey "$s" "${1-}" || return 1
  if [ -n "$gone" ]; then u="/v1/$A"; w='{identity:$i}'; else u="/v1/$A/prekey"; w='{}'; fi      # a registration is the identity document, then what a new prekey carries
  jq -n --arg i "$(dr_b64 "$DR/identity.doc")" --arg p "$(dr_b64 "$DR/prekeys/$s.txt")" --arg g "$(dr_b64 "$DR/prekeys/$s.txt.sig")" --argjson k "$(dr_senders)" "$w"' + {prekey:$p, prekey_signature:$g, sender_key_types:$k}' > "$DR/rekey.json"
  h=$(dr_pass "$s") && dr_api PUT "$u" "$DR/rekey.json" -H "Authorization: $h" > /dev/null || { dr_clock; dr_own; return 1; }      # a pass under the NEW certificate: that is how a box moves to one, and the server then takes no pass under an older
  [ "$s" -le "$(cat "$DR/serial" 2> /dev/null || echo 0)" ] || dr_putline "$DR/serial" "$s" || return 1
  mv "$DR/pass.new" "$DR/pass" || return 1
  for f in "$DR"/work/*-cert.pub; do t=$(basename "$f" -cert.pub); [[ $t =~ ^[0-9]+$ ]] && [ "$t" -lt "$s" ] && rm -f "$DR/work/$t" "$DR/work/$t.pub" "$f"; done      # older working keys: what they signed is signed, and the server takes no pass under them
  at=$(dr_taken) && dr_prune "$at" && dr_out prekey --argjson serial "$s" --arg not_after "$(sed -n 5p "$DR/prekeys/$s.txt")"      # by the reading the server took the renewal at: the date of its pass, now $DR/pass
}
dr_prune(){ # <Unix time, one a server took (dr_taken)> → deletes every retired prekey past its deletion time by that reading of this machine's clock: its not_after + the 33 days mail is kept. dr_recv gives the date of the pass its list carried, dr_renew that of the renewal's: a clock a server took, never a later reading. After that, mail encrypted to it is unrecoverable. (The Go client also deletes them sooner.)
  local f n top na; top=$(ls "$DR/prekeys" | sed -n 's/\.agekey$//p' | sort -n | tail -n 1); [ -n "$top" ] || return 0
  for f in "$DR"/prekeys/*.txt; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .txt); [ "$n" -lt "$top" ] || continue      # never the newest
    na=$(dr_time "$(sed -n 5p "$f")") || continue
    [ "$1" -lt $((na + 33*86400)) ] || rm -f "$DR/prekeys/$n.agekey" "$DR/work/$n" "$DR/work/$n.pub" "$DR/work/$n-cert.pub"      # and the working key made with it, if a renewal the server never took left one
  done
}

# Run as a command, not sourced: the Go client's command line, for the commands this script has.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  dr_usage(){ sed -n '/^#   bash dromas\.sh /,/^#   The README/p' "$0" | sed 's/^#   //'; }      # the usage at the top
  dr_lines(){ dr_usage | awk -v w="bash dromas.sh $* " '/^bash dromas\.sh /{ on = index($0 " ", w) == 1 } /^The README/{ on = 0 } on'; }      # <words> → the usage lines of the commands they start
  dr_wrong(){ jq -cn --arg m "$1" --arg u "${2-}" --arg h "${3:-bash dromas.sh help}" '{type:"usage_error"} + (if $u != "" then {usage:$u} else {} end) + {help:$h, message:$m}' >&2; exit 2; }      # <words> [usage] [help] → the usage_error line on stderr, as the Go client prints one: what was wrong, the command's usage, and the help to read. Nothing ran
  dr_cmd= dr_n=0 dr_min=0 dr_max=0      # the function the command line runs, how many words name it, and how many arguments it takes, at least and at most
  case ${1-} in init) dr_cmd=dr_init dr_n=1 dr_max=1 ;; addr | recv) dr_cmd=dr_$1 dr_n=1 ;; send) dr_cmd=dr_send dr_n=1 dr_min=1 dr_max=2 ;; esac
  case "${1-} ${2-}" in 'prekey renew') dr_cmd=dr_rekey dr_n=2 dr_max=1 ;; esac
  dr_help=0
  for a; do case $a in --help) dr_help=1 ;; -h) dr_help=1; echo "Flag shorthand -h has been deprecated, use --help" >&2 ;; esac; done      # anywhere after a command: its help, and nothing runs. -h works too, as in the Go client, and means nothing else
  if [ "${1-}" = help ] || { [ -z "$dr_cmd" ] && [ "${2-}" = help ]; }; then
    dr_help=1; [ "$1" = help ] && shift || set -- "$1"
    [ $# -eq 0 ] || case "${1-} ${2-}" in 'prekey '?*) dr_n=2 ;; ?*) dr_n=1 ;; esac
  fi
  if [ $dr_help = 1 ]; then      # help: the usage, or the lines of the command or group it names
    [ "$dr_n" -gt 0 ] || [ $# -eq 0 ] || [[ $1 = -* ]] || dr_n=1
    [ "$dr_n" -gt 0 ] || { dr_usage; exit 0; }
    out=$(dr_lines "${@:1:dr_n}"); [ -n "$out" ] && { echo "$out"; exit 0; }
    dr_wrong "dromas.sh has no command ${*:1:dr_n}"
  fi
  if [ -z "$dr_cmd" ]; then      # bare, a group alone, or a command it does not have
    if [ $# -eq 0 ]; then dr_wrong "dromas.sh takes a command: bash dromas.sh help lists them"
    elif [ -z "$(dr_lines "$1")" ]; then dr_wrong "dromas.sh has no command $1"
    elif [ -n "${2-}" ]; then dr_wrong "dromas.sh $1 has no command $2" "" "bash dromas.sh help $1"
    else dr_wrong "dromas.sh $1 takes a command: bash dromas.sh help $1 lists them" "" "bash dromas.sh help $1"; fi
  fi
  words=${*:1:dr_n}; shift $dr_n
  dr_use=$(dr_lines "$words" | head -n 1 | sed 's/   .*//')
  if [ $# -lt $dr_min ] || [ $# -gt $dr_max ]; then dr_wrong "dromas.sh $words takes $([ $dr_min = $dr_max ] && echo $dr_min || echo "$dr_min to $dr_max") arguments, and was given $#" "$dr_use" "bash dromas.sh help $words"; fi
  case $dr_cmd in      # every word a command takes, and no other: a word it does not take is a wrong command line, never dropped
    dr_init | dr_rekey) [ $# -eq 0 ] || [ "$1" = --no-pq ] || dr_wrong "dromas.sh $words takes no option but --no-pq: $1" "$dr_use" "bash dromas.sh help $words" ;;
    dr_send) for a; do [[ $a != -* ]] || dr_wrong "dromas.sh send takes no option: $a" "$dr_use" "bash dromas.sh help send"; done ;;
  esac
  dr_tls "$DR_BASE" || exit 1      # refused before anything, as the Go client refuses to open a box whose server it would not call
  "$dr_cmd" "$@"; exit
fi
