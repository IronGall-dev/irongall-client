#!/usr/bin/env bash
# scripts/check.sh: the checks a change must pass, one definition for a laptop
# and for CI (.github/workflows/ci.yml runs `full` and `vuln`).
#
#   scripts/check.sh         quick: gofmt, vet and the tests -short keeps, while working
#   scripts/check.sh full    CI's test job: gofmt, vet, every test, the skip check, the race test
#   scripts/check.sh push    full, then golangci-lint and govulncheck: before a push
#   scripts/check.sh vuln    govulncheck alone, at the version pinned here
#
# The tests build with -tags dromas_nofsync, so no write is flushed to the
# disk (client/fsync.go): a test kills a process, never the machine. -short
# skips the long tests, each of which says so; CI never passes it. On macOS
# ./sh is left to CI: the script is held to GNU's and uutils' tools (README §
# The shell client), and on macOS its tests, a few thousand short processes,
# took from 3 to more than 20 minutes on one machine in one day (go test ./sh
# still runs them, with bash 4 or later and GNU coreutils first in PATH).
set -euo pipefail
cd "$(dirname "$0")/.."

govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0
tags=dromas_nofsync
darwin=
[ "$(uname -s)" = Darwin ] && darwin=1
if [ -n "$darwin" ] && command -v brew > /dev/null; then
  for d in "$(brew --prefix)/opt/coreutils/libexec/gnubin" "$(brew --prefix)/opt/bash/bin"; do
    if [ -d "$d" ]; then PATH="$d:$PATH"; fi
  done
fi
unset DROMAS_HOME DROMAS_BOX DR_HOME DR_BOX # no test may meet a real box

# A test skips when a tool it runs is missing. A runner with every tool skips
# nothing, so a skip fails `full`, but for these.
allowed=(-e 'run by the crash tests, in a process of its own')

pkgs=$(go list ./...)
if [ -n "$darwin" ]; then
  pkgs=$(grep -v '/sh$' <<< "$pkgs")
  echo "macOS: ./sh is left to CI (scripts/check.sh, top)" >&2
fi

fail() { # an annotation on GitHub's page, a line on a terminal
  if [ -n "${GITHUB_ACTIONS-}" ]; then echo "::error::$*"; else echo "$*" >&2; fi
}

fmt() {
  local out
  out=$(gofmt -l .)
  if [ -n "$out" ]; then fail "not gofmt'd: $out"; return 1; fi
}

alltests() {
  local dir status
  dir=$(mktemp -d)
  set +e
  # shellcheck disable=SC2086 # one package a word
  go test -tags "$tags" -count=1 -timeout 20m -json $pkgs | tee "$dir/test.json" | jq -rj --unbuffered 'select(.Action == "output") | .Output'
  status=${PIPESTATUS[0]}
  set -e
  jq -rs '[.[] | select(.Test != null)] | group_by([.Package, .Test])[] | select(any(.Action == "skip"))
    | "\(.[0].Package) \(.[0].Test): " + ([.[] | select(.Action == "output") | .Output
      | select(test("^ +[^ ]+\\.go:[0-9]+: ")) | sub("^ +"; "") | rtrimstr("\n")] | join(" "))' \
    "$dir/test.json" > "$dir/skips"
  echo "Skipped:"; cat "$dir/skips"
  if grep -v -F "${allowed[@]}" "$dir/skips"; then
    fail "the tests above skipped, and this machine has every tool they need"
    rm -rf "$dir"
    return 1
  fi
  rm -rf "$dir"
  return "$status"
}

full() {
  fmt
  go vet ./...
  alltests
  go test -tags "$tags" -race -count=1 -run 'SharedByGoroutines' ./client # a Box shared by goroutines
}

case ${1:-quick} in
  quick)
    fmt
    go vet ./...
    # shellcheck disable=SC2086 # one package a word
    go test -tags "$tags" -short $pkgs
    ;;
  full) full ;;
  push)
    full
    golangci-lint run ./...
    go run "$govulncheck" ./...
    ;;
  vuln) go run "$govulncheck" ./... ;;
  *) sed -n '5,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
