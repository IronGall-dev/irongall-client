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
# skips the long tests, each of which says so; CI never passes it. On macOS,
# Windows and the BSDs ./sh is left to the Linux runs: the script is held to
# GNU's and uutils' tools (README § The shell client), and its tests, a few
# thousand short processes, take from 3 to more than 20 minutes on a Mac,
# where a process costs less than on Windows (go test ./sh still runs them,
# with bash 4 or later and GNU coreutils first in PATH).
set -euo pipefail
cd "$(dirname "$0")/.."

govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0
tags=dromas_nofsync
# How long one package's tests may run: about half again the slowest's, the
# shell client's, on the slowest runner, so a test that hangs fails in
# minutes with every goroutine's stack, which names what it waits for.
timeout=6m
darwin='' nosh=''
case $(uname -s) in
  Darwin) darwin=1 nosh=macOS ;;
  MINGW* | MSYS* | CYGWIN*) nosh=Windows ;;
  FreeBSD | OpenBSD | NetBSD | DragonFly) nosh=$(uname -s) ;;
esac
if [ -n "$darwin" ] && command -v brew > /dev/null; then
  for d in "$(brew --prefix)/opt/coreutils/libexec/gnubin" "$(brew --prefix)/opt/bash/bin"; do
    if [ -d "$d" ]; then PATH="$d:$PATH"; fi
  done
fi
unset DROMAS_HOME DROMAS_MAILBOX DR_HOME DR_MAILBOX # no test may meet a real mailbox

# A test skips when a tool it runs is missing. A runner with every tool skips
# nothing, so a skip fails `full`, but for these.
allowed=(-e 'run by the crash tests, in a process of its own')
case $(uname -s) in
  # Their base systems ship sha256(1) and no sha256sum: the vectors' hashes
  # are held to sha256sum on every other runner.
  OpenBSD | NetBSD | DragonFly) allowed+=(-e 'sha256sum is not installed') ;;
esac

pkgs=$(go list ./...)
if [ -n "$nosh" ]; then
  pkgs=$(grep -v '/sh$' <<< "$pkgs")
  echo "$nosh: ./sh is left to the Linux runs (scripts/check.sh, top)" >&2
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
  go test -tags "$tags" -count=1 -timeout "$timeout" -json $pkgs | tee "$dir/test.json" | jq -rj --unbuffered 'select(.Action == "output") | .Output'
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
  # A Mailbox shared by goroutines, and every test of a held list (hold_test.go),
  # whose request runs beside the mailbox's other commands, under the race
  # detector where Go has one (go.dev/doc/articles/race_detector,
  # Requirements).
  case $(go env GOOS)/$(go env GOARCH) in
    linux/amd64 | linux/ppc64le | linux/arm64 | linux/s390x | linux/loong64 | freebsd/amd64 | netbsd/amd64 | darwin/amd64 | darwin/arm64 | windows/amd64)
      go test -tags "$tags" -race -count=1 -timeout "$timeout" -run "SharedByGoroutines|^($(sed -n 's/^func \(Test[A-Za-z0-9_]*\).*/\1/p' client/hold_test.go | paste -sd '|' -))\$" ./client
      ;;
    *) echo "$(go env GOOS)/$(go env GOARCH): the race test is left out: Go's race detector does not run here" >&2 ;;
  esac
}

# Every module before any test, the tools' too: internal/agetool builds age
# with go tool, which otherwise fetches its modules mid-test, so a fetch that
# times out reads as a failed test (v0.1.1's first tag run, macos-26-intel:
# nistec and x/term, Go's 30 s dial timeout each, 62.8 s).
go mod download

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
