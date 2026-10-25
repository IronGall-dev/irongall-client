#!/usr/bin/env bash
# scripts/tagcheck.sh <tag>: what a release tag must be, checked where it is
# made (scripts/release.sh, before the push) and where it is built
# (.github/workflows/release.yml, before anything is built): an annotated
# tag, signed by a key in .github/allowed_signers, on a commit of
# origin/main whose CI run passed. It says why it refuses one, and exits 1.
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:?usage: scripts/tagcheck.sh <tag>}
fail() { echo "tagcheck: $tag: $*" >&2; exit 1; }

[ "$(git cat-file -t "refs/tags/$tag" 2> /dev/null || true)" = tag ] || fail "not an annotated tag"
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "$tag" ||
  fail "not signed by a key in .github/allowed_signers"
commit=$(git rev-parse "refs/tags/$tag^{commit}")
git merge-base --is-ancestor "$commit" origin/main || fail "${commit:0:7} is not on origin/main"
repo=${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
passed=$(gh run list -R "$repo" --workflow ci.yml --commit "$commit" --status success --json databaseId --jq length)
[ "$passed" -gt 0 ] || fail "no CI run of ${commit:0:7} has passed"
echo "tagcheck: $tag: annotated, signed, on origin/main at ${commit:0:7}, CI passed"
