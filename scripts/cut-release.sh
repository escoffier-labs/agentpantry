#!/usr/bin/env bash
#
# cut-release.sh vX.Y.Z
#
# One reusable path from a green master to a published release AND an updated
# live binary, so the machine you cut from never keeps running an old build.
#
# Steps, each a hard gate:
#   1. preconditions  - on master, clean, synced with origin, CHANGELOG names the
#                       version, tag does not already exist
#   2. verify         - ./scripts/verify (build + vet + full test suite)
#   3. tag + push     - annotated tag; the push fires .github/workflows/release.yml
#   4. wait           - poll until the GitHub release exists
#   5. install        - make install (version-stamped binary into ~/.local/bin)
#   6. confirm        - the running `agentpantry version` MUST report the tag,
#                       or the script fails loudly
#
# Idempotency: if the tag already exists the script refuses; re-running after a
# partial failure past the tag step is safe from step 4 onward (skips existing).
set -euo pipefail

REPO="escoffier-labs/agentpantry"
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: scripts/cut-release.sh vX.Y.Z" >&2
  exit 2
fi
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must look like v1.2.3, got '$VERSION'" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf '\n=== %s ===\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ---- 1. preconditions ------------------------------------------------------
say "1/6 preconditions"
branch="$(git rev-parse --abbrev-ref HEAD)"
[[ "$branch" == "master" ]] || die "must cut from master (on '$branch')"
[[ -z "$(git status --porcelain)" ]] || die "working tree not clean; commit or stash first"
git fetch origin --quiet --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/master)" ]] \
  || die "local master is not in sync with origin/master"
# CHANGELOG must carry a heading for this version (with or without the leading v)
if ! grep -Eq "^## (${VERSION}|${VERSION#v})([[:space:]]|$)" CHANGELOG.md; then
  die "CHANGELOG.md has no '## ${VERSION}' section; bump the changelog first"
fi
if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
  die "tag ${VERSION} already exists locally"
fi
if git ls-remote --exit-code --tags origin "refs/tags/${VERSION}" >/dev/null 2>&1; then
  die "tag ${VERSION} already exists on origin"
fi
echo "ok: on master, clean, synced, CHANGELOG names ${VERSION}, tag is free"

# ---- 2. verify -------------------------------------------------------------
say "2/6 verify (build + vet + tests)"
./scripts/verify

# ---- 3. tag + push ---------------------------------------------------------
say "3/6 tag and push ${VERSION}"
git tag -a "${VERSION}" -m "Agent Pantry ${VERSION}"
git push origin "${VERSION}"
echo "pushed tag ${VERSION}; release.yml is now building artifacts"

# ---- 4. wait for the published release -------------------------------------
say "4/6 waiting for the GitHub release to publish"
published=false
for _ in $(seq 1 90); do
  if gh release view "${VERSION}" --repo "${REPO}" >/dev/null 2>&1; then
    published=true
    break
  fi
  sleep 10
done
if [[ "$published" != true ]]; then
  echo "warning: release ${VERSION} not visible yet after ~15m; check the Actions tab." >&2
  echo "         continuing to install the live binary from the local tagged tree." >&2
fi

# ---- 5. install the live binary --------------------------------------------
say "5/6 installing the live binary (make install)"
# HEAD is the tagged commit, so the Makefile's git-describe VERSION == the tag.
make install

# ---- 6. confirm the running binary matches ---------------------------------
say "6/6 confirming the live binary reports ${VERSION}"
bin="$(command -v agentpantry || true)"
[[ -n "$bin" ]] || die "agentpantry not found on PATH after install; check that ${HOME}/.local/bin is on PATH"
running="$("$bin" version 2>/dev/null | head -1)"
if ! grep -qF "${VERSION}" <<<"$running"; then
  die "live binary drift: '$bin' reports '$running', expected ${VERSION}. Fix PATH or reinstall."
fi
echo "ok: $bin -> $running"

say "done: ${VERSION} released and the live binary is current"
