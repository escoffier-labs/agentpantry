# Releasing

Releases are cut with one script so the machine you release from never keeps
running an old binary.

## Cut a release

1. Land all changes on `master` (feature branch + PR, CI green).
2. Update `CHANGELOG.md`: rename `## Unreleased` to `## vX.Y.Z - YYYY-MM-DD` and
   add a fresh empty `## Unreleased` above it. Merge that via PR too.
3. From a clean, synced `master`:

   ```sh
   scripts/cut-release.sh vX.Y.Z
   ```

That script is the whole path and each step is a hard gate:

1. **preconditions** - on `master`, clean tree, in sync with origin,
   `CHANGELOG.md` has a `## vX.Y.Z` heading, the tag does not already exist.
2. **verify** - runs `./scripts/verify` (build + vet + full test suite).
3. **tag + push** - annotated tag; the push fires
   `.github/workflows/release.yml`, which builds per-platform archives, an SBOM,
   and provenance attestation, then publishes the GitHub release.
4. **wait** - polls until the GitHub release is visible.
5. **install** - `make install` builds a version-stamped binary into
   `~/.local/bin` (override with `PREFIX=`).
6. **confirm** - fails loudly unless `agentpantry version` reports the tag, so a
   stale binary or a `PATH` problem cannot pass silently.

## Version bump policy

- New backward-compatible commands, flags, or config keys: minor bump.
- Bug/security fixes only: patch bump.
- The `go.mod` `toolchain` directive and every `go-version` pin in
  `.github/workflows/*.yml` move together (see the v0.6.0 toolchain bump).

## Updating the live binary without cutting a release

`make install` on its own reinstalls the current checkout's binary (version from
`git describe`). Use it after pulling `master` if you want the local tool ahead
of a formal tag; `scripts/cut-release.sh` calls it for you at release time.
