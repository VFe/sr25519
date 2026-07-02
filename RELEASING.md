# Releasing

The release flow for a precompiled-NIF package has a hard ordering constraint:
**the precompiled artifacts must exist on the GitHub release before the Hex
package (which embeds their checksums) can be built and published.** Follow the
steps in order.

## 0. Pre-release gates

- [ ] `mix conformance` green locally (every rung L0–L7).
- [ ] CI green on the release commit (Linux + macOS full ladder, Windows subset,
      `audit.yml` cargo-audit/cargo-deny).
- [ ] The **independent human security review** is done for a first release or
      any release that touches the Rust core, the conventions, or the release
      pipeline (checklist in `SECURITY.md`).
- [ ] The GitHub repository is **public** — consumers download precompiled
      artifacts from its releases.
- [ ] `CHANGELOG.md` has an entry for the version; `@version` in `mix.exs` bumped.
- [ ] No crypto-dependency bump (schnorrkel) without re-running the full vector
      corpus and treating behavior changes as breaking.

## 1. Tag and build the artifacts

```sh
git tag vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` verifies the tag matches `mix.exs` `@version`, then builds the NIF
for every target in `Sr25519.Native`'s pinned target list and attaches the
artifacts to the GitHub release. Wait for **all matrix jobs** to succeed —
a missing target becomes a consumer-facing download failure.

## 2. Generate and commit the checksum file

```sh
mix rustler_precompiled.download Sr25519.Native --all --print
git add checksum-Elixir.Sr25519.Native.exs
git commit -m "Add precompiled NIF checksums for vX.Y.Z"
git push origin main
```

This downloads every artifact from the release and records its SHA-256. The Hex
package is non-functional without this file (it is in the `files:` list and the
tarball check below asserts it).

**Do NOT move the tag onto the checksum commit.** `release.yml` triggers on any
tag push, so a forced tag update would rebuild all artifacts and overwrite the
release assets your just-committed checksums were computed from — every
consumer's download would then fail checksum verification. The checksum commit
landing on `main` *after* the tag is the normal state for precompiled-NIF
packages (explorer, tokenizers, etc.): consumers install the Hex tarball, which
is built from your working tree at publish time and carries the checksum file.

## 3. Sanity-check the tarball, then publish

```sh
mix hex.build --unpack -o /tmp/sr25519_pkg   # inspect: checksum file, native/, Cargo.lock
mix hex.publish                              # runs in the :docs env; builds HexDocs
```

`mix hex.publish` requires a hex.pm account with ownership of the `sr25519`
package (first publish claims the name) — `mix hex.user register` /
`mix hex.user auth`.

## 4. Post-publish verification

In a scratch project, add `{:sr25519, "== X.Y.Z"}` (no Rust toolchain, no
force-build) on at least one Tier-1 platform and run a known-answer verify —
this exercises the real consumer path: precompiled download + checksum match.
Use the "Prove the install works" snippet from the README verbatim (it is the
single canonical copy, and a test pins its hex values to the frozen corpus).

Finally: check the HexDocs rendered, and write GitHub release notes from the
CHANGELOG entry.

## Never

- Never publish with a checksum file that wasn't regenerated from this
  release's artifacts.
- Never auto-merge or fast-track a `schnorrkel`/`rustler` bump.
- Never weaken a compatibility vector to make a release pass.
