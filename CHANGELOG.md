# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A change to the pinned `schnorrkel` version or to verification behavior is treated
as potentially breaking and versioned deliberately.

## [Unreleased]

### Added
- Supply-chain hardening from the first OpenSSF Scorecard run:
  - Releases now attach each artifact's Sigstore provenance bundle as
    `<artifact>.sigstore.json` (offline `gh attestation verify --bundle`;
    also retro-attached to v0.1.0). Release asset uploads no longer overwrite
    existing assets (`overwrite_files: false`).
  - Hex publishing moved into CI: a dispatch-only, reviewer-gated
    `publish.yml` with a dry-run default and gates that enforce the
    RELEASING.md ordering invariants (tag exists, `Release verify` green for
    the exact commit, tarball contents asserted).
  - CodeQL analysis (Rust + GitHub Actions) on every PR, push to `main`, and
    weekly.
  - `CONTRIBUTING.md`.

## [0.1.0] - 2026-07-02

The first public release: the verification-only core, plus a pre-publish
security-hardening pass (no vulnerabilities found; all hardening changes are
defense-in-depth or supply-chain robustness).

### Added
- **Verification-only v0.1 core.**
  - `Sr25519.verify_raw/4` — low-level schnorrkel verify over
    `(message, signature, public_key, context)`; validates lengths, a
    `max_message_bytes/0` cap on the message and a `max_context_bytes/0` cap on
    the signing context (`{:error, :context_too_large}`), and maps every
    fallible step to a typed result.
  - `Sr25519.Substrate.verify_raw_message/3` — the `"substrate"` context, no wrapping.
  - `Sr25519.Substrate.verify_wrapped_bytes/3` — the polkadot-js `signRaw`
    convention, mirroring `u8aWrapBytes` exactly: wraps in `<Bytes>…</Bytes>`
    unless the message is already wrapped or Ethereum-prefixed (passthrough,
    vector-backed).
- Rust NIF over `schnorrkel = "=0.11.5"` with `#![forbid(unsafe_code)]` and
  `panic = "unwind"`.
- Frozen cross-implementation vector corpus from four oracles —
  `substrate-interface` (production Substrate/Bittensor signer),
  `@polkadot/util-crypto` (the polkadot-js wasm signer + exact `signRaw` flow),
  `@scure/sr25519` (independent lineage), and the `schnorrkel` crate itself —
  and a single-command conformance ladder (`mix conformance`, rungs L0–L7).
- Concurrency and memory-stability tests (parallel verification from 64
  processes; 20k-call sustained-load memory bound).
- NIF-safety suite: separate-process deliberate-panic survival test, input fuzzing,
  and a p99 < 1 ms latency gate.
- Precompiled distribution via `rustler_precompiled` with a `SR25519_FORCE_BUILD`
  source-build escape hatch.
- **`release-verify.yml`** — a pre-publish gate triggered by the checksum
  commit: committed checksums must exactly match the GitHub release assets
  (both directions), every asset's build-provenance attestation is verified
  against `release.yml`, and the real consumer install path (precompiled
  download + checksum verification + NIF load + known-answer verifies) is
  exercised on Linux/macOS/Windows.
- **All GitHub Actions pinned to commit SHAs** (with dependabot-refreshed
  version comments); `persist-credentials: false` on every checkout; `zizmor`
  workflow linting and an OpenSSF Scorecard workflow.
- Elixir-side advisory scanning in CI (`mix hex.audit` + `mix deps.audit` via
  `mix_audit`).
- Dependabot coverage for the vector-generator manifests
  (`vectors/rust_oracle` cargo, `vectors/python` pip) and a pinned
  `vectors/python/requirements.txt` matching the frozen corpus metadata.
- `.github/CODEOWNERS`; the release job targets a protectable `release`
  environment; RELEASING.md documents the required one-time repository
  settings and gates publishing on `Release verify` being green.
- README section **"Verifying release artifacts"** (trust chain,
  `gh attestation verify` instructions, residual-trust statement).
- Tests: 1 MiB signature/public-key cheap rejection, `Sr25519.Substrate`
  non-binary `:invalid_type` coverage, direct-NIF `ArgumentError` boundary
  contract, and direct-NIF wrong-length backstop coverage.

### Changed
- **`verify_raw` now runs on a dirty CPU scheduler.** The 64 KiB cap-sized
  transcript absorb could exceed the BEAM's ~1 ms regular-scheduler guideline
  on slow release targets (armv7, riscv64); scheduler fairness no longer
  depends on verify latency. The p99 < 1 ms benchmark stays as a
  perf-regression gate. Verification behavior is unchanged.
- **schnorrkel is built with `default-features = false` (`alloc`)**: the OS-RNG
  stack (`getrandom`, `rand`, `rand_chacha`, `ppv-lite86`, `zerocopy`, `aead`,
  `wasi`) is no longer linked into the verify-only NIF — 8 fewer supply-chain
  crates. Proven behavior-identical by the frozen vector corpus.
- `Sr25519.verify_raw/4` rejects wrong-length signatures/public keys before
  calling the NIF (the Rust checks remain the authoritative backstop, still
  covered by direct-NIF tests).
- The release profile builds with `overflow-checks = true` (an overflow panics
  and unwinds into a typed error instead of silently wrapping).
- `cargo-deny` now **fails** on duplicate crate versions (was: warn).

### Fixed
- SECURITY.md claimed builds use `--locked`; the actual mechanism is a
  `cargo metadata --locked` integrity gate in CI and release (rustler does not
  pass `--locked` to cargo).
- README/moduledoc/package wording no longer reads as if this wrapper were
  audited — `schnorrkel` is audited upstream; the wrapper is human-reviewed.
- Documented that legacy pre-0.8 unmarked schnorrkel signatures verify as
  `{:ok, false}` (the deprecated `preaudit_deprecated` encoding is deliberately
  not enabled).

[Unreleased]: https://github.com/VFe/sr25519/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/VFe/sr25519/commits/v0.1.0
