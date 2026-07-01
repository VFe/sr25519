# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A change to the pinned `schnorrkel` version or to verification behavior is treated
as potentially breaking and versioned deliberately.

## [Unreleased]

## [0.1.0] - 2026-07-01

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

[Unreleased]: https://github.com/VFe/sr25519/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/VFe/sr25519/commits/v0.1.0
