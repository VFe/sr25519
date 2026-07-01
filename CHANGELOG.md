# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A change to the pinned `schnorrkel` version or to verification behavior is treated
as potentially breaking and versioned deliberately.

## [Unreleased]

### Added
- **Verification-only v0.1 core.**
  - `Sr25519.verify_raw/4` — low-level schnorrkel verify over
    `(message, signature, public_key, context)`; validates lengths and a
    `MAX_MESSAGE_BYTES` cap, maps every fallible step to a typed result.
  - `Sr25519.Substrate.verify_raw_message/3` — the `"substrate"` context, no wrapping.
  - `Sr25519.Substrate.verify_wrapped_bytes/3` — the `<Bytes>…</Bytes>` convention.
- Rust NIF over `schnorrkel = "=0.11.5"` with `#![forbid(unsafe_code)]` and
  `panic = "unwind"`.
- Frozen cross-implementation vector corpus (`substrate-interface`, `@scure/sr25519`,
  `schnorrkel` crate) and a single-command conformance ladder (`mix conformance`,
  rungs L0–L7).
- NIF-safety suite: separate-process deliberate-panic survival test, input fuzzing,
  and a p99 < 1 ms latency gate.
- Precompiled distribution via `rustler_precompiled` with a `SR25519_FORCE_BUILD`
  source-build escape hatch.

[Unreleased]: https://github.com/vfe/sr25519/commits/main
