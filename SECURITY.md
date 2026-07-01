# Security Policy

`sr25519` is cryptographic infrastructure intended for money-path signature
verification. A vulnerability here is high-severity. Please treat it accordingly.

## Reporting a vulnerability

Report privately to **vfe@einsfeld.com** with enough detail to reproduce. Please do
**not** open a public issue for a suspected vulnerability. You will get an
acknowledgement, and we will coordinate a fix and disclosure timeline with you.

## Scope

This library **verifies exact bytes** and (in v0.1) handles **no secret material**.
The most security-relevant areas:

- The verification result contract (`Sr25519.verify_raw/4` and the named
  `Sr25519.Substrate` variants) — a wrong result on the money path is the worst case.
- The exact signing convention (`"substrate"` context; `<Bytes>…</Bytes>` wrapping)
  pinned in named, vector-backed functions. Constructing the exact signed bytes is a
  **caller** responsibility; a confused-deputy bug most often lives there.
- The NIF boundary: no panic may cross it (`panic = "unwind"`, `#![forbid(unsafe_code)]`).

## Pre-release review gate (M2.5)

Before the first published release, an independent human review is required
(someone comfortable with Rust NIFs and crypto bindings), confirming at least:

- no `unsafe`; no `unwrap`/`expect`/panic path reachable from untrusted input;
- the release workflow cannot publish a mismatched artifact/checksum;
- the vector generators are reproducible and the pinned convention matches real tooling;
- the consuming integration constructs **exactly** the signed bytes.

This gate is not a substitute for a formal audit but is required for a money-path,
AI-assisted codebase.

## Dependency & version policy

- `schnorrkel` is pinned to an exact version; `Cargo.lock` is committed and shipped;
  builds use `--locked`. `cargo audit` and `cargo deny` run in CI.
- Crypto-dependency bumps are **never auto-merged**. Any `schnorrkel` bump re-runs the
  full vector corpus and is treated as potentially breaking.

## Supported versions

Until v1.0, only the latest `0.x` release receives security fixes.
