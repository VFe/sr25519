# Contributing

Thanks for your interest. This is cryptographic infrastructure for money-path
signature verification, so the bar for changes is deliberately high and the
process below is enforced by CI and branch protection.

## Build and test

```sh
mix deps.get
SR25519_FORCE_BUILD=1 mix test     # builds the NIF from source (needs Rust stable)
mix conformance                    # the full L0–L7 conformance ladder
mix format --check-formatted
mix dialyzer
```

Without `SR25519_FORCE_BUILD=1`, compilation downloads a precompiled NIF for a
released version — for local development against unreleased native code, always
force-build. Toolchain versions CI uses: OTP 26.2 / Elixir 1.16.3 / Rust stable.

## Requirements for pull requests

- **Every functional change needs tests.** New functionality ships with tests
  that fail without it; bug fixes ship with a regression test. The conformance
  suite (`mix conformance`) must stay green on Linux and macOS, and the portable
  subset on Windows.
- **Vector-backed behavior is frozen.** Never edit files under `vectors/` to
  make a test pass — a behavior change against the frozen corpus is a breaking
  change by definition and needs a maintainer decision first (see
  [SECURITY.md](SECURITY.md)).
- **Rust changes**: `#![forbid(unsafe_code)]` stays; no `unwrap`/`expect`/panic
  reachable from untrusted input; `panic = "unwind"` stays (a NIF panic must
  not kill the BEAM); keep `Cargo.lock` in sync (`cargo metadata --locked`).
- **Crypto-sensitive changes** (anything touching `schnorrkel`/
  `curve25519-dalek`/`merlin`, the signing convention, or the release pipeline)
  require the human review gate described in [SECURITY.md](SECURITY.md) and a
  full corpus re-validation. Expect these to move slowly on purpose.
- Workflows are SHA-pinned and least-privilege; `audit.yml` (zizmor) enforces
  this on every PR.

## Reporting issues

Bugs and feature requests: GitHub issues. **Suspected vulnerabilities: never a
public issue** — follow [SECURITY.md](SECURITY.md) (private vulnerability
reporting or email).

## Releasing

Maintainer-only; the process is documented in [RELEASING.md](RELEASING.md).
