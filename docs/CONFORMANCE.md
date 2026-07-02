# Spec conformance record

This library was built against a written specification (the "library plan").
This document records, section by section, where the implementation conforms
and every place it deliberately deviates — primarily for the pre-release
security review (see `SECURITY.md`).

## Anti-patterns (plan §0) — all honored

| Rule | Where enforced |
| --- | --- |
| Never normalize/decode/canonicalize input in the crypto core | The NIF takes raw binaries only; every convention lives in `Sr25519.Substrate`, named and vector-backed |
| Never let a panic cross the NIF boundary | `panic = "unwind"` + `#![forbid(unsafe_code)]` + `compile_error!` under `cfg(panic = "abort")` + CI grep + separate-OS-process panic test |
| Never accept unvalidated lengths | Rust length checks before `schnorrkel` is touched (L3-tested, incl. a direct-NIF bypass test) |
| Never verify an unbounded message | `max_message_bytes/0` (64 KiB) + `max_context_bytes/0` (1 KiB) caps, both Rust-backstopped; DirtyCpu scheduler; p99 < 1 ms perf-regression gate |
| Never ship without the checksum file | In the package `files:` list; `mix hex.build` refuses without it; L7 asserts it |
| Never hand-roll curve math | The Rust core is input validation + `schnorrkel` calls only |
| Never weaken a vector to pass CI | Corpus is frozen and committed; regeneration is deliberate and reviewed |

## Scope (§1) and API (§4)

v0.1 is verification-only exactly as specified: `Sr25519.verify_raw/4`,
`Sr25519.Substrate.verify_raw_message/3`, `Sr25519.Substrate.verify_wrapped_bytes/3`.
The Bittensor variant was deliberately **deferred and documented** (Epistula uses
the raw substrate convention; callers construct the payload). Non-goals hold: no
SS58/hex/SCALE/`MultiSignature` handling in the core.

**Deviation — error taxonomy extended.** The plan's table has four error atoms;
the implementation adds `{:error, :context_too_large}` with a separate 1 KiB
context cap. Rationale: a context capped at 64 KiB like the message would allow
~128 KiB per call into the Merlin transcript — double the bound the p99 gate
measures. Decided before v0.1 (the taxonomy freeze point), documented in the
CHANGELOG and README.

**Deviation — conditional wrapping.** `verify_wrapped_bytes/3` mirrors
polkadot-js `u8aWrapBytes` *exactly*, including its passthrough for
already-wrapped and Ethereum-prefixed messages (the plan's table implies
unconditional wrapping). The production function is conditional; matching it is
required for byte-exact interop, and the passthrough cases are vector-backed.

## NIF safety (§5) — conforming

All rules implemented and tested (rungs L3/L6): typed results everywhere,
deliberate-panic survival in a separate BEAM OS process, StreamData fuzzing
(cargo-fuzz optional per plan — not added), p99 benchmark gate, static guards.
Post-review hardening moved `verify_raw` to a **dirty CPU scheduler**: the
64 KiB cap-sized transcript absorb could exceed the ~1 ms regular-scheduler
guideline on the slower release targets (armv7, riscv64), so scheduler fairness
no longer depends on the latency bound at all. One plan item remains
environment-dependent: the p99 gate — now a perf-regression bound — has run on
CI runners and this build container, not yet on a **production-like machine**;
run it there before relying on the latency bound in production capacity
planning.

## Build & distribution (§6)

Conforming: `rustler_precompiled` with checksum + shipped `Cargo.lock` + exact
`schnorrkel = "=0.11.5"` pin, force-build escape hatch with optional `rustler`,
`cargo deny`/`cargo audit` in CI, explicit 10-target matrix taken from the
tool's defaults (pinned literally and tied to the release workflow by a
conformance test).

**Deviation — `--locked` builds.** The plan requires building with `--locked`;
`rustler` does not pass it and that is outside our control. Compensations: the
lockfile ships and is exact-pinned, and a `cargo metadata --locked` integrity
guard runs in both CI and the release workflow, so a stale lockfile can never
merge or release. Release artifacts are built in our CI from the committed
lockfile.

**Gate split (§6c/d).** Full test suites run on native Linux/macOS/Windows;
cross-compiled targets are built (10/10 proven green) and their naming +
checksums are validated by the release checksum step. Per-target *load*
smoke-tests under emulation (qemu) were **not** implemented — deviation
accepted for v0.1; the checksum download step catches artifact-shape problems,
and `release-verify.yml`'s consumer-install job now load-smokes the three
native OS families through the real precompiled-download path before publish.

## Verification spine (§8)

- **Oracle set (§8.1) — substitutions.** Implemented: the `schnorrkel` crate
  (L1), `substrate-interface` (L4, the production Substrate/Bittensor signer),
  `@polkadot/util-crypto` (L4, the polkadot-js production signer — an
  *addition* beyond the plan), and `@scure/sr25519` (L5, the independent
  lineage). **Not implemented:** the `sp_core` Rust bin and `subkey` CLI
  oracles. Rationale: both are the same `schnorrkel` + `b"substrate"` code path
  already covered three ways (the crate itself with that exact context, plus
  two production signers of that lineage); adding them would import the heavy
  polkadot-sdk build for zero new failure modes. The independence property the
  plan actually wanted is carried by `@scure`.
- **Bootstrap anchor (§8.1) — conforming (late).** The `46ebddef…` tuples are
  now lifted verbatim from the published scure-sr25519 suite
  (`test/vectors/lifted_scure_published.json`), including the canonical
  polkadot-js Alice vector — extracted from source, not re-derived — alongside
  the deterministic generated anchor.
- **Discover-and-lock (§8.2) — conforming.** `b"substrate"` / `<Bytes>` were
  confirmed against real tooling before the variants were considered correct,
  and are pinned by L4 vectors from two production signers.
- **Schema (§8.3) — conforming** (with additive fields: `convention`,
  `message_name`, `seed_name`, compact `message_repeat`).
- **Ladder (§8.5) + single command (§8.8) — conforming.** `mix conformance`
  emits `conformance_report.json`; all rungs green. The corpus still needs to
  be **copied into the consuming application's fixture set** (an
  integration-side step, §8.8's final clause).

## Governance (§9)

Name availability confirmed at selection; dual MIT/Apache-2.0 with the
`schnorrkel` BSD-3-Clause `NOTICE`; SECURITY policy + disclosure contact;
CHANGELOG; **Dependabot configured to open PRs with auto-merge prohibited**
(`.github/dependabot.yml`, crypto crates labeled for mandatory human review).

## Supply-chain posture (beyond the plan)

- Signed **build-provenance attestations** on every release artifact
  (`gh attestation verify <artifact> --repo VFe/sr25519`), now **enforced**
  pre-publish by `release-verify.yml` (checksums ≡ assets, attestation on every
  asset, real consumer-install smoke on three OS families).
- Least-privilege `permissions:` on all workflows; checkouts use
  `persist-credentials: false`.
- Every GitHub Action `uses:` reference is **pinned to a commit SHA** with a
  dependabot-refreshed version comment (the former follow-up, done);
  `zizmor` lints the workflows in CI and OpenSSF Scorecard runs weekly.
- Lockfiles committed for every ecosystem (cargo, mix, npm generators), oracle
  generator dependencies exact-pinned — including `vectors/python/requirements.txt`
  matching the versions recorded in the frozen corpus metadata; dependabot
  watches all generator manifests.
- The verify-only NIF builds schnorrkel with `default-features = false`
  (`alloc`): no `getrandom`/`rand` OS-RNG stack is linked at all.
- Elixir-side advisory scanning (`mix hex.audit`, `mix deps.audit`) alongside
  `cargo audit`/`cargo deny`; duplicate crate versions are a hard `deny`.
