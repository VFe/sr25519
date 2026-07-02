# sr25519

[![Hex.pm](https://img.shields.io/hexpm/v/sr25519.svg)](https://hex.pm/packages/sr25519)
[![Docs](https://img.shields.io/badge/hexdocs-docs-purple.svg)](https://hexdocs.pm/sr25519)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/VFe/sr25519/badge)](https://scorecard.dev/viewer/?uri=github.com/VFe/sr25519)

**sr25519 (schnorrkel) signature verification for the BEAM.**

sr25519 is Schnorr signing over the Ristretto255 group of Curve25519, with
protocol-level domain separation via Merlin transcripts — the scheme defined by
the w3f [`schnorrkel`](https://github.com/w3f/schnorrkel) crate. This library is
a thin, safety-critical [Rustler](https://hexdocs.pm/rustler) NIF over that
crate (independently audited *upstream*; the wrapper itself is human-reviewed,
not independently audited — see [SECURITY.md](SECURITY.md)).

- **v0.1: verification only.** No secret-key material surface at all. Signing,
  keypair generation, and derivation are planned for v0.2+.
- **Precompiled by default** — no Rust toolchain required to use it.

## Motivation

The BEAM ecosystem has had no maintained sr25519 library, so Elixir services
that need to check sr25519 signatures in-process — for example, signatures
produced by Substrate/Polkadot or Bittensor tooling — had to shell out or trust
a sidecar. This package provides exactly the verification primitive, hardened
for server-side use.

## Design

The library **verifies exact bytes**. It never decodes, normalizes, or
canonicalizes input: no hex, base64, SS58, SCALE, JSON, UTF-8, or
`MultiSignature` tag handling happens inside it. Those are caller
responsibilities, so the crypto core can never verify "the wrong thing". Each
real-world signing convention is a **named, vector-backed** function — never a
flag or a hidden branch inside an ambiguous "verify".

All inputs are raw-byte binaries:

- `message` — the exact bytes that were signed
- `signature` — the bare **64-byte** signature (strip any encoding or envelope first)
- `public_key` — the raw **32-byte** public key (a compressed Ristretto point)
- `context` — at the low level, schnorrkel's transcript-level domain-separation
  label (Substrate pins the 9 ASCII bytes `"substrate"`)

## Install

```elixir
def deps do
  [{:sr25519, "~> 0.1"}]
end
```

Precompiled NIFs are downloaded and checked against a committed SHA256 checksum.

To compile from source instead (an unlisted target, or by choice), you need a
Rust toolchain **and** the `rustler` package — it is an *optional* dependency of
this library, so Hex does not fetch it for you:

```elixir
def deps do
  [
    {:sr25519, "~> 0.1"},
    {:rustler, "~> 0.38"}  # only needed when force-building from source
  ]
end
```

Then set `SR25519_FORCE_BUILD=1` for the compile (or use
`config :rustler_precompiled, :force_build, sr25519: true` in your config).

### Prove the install works (30 seconds)

Paste this into `iex -S mix` — it verifies a frozen known-answer vector from the
independent `@scure/sr25519` oracle (committed in this repo's vector corpus):

```elixir
msg = "sr25519 known-answer anchor"

sig =
  Base.decode16!(
    "9a0d379ebe5a8158576e7064c01adcaf80f76cf26f4c74b10ee25fffe79bf657" <>
      "91e1e9cf7b46ee152ca95bafde4c2d4a3128d67ad7738b40d21a098d09e5b88d",
    case: :lower
  )

pk = Base.decode16!("189dac29296d31814dc8c56cf3d36a0543372bba7538fa322a4aebfebc39e056", case: :lower)

{:ok, true} = Sr25519.Substrate.verify_raw_message(msg, sig, pk)
{:ok, false} = Sr25519.Substrate.verify_raw_message("tampered" <> msg, sig, pk)
```

### Supported platforms

Precompiled artifacts (NIF version 2.15, so OTP ≥ 24; the package requires
Elixir ~> 1.15) ship for:

| Linux | macOS | Windows |
| --- | --- | --- |
| x86_64 gnu + musl | x86_64 | x86_64 msvc + gnu |
| aarch64 gnu + musl | aarch64 (Apple Silicon) | |
| arm gnueabihf, riscv64gc | | |

Anything else (FreeBSD, other archs) works via the force-build path above.

## API

```elixir
# The "substrate" signing context, message signed as-is (no wrapping) — what
# `sign(bytes)` produces in substrate-interface, subkey, py-sr25519-bindings,
# and the keyrings derived from them.
Sr25519.Substrate.verify_raw_message(message, signature, public_key)
#=> {:ok, true} | {:ok, false} | {:error, reason}

# The polkadot-js extension / `signRaw` message-signing convention. Mirrors
# `u8aWrapBytes` exactly: wraps the message in <Bytes>…</Bytes> unless it is
# already wrapped or carries the Ethereum signed-message prefix (those are
# signed — and verified — as-is).
Sr25519.Substrate.verify_wrapped_bytes(message, signature, public_key)

# Low-level: you supply the signing context yourself.
Sr25519.verify_raw(message, signature, public_key, context)
```

Per-call work is bounded: messages are capped at `Sr25519.max_message_bytes/0`
(64 KiB) and contexts at `Sr25519.max_context_bytes/0` (1 KiB); oversized input
returns a typed error instead of absorbing unbounded bytes into the transcript.

### Return contract

| Return | Meaning |
| --- | --- |
| `{:ok, true}` | valid signature over the exact bytes |
| `{:ok, false}` | 32/64-byte inputs that parse but do not verify (incl. a structurally-invalid but length-correct signature — never raises) |
| `{:error, :invalid_type}` | a non-binary argument |
| `{:error, :invalid_length}` | public key ≠ 32 bytes, or signature ≠ 64 bytes |
| `{:error, :message_too_large}` | message exceeds `Sr25519.max_message_bytes/0` |
| `{:error, :context_too_large}` | signing context exceeds `Sr25519.max_context_bytes/0` |
| `{:error, :invalid_public_key}` | public-key bytes schnorrkel rejects structurally |

Both `:error` and `{:ok, false}` fail closed — the distinction is for
metrics/alerting, not control flow.

> **Legacy-format note:** signatures from pre-0.8 schnorrkel (missing the
> `0x80` "schnorrkel-marked" bit in byte 63) parse-fail and return
> `{:ok, false}`, never an error. The deprecated legacy encoding
> (`preaudit_deprecated`) is deliberately not enabled; all modern signers
> emit the marker.

### Interop cheat-sheet

The library takes **raw bytes only** — here is how the common encodings map to them:

| You have | You need | How |
| --- | --- | --- |
| `0x`-prefixed hex signature (polkadot-js `signRaw` result) | 64-byte binary | strip `"0x"`, `Base.decode16!(hex, case: :mixed)` |
| 65-byte `MultiSignature` blob (`0x01` ‖ sig) | 64-byte binary | `<<0x01, signature::binary-size(64)>> = blob` |
| SS58 address (e.g. `5FHneW…`) | 32-byte public key | decode on the signer side (`decodeAddress` in polkadot-js, `Keypair.public_key` in substrate-interface) or use any Base58 lib: SS58 = prefix ‖ pubkey ‖ checksum. This library deliberately ships no codec. |

#### polkadot-js dapp (`signRaw`)

```js
// browser side
const { signature } = await signer.signRaw({ address, data: stringToHex(message), type: 'bytes' });
// send `signature` (0x-hex) and the address's raw public key (decodeAddress(address)) to your API
```

```elixir
# BEAM side — signRaw wraps in <Bytes>…</Bytes>; this mirrors it exactly
sig = Base.decode16!(String.trim_leading(signature_hex, "0x"), case: :mixed)
Sr25519.Substrate.verify_wrapped_bytes(message, sig, public_key)
```

#### substrate-interface / subkey (`sign` over bytes)

```elixir
# Keypair.sign(data) signs the bytes as-is under the "substrate" context
Sr25519.Substrate.verify_raw_message(message, signature, public_key)
```

If a protocol built on sr25519 signs a composite payload (a domain tag plus
fields, a canonical serialization, …), reconstruct the **exact** signed byte
string on your side and pass it to `verify_raw_message/3` — constructing those
bytes is deliberately outside this library.

#### Pitfall: extrinsic (transaction) signatures

Substrate signs the SCALE-encoded `ExtrinsicPayload`, and when that payload
exceeds **256 bytes** the signature is over its **blake2_256 hash**, not the
payload itself. If you verify transaction signatures, reproduce that rule when
constructing the bytes you pass in — otherwise long extrinsics return
`{:ok, false}` with no other symptom.

## Correctness & safety

Correctness is defined by **real-world vectors**, not prose. The vector corpus in
`test/vectors/` is generated from four oracles and frozen:

- **`substrate-interface`** (Python) — the widely deployed production signer.
- **`@polkadot/util-crypto`** (polkadot-js wasm-crypto + the exact `u8aWrapBytes`
  `signRaw` flow) — where most real-world dapp signatures come from.
- **`@scure/sr25519`** (pure-JS noble, independently audited) — the one oracle of
  **genuinely independent lineage**: the other three all descend from the w3f
  `schnorrkel` code, so only @scure proves the convention is *right* rather than
  merely self-consistent.
- **the `schnorrkel` crate** (Rust) — confirms the wrapper behaves as the crate it wraps.

All four derive the **same keypair** from a shared seed, every production
signer's signatures verify alongside @scure's over identical tuples
(cross-oracle agreement), and the corpus carries known-answer anchors lifted
verbatim from the published scure-sr25519 test suite — including the canonical
polkadot-js Alice vector.

Safety properties are enforced, not assumed:

- `#![forbid(unsafe_code)]` in the Rust core.
- `panic = "unwind"` in the release profile, so a NIF panic cannot abort the BEAM
  VM — proven by a deliberate-panic test run in a **separate OS process**, and
  guarded by a CI check that rejects `panic = "abort"`.
- Verification runs on a **dirty CPU scheduler**, so even cap-sized messages on
  slow targets cannot starve the BEAM's regular schedulers; a `MAX_MESSAGE_BYTES`
  cap bounds per-call work, and a benchmark gate asserts **p99 < 1 ms** at the
  cap as a perf-regression bound.

Run the whole ladder with one command:

```sh
mix conformance   # L0–L7 + property & safety suites → conformance_report.json
```

## Verifying release artifacts

Precompiled NIFs involve a supply chain; here is exactly what protects it and
how to check it yourself.

**The trust chain.** Each release's NIF binaries are built by
[`release.yml`](.github/workflows/release.yml) and signed with a GitHub
[build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
The Hex package embeds `checksum-Elixir.Sr25519.Native.exs`; at install time
`rustler_precompiled` downloads the artifact for your platform and rejects it
unless its SHA-256 matches that file. Before every publish, the
[`release-verify.yml`](.github/workflows/release-verify.yml) workflow
independently re-checks the release: committed checksums must equal the release
assets (both directions), every asset's attestation must verify against this
repo's release workflow, and the real download-verify-load install path must
work on Linux/macOS/Windows.

**Check an artifact yourself** (requires the [GitHub CLI](https://cli.github.com)):

```sh
gh release download vX.Y.Z --repo VFe/sr25519 --pattern '*.tar.gz' --dir assets
gh attestation verify assets/<artifact>.tar.gz --repo VFe/sr25519 \
  --signer-workflow VFe/sr25519/.github/workflows/release.yml
```

Each release also attaches every artifact's Sigstore bundle as
`<artifact>.sigstore.json`, so the same check works without calling the
attestations API (offline/air-gapped verification): add
`--bundle assets/<artifact>.tar.gz.sigstore.json`.

**Residual trust.** The checksum file binds your install to the attested bytes,
and the attestation proves those bytes were built by this repository's release
workflow at the tagged commit. What remains is the Hex tarball itself (hex.pm
does not attest packages): it is published by the reviewer-gated
[`publish.yml`](.github/workflows/publish.yml) workflow, from the same commit
`release-verify` validated. If you need stronger guarantees,
build from source with `SR25519_FORCE_BUILD=1` — the package ships the full
Rust source and the exact `Cargo.lock`.

## Versioning

`schnorrkel` is pinned exactly (`=0.11.5`); a change to its verification behavior is
treated as breaking and versioned deliberately. See [CHANGELOG.md](CHANGELOG.md) and
[SECURITY.md](SECURITY.md).

## Troubleshooting

- **`Rustler dependency is needed to force the build`** — you enabled the
  force-build path without the `rustler` dep; see
  [Install](#install) for the exact line to add.
- **`Error while downloading precompiled NIF … 404`** — the target/NIF-version
  combination has no published artifact. Either your platform is not in the
  table above (compile from source per [Install](#install)), or the version was
  published without that artifact — please open an issue.
- **Setting `SR25519_FORCE_BUILD=1` after `:sr25519` already compiled does
  nothing** — env vars aren't tracked by the compiler; run
  `mix deps.clean sr25519` first. (The `config :rustler_precompiled` form
  recompiles automatically.)

## License

Dual-licensed under
[MIT](https://github.com/VFe/sr25519/blob/main/LICENSE-MIT) or
[Apache-2.0](https://github.com/VFe/sr25519/blob/main/LICENSE-APACHE) at your
option. Bundles the BSD-3-Clause `schnorrkel` crate — see
[NOTICE](https://github.com/VFe/sr25519/blob/main/NOTICE).
