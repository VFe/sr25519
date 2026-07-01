# sr25519

[![Hex.pm](https://img.shields.io/hexpm/v/sr25519.svg)](https://hex.pm/packages/sr25519)
[![Docs](https://img.shields.io/badge/hexdocs-docs-purple.svg)](https://hexdocs.pm/sr25519)

**Substrate-compatible sr25519 (schnorrkel) signature verification for the BEAM.**

A thin, safety-critical [Rustler](https://hexdocs.pm/rustler) NIF over the audited
[w3f `schnorrkel`](https://github.com/w3f/schnorrkel) crate. It fills a real gap:
the BEAM ecosystem has had **no maintained sr25519/schnorrkel library**, which is
what you need to verify Substrate / Polkadot / Bittensor signatures in-process from
Elixir.

Precompiled by default — **no Rust toolchain required** to use it.

## What it does (and deliberately doesn't)

This library **verifies exact bytes**. It never decodes, normalizes, or
canonicalizes input: no hex, base64, SS58, SCALE, JSON, UTF-8, or `MultiSignature`
tag handling happens inside it. Those are caller responsibilities, so the crypto
core can never verify "the wrong thing". Every Substrate/Bittensor convention lives
in a **named, vector-backed** function.

- **v0.1 (this release): verification only.** No secret-key material surface at all.
- Signing / keypair generation / key derivation are planned for v0.2+.

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

Then set `SR25519_FORCE_BUILD=1` for the compile.

## Usage

All inputs are **raw-byte binaries**: the bare **64-byte** signature (strip any
`MultiSignature` `0x01` tag and any hex/SS58 encoding first) and the raw **32-byte**
public key.

```elixir
# Substrate: message signed directly under the "substrate" context, no wrapping.
# This is what substrate-interface / subkey `sign(bytes)` and Bittensor hotkeys produce.
Sr25519.Substrate.verify_raw_message(message, signature, public_key)
#=> {:ok, true} | {:ok, false} | {:error, reason}

# Substrate: polkadot-js extension / signRaw message-signing convention.
# Mirrors u8aWrapBytes exactly: wraps the message as <Bytes>…</Bytes> unless it
# is already wrapped or Ethereum-prefixed (those are signed — and verified — as-is).
Sr25519.Substrate.verify_wrapped_bytes(message, signature, public_key)

# Low-level: you supply the signing context yourself.
Sr25519.verify_raw(message, signature, public_key, "substrate")
```

### Bittensor / Epistula

Bittensor hotkey signing uses the raw `"substrate"` context with **no** wrapping.
Construct the exact Epistula payload string on your side and verify it:

```elixir
payload = "#{body}.#{uuid}.#{timestamp}.#{signed_for}"
Sr25519.Substrate.verify_raw_message(payload, signature, hotkey_public_key)
```

## Return contract

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

## Correctness & safety

Correctness is defined by **real-world vectors**, not prose. The vector corpus in
`test/vectors/` is generated from independent oracles and frozen:

- **`substrate-interface`** (Python) — the real production signer for Substrate/Bittensor.
- **`@scure/sr25519`** (pure-JS noble, independently audited) — the genuinely
  independent oracle that proves the convention is *right*, not merely self-consistent.
- **the `schnorrkel` crate** (Rust) — confirms the wrapper behaves as the crate it wraps.

All three independently derive the **same keypair** from a shared seed, and both
`substrate-interface` and `@scure` signatures verify (cross-oracle agreement).

Safety properties are enforced, not assumed:

- `#![forbid(unsafe_code)]` in the Rust core.
- `panic = "unwind"` in the release profile, so a NIF panic cannot abort the BEAM
  VM — proven by a deliberate-panic test run in a **separate OS process**, and
  guarded by a CI check that rejects `panic = "abort"`.
- A `MAX_MESSAGE_BYTES` cap keeps verify a well-behaved regular NIF; a benchmark
  gate asserts **p99 < 1 ms** at the cap.

Run the whole ladder with one command:

```sh
mix conformance   # L0–L7 + property & safety suites → conformance_report.json
```

## Versioning

`schnorrkel` is pinned exactly (`=0.11.5`); a change to its verification behavior is
treated as breaking and versioned deliberately. See [CHANGELOG.md](CHANGELOG.md) and
[SECURITY.md](SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option. Bundles the BSD-3-Clause `schnorrkel` crate — see [NOTICE](NOTICE).
