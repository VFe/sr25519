//! `sr25519_nif` — a tiny, safety-critical Rustler wrapper over the w3f
//! `schnorrkel` crate for Substrate-compatible sr25519 signature *verification*.
//!
//! Design rules (see the library plan §5):
//!   * This crate NEVER normalizes, decodes, or canonicalizes input. It verifies
//!     exact bytes. Every Substrate/Bittensor convention lives on the Elixir side.
//!   * No panic may cross the NIF boundary. Every fallible step maps to a
//!     `Result`/typed term; `#![forbid(unsafe_code)]`; the release profile is
//!     `panic = "unwind"` (enforced by a CI guard + a separate-process test).
//!   * Lengths are validated in Rust before `schnorrkel` is touched; a huge
//!     message is rejected before it can be absorbed into the transcript.
#![forbid(unsafe_code)]

use rustler::{Atom, Binary, Encoder, Env, NifResult, Term};
use schnorrkel::{PublicKey, Signature};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        invalid_length,
        invalid_public_key,
        message_too_large,
    }
}

/// Hard cap on the message (and caller-supplied context) size. An unbounded
/// binary absorbed into the Merlin transcript could block the BEAM scheduler
/// (Erlang's ~1 ms NIF guideline). Kept in sync with `Sr25519.max_message_bytes/0`.
const MAX_MESSAGE_BYTES: usize = 65_536;

const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// Low-level verify over `(message, signature, public_key, context)`.
///
/// The signature is checked against `context ‖ message` through schnorrkel's
/// Merlin transcript (`PublicKey::verify_simple`). Return contract (§4/§8.4):
///
///   * `{:ok, true}`  — valid signature over the exact bytes
///   * `{:ok, false}` — 64-byte signature that parses-but-fails, OR is
///                      structurally invalid but length-correct (never a crash)
///   * `{:error, :invalid_length}`     — pubkey ≠ 32 or signature ≠ 64 bytes
///   * `{:error, :message_too_large}`  — message/context exceeds the cap
///   * `{:error, :invalid_public_key}` — pubkey schnorrkel rejects structurally
#[rustler::nif]
fn verify_raw<'a>(
    env: Env<'a>,
    message: Binary<'a>,
    signature: Binary<'a>,
    public_key: Binary<'a>,
    context: Binary<'a>,
) -> NifResult<Term<'a>> {
    let msg = message.as_slice();
    let sig = signature.as_slice();
    let pk = public_key.as_slice();
    let ctx = context.as_slice();

    // Size cap (backstop — the Elixir layer checks first to avoid copying a huge
    // binary across the boundary; re-checked here as the authoritative guard).
    if msg.len() > MAX_MESSAGE_BYTES || ctx.len() > MAX_MESSAGE_BYTES {
        return Ok(err(env, atoms::message_too_large()));
    }

    // Length validation BEFORE touching schnorrkel — wrong sizes are a caller
    // bug and must be a typed error, never an array-conversion panic.
    if pk.len() != PUBLIC_KEY_BYTES || sig.len() != SIGNATURE_BYTES {
        return Ok(err(env, atoms::invalid_length()));
    }

    // Public-key parse failure is a caller *identity* problem → typed error.
    let public = match PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(_) => return Ok(err(env, atoms::invalid_public_key())),
    };

    // A length-correct but structurally-invalid signature is NOT an error — it
    // simply does not verify. So random/tampered 64-byte values → {:ok, false}.
    let signature = match Signature::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return Ok(ok(env, false)),
    };

    let valid = public.verify_simple(ctx, msg, &signature).is_ok();
    Ok(ok(env, valid))
}

#[inline]
fn ok(env: Env<'_>, valid: bool) -> Term<'_> {
    (atoms::ok(), valid).encode(env)
}

#[inline]
fn err<'a>(env: Env<'a>, reason: Atom) -> Term<'a> {
    (atoms::error(), reason).encode(env)
}

/// Test-only NIF that deliberately panics. Compiled ONLY under the `panic_test`
/// feature and invoked by the NIF-safety test in a *separate* BEAM OS process to
/// prove `panic = "unwind"` + the catch path leave the parent VM unharmed.
#[cfg(feature = "panic_test")]
#[rustler::nif]
fn deliberate_panic() -> bool {
    panic!("sr25519_nif: deliberate panic for the NIF-safety test");
}

rustler::init!("Elixir.Sr25519.Native");
