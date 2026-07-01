defmodule Sr25519 do
  @moduledoc """
  Substrate-compatible **sr25519 (schnorrkel) signature verification** for the BEAM.

  This is a thin, safety-critical [Rustler](https://hexdocs.pm/rustler) NIF over the
  audited [w3f `schnorrkel`](https://github.com/w3f/schnorrkel) crate. It **verifies
  exact bytes** and nothing more: it never decodes, normalizes, or canonicalizes input
  (no hex, base64, SS58, SCALE, JSON, UTF-8, or `MultiSignature` tag handling). Every
  Substrate/Bittensor convention lives in a **named, vector-backed** module —
  `Sr25519.Substrate`.

  ## What this module verifies

  `verify_raw/4` is the low-level primitive: the caller supplies the signing
  `context`, and the signature is checked against `context ‖ message` through
  schnorrkel's Merlin transcript. Most callers want the named conventions in
  `Sr25519.Substrate` instead.

  ## Inputs

  All arguments are **raw-byte binaries**:

    * `message`     — the exact bytes that were signed
    * `signature`   — the bare **64-byte** sr25519 signature (strip any
      `MultiSignature` `0x01` tag and any hex/SS58 encoding first)
    * `public_key`  — the raw **32-byte** public key
    * `context`     — the signing context bytes (e.g. `"substrate"`)

  ## Return contract

  | Return | Meaning |
  | --- | --- |
  | `{:ok, true}` | valid signature over the exact bytes |
  | `{:ok, false}` | 32/64-byte inputs that parse but do not verify — including a length-correct but structurally-invalid signature (so random/tampered 64-byte values fail, they do not raise) |
  | `{:error, :invalid_type}` | a non-binary argument |
  | `{:error, :invalid_length}` | public key ≠ 32 bytes, or signature ≠ 64 bytes |
  | `{:error, :message_too_large}` | message exceeds `max_message_bytes/0` |
  | `{:error, :context_too_large}` | signing context exceeds `max_context_bytes/0` |
  | `{:error, :invalid_public_key}` | public-key bytes schnorrkel rejects structurally |

  Both `:error` and `{:ok, false}` fail closed — the distinction is for
  metrics/alerting, not control flow.
  """

  alias Sr25519.Native

  @typedoc "A typed verification error."
  @type error ::
          :invalid_type
          | :invalid_length
          | :message_too_large
          | :context_too_large
          | :invalid_public_key

  @typedoc "The result of a verification call."
  @type result :: {:ok, boolean} | {:error, error}

  # Hard caps on what gets absorbed into the Merlin transcript. An unbounded
  # binary could block the BEAM scheduler (Erlang's ~1 ms NIF guideline); the
  # p99 < 1 ms gate is benchmarked at MAX_MESSAGE_BYTES, so the context gets its
  # own (much smaller) cap rather than doubling the bound. Real signing contexts
  # are short domain labels — Substrate's is 9 bytes. Both constants are
  # mirrored in `native/sr25519_nif/src/lib.rs` and asserted equal by tests.
  @max_message_bytes 65_536
  @max_context_bytes 1_024

  @doc """
  The maximum accepted `message` size, in bytes.

  Messages larger than this are rejected with `{:error, :message_too_large}` rather
  than risking a scheduler-blocking NIF call. Realistic Substrate extrinsics and
  Bittensor/Epistula payloads are far below this cap.
  """
  @spec max_message_bytes() :: pos_integer()
  def max_message_bytes, do: @max_message_bytes

  @doc """
  The maximum accepted signing `context` size, in bytes.

  Signing contexts are short domain-separation labels (Substrate's is the 9-byte
  `"substrate"`); an oversized one returns `{:error, :context_too_large}`.
  """
  @spec max_context_bytes() :: pos_integer()
  def max_context_bytes, do: @max_context_bytes

  @doc """
  Verify a raw schnorrkel signature over `context ‖ message`.

  The caller supplies the exact signing `context`; the library validates lengths
  and the size cap, then calls schnorrkel. See the module doc for the full return
  contract.

  ## Examples

      iex> Sr25519.verify_raw("hi", <<0::512>>, <<0::256>>, "substrate")
      {:ok, false}

      iex> Sr25519.verify_raw("hi", <<0::512>>, <<0::248>>, "substrate")
      {:error, :invalid_length}

      iex> Sr25519.verify_raw("hi", <<0::512>>, 123, "substrate")
      {:error, :invalid_type}
  """
  @spec verify_raw(binary, binary, binary, binary) :: result
  def verify_raw(message, signature, public_key, context)
      when is_binary(message) and is_binary(signature) and is_binary(public_key) and
             is_binary(context) do
    cond do
      byte_size(message) > @max_message_bytes -> {:error, :message_too_large}
      byte_size(context) > @max_context_bytes -> {:error, :context_too_large}
      true -> Native.verify_raw(message, signature, public_key, context)
    end
  end

  def verify_raw(_message, _signature, _public_key, _context), do: {:error, :invalid_type}
end
