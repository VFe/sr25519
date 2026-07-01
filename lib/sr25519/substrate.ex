defmodule Sr25519.Substrate do
  @moduledoc """
  Named **Substrate/Polkadot** sr25519 verification conventions.

  Substrate does **not** use bare schnorrkel's defaults — it pins the signing
  context to the ASCII bytes `"substrate"`, and some message-signing flows wrap
  the payload in `<Bytes>…</Bytes>`. Each convention here is a named function
  backed by real-tooling vectors; adding a convention means adding a named
  function plus its vectors, never a hidden branch inside an ambiguous "verify".

  All inputs are raw-byte binaries: the bare **64-byte** signature (strip any
  `MultiSignature` `0x01` tag first) and the raw **32-byte** public key. The
  return contract is identical to `Sr25519.verify_raw/4`.

  ## Which function do I want?

    * `verify_raw_message/3` — the signer signed the message bytes directly under
      the `"substrate"` context, with **no** wrapping. This is what
      `substrate-interface`/`subkey` produce for `sign(bytes)`, and what
      **Bittensor** hotkeys / the **Epistula** protocol use (Epistula signs the
      plain payload string `"\#{body}.\#{uuid}.\#{timestamp}.\#{signed_for}"` with
      no wrapping — construct that exact string on the caller side and pass it here).

    * `verify_wrapped_bytes/3` — the signer wrapped the message in `<Bytes>…</Bytes>`
      before signing. This is the polkadot-js extension / `signRaw` message-signing
      convention (`u8aWrapBytes`).

  If a caller already holds the exact wrapped/prefixed bytes, use
  `Sr25519.verify_raw/4` with the `"substrate"` context directly.
  """

  # The Substrate signing context: the 9 ASCII bytes "substrate"
  # (hex 73 75 62 73 74 72 61 74 65). Defined as `const SIGNING_CTX: &[u8] =
  # b"substrate"` in sp_core::sr25519 and used identically by polkadot-js/wasm.
  @signing_context "substrate"

  # polkadot-js `u8aWrapBytes`: PREFIX ‖ message ‖ SUFFIX.
  # PREFIX  "<Bytes>"  = hex 3c 42 79 74 65 73 3e        (7 bytes)
  # SUFFIX  "</Bytes>" = hex 3c 2f 42 79 74 65 73 3e     (8 bytes)
  @wrap_prefix "<Bytes>"
  @wrap_suffix "</Bytes>"

  @doc """
  The Substrate signing context bytes (`"substrate"`).
  """
  @spec signing_context() :: binary
  def signing_context, do: @signing_context

  @doc """
  Verify an sr25519 signature over the raw `message` under the `"substrate"`
  context, with **no** wrapping.

  Use this for `substrate-interface`/`subkey` `sign(bytes)` output and for
  Bittensor/Epistula payloads.
  """
  @spec verify_raw_message(binary, binary, binary) :: Sr25519.result()
  def verify_raw_message(message, signature, public_key) do
    Sr25519.verify_raw(message, signature, public_key, @signing_context)
  end

  @doc """
  Verify an sr25519 signature over `message` wrapped as `<Bytes>message</Bytes>`
  under the `"substrate"` context.

  This is the polkadot-js extension / `signRaw` message-signing convention. Pass
  the **unwrapped** `message`; the wrapper is applied here. (Callers who already
  hold pre-wrapped bytes should use `Sr25519.verify_raw/4` directly.)
  """
  @spec verify_wrapped_bytes(binary, binary, binary) :: Sr25519.result()
  def verify_wrapped_bytes(message, signature, public_key) when is_binary(message) do
    wrapped = @wrap_prefix <> message <> @wrap_suffix
    Sr25519.verify_raw(wrapped, signature, public_key, @signing_context)
  end

  def verify_wrapped_bytes(_message, _signature, _public_key), do: {:error, :invalid_type}
end
