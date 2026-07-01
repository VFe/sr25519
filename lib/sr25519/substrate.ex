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

    * `verify_wrapped_bytes/3` — the signer used the polkadot-js extension /
      `signRaw` message-signing convention (`u8aWrapBytes`), which wraps the
      message in `<Bytes>…</Bytes>` **unless it is already wrapped or carries the
      Ethereum signed-message prefix** — this function mirrors that conditional
      behavior exactly, so pass the message precisely as the dapp passed it to
      `signRaw`.

  If a caller already holds the exact signed bytes (wrapped or otherwise), use
  `Sr25519.verify_raw/4` with the `"substrate"` context directly.
  """

  # The Substrate signing context: the 9 ASCII bytes "substrate"
  # (hex 73 75 62 73 74 72 61 74 65). Defined as `const SIGNING_CTX: &[u8] =
  # b"substrate"` in sp_core::sr25519 and used identically by polkadot-js/wasm.
  @signing_context "substrate"

  # polkadot-js `u8aWrapBytes` constants (@polkadot/util src/u8a/wrap.ts):
  # PREFIX  "<Bytes>"  = hex 3c 42 79 74 65 73 3e        (7 bytes)
  # SUFFIX  "</Bytes>" = hex 3c 2f 42 79 74 65 73 3e     (8 bytes)
  # ETHEREUM "\x19Ethereum Signed Message:\n"            (26 bytes)
  @wrap_prefix "<Bytes>"
  @wrap_suffix "</Bytes>"
  @wrap_overhead byte_size(@wrap_prefix) + byte_size(@wrap_suffix)
  @eth_prefix <<0x19, "Ethereum Signed Message:\n">>

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
  Verify an sr25519 signature produced by the polkadot-js extension / `signRaw`
  message-signing convention, under the `"substrate"` context.

  Mirrors `u8aWrapBytes` from `@polkadot/util` exactly: the message is wrapped as
  `<Bytes>message</Bytes>` **unless** it is already `<Bytes>…</Bytes>`-wrapped or
  starts with the Ethereum signed-message prefix (`"\\x19Ethereum Signed
  Message:\\n"`), in which case the signer signed it as-is and so it is verified
  as-is. Pass the message exactly as the dapp passed it to `signRaw`.

  Because wrapping adds #{@wrap_overhead} bytes, a message that gets wrapped must
  satisfy `byte_size(message) <= Sr25519.max_message_bytes() - #{@wrap_overhead}`;
  larger ones return `{:error, :message_too_large}`. Already-wrapped /
  Ethereum-prefixed messages are capped at `Sr25519.max_message_bytes()` itself.
  """
  @spec verify_wrapped_bytes(binary, binary, binary) :: Sr25519.result()
  def verify_wrapped_bytes(message, signature, public_key) when is_binary(message) do
    cond do
      wrapped_or_eth?(message) ->
        Sr25519.verify_raw(message, signature, public_key, @signing_context)

      # Reject before allocating the wrapped copy: a doomed oversized message
      # should not cost a ~64 KiB concat on the error path.
      byte_size(message) + @wrap_overhead > Sr25519.max_message_bytes() ->
        {:error, :message_too_large}

      true ->
        wrapped = @wrap_prefix <> message <> @wrap_suffix
        Sr25519.verify_raw(wrapped, signature, public_key, @signing_context)
    end
  end

  def verify_wrapped_bytes(_message, _signature, _public_key), do: {:error, :invalid_type}

  # u8aIsWrapped(u8a, withEthereum: true): already <Bytes>…</Bytes>-wrapped
  # (length must fit both delimiters), or Ethereum-prefixed.
  defp wrapped_or_eth?(message) do
    (byte_size(message) >= @wrap_overhead and
       String.starts_with?(message, @wrap_prefix) and
       String.ends_with?(message, @wrap_suffix)) or
      String.starts_with?(message, @eth_prefix)
  end
end
