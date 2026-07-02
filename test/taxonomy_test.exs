defmodule Sr25519.TaxonomyTest do
  @moduledoc """
  L3 — the error-taxonomy contract (§8.4). Every row is a fixed input → output.
  """
  use ExUnit.Case, async: true
  @moduletag :conformance

  # A real, valid vector (for the {:ok, true} row).
  @good Sr25519.Vectors.known_answer()

  # A 32-byte value schnorrkel rejects structurally (invalid Ristretto point).
  @bad_pubkey Base.decode16!("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")

  @tag rung: :L3
  test "a known-good vector -> {:ok, true}" do
    assert Sr25519.Vectors.run(@good) == {:ok, true}
  end

  @tag rung: :L3
  test "single-byte tamper of a good message -> {:ok, false}" do
    {msg, sig, pk} = Sr25519.Vectors.triple(@good)
    <<first, rest::binary>> = msg
    tampered = <<Bitwise.bxor(first, 1)>> <> rest
    assert Sr25519.Substrate.verify_raw_message(tampered, sig, pk) == {:ok, false}
  end

  @tag rung: :L3
  test "single-byte tamper of a good signature -> {:ok, false}" do
    {msg, sig, pk} = Sr25519.Vectors.triple(@good)
    <<head::binary-size(10), b, rest::binary>> = sig
    tampered = <<head::binary, Bitwise.bxor(b, 1), rest::binary>>
    assert Sr25519.Substrate.verify_raw_message(msg, tampered, pk) == {:ok, false}
  end

  @tag rung: :L3
  test "random 64-byte value as signature over a random 32-byte key -> {:ok, false}" do
    for _ <- 1..50 do
      sig = :crypto.strong_rand_bytes(64)
      pk = :crypto.strong_rand_bytes(32)

      assert Sr25519.verify_raw("msg", sig, pk, "substrate") in [
               {:ok, false},
               {:error, :invalid_public_key}
             ]
    end
  end

  @tag rung: :L3
  test "public key not 32 bytes -> {:error, :invalid_length}" do
    assert Sr25519.verify_raw("m", <<0::512>>, <<0::248>>, "substrate") ==
             {:error, :invalid_length}

    assert Sr25519.verify_raw("m", <<0::512>>, <<0::264>>, "substrate") ==
             {:error, :invalid_length}
  end

  @tag rung: :L3
  test "signature not 64 bytes -> {:error, :invalid_length}" do
    assert Sr25519.verify_raw("m", <<0::504>>, <<0::256>>, "substrate") ==
             {:error, :invalid_length}

    assert Sr25519.verify_raw("m", <<0::520>>, <<0::256>>, "substrate") ==
             {:error, :invalid_length}
  end

  @tag rung: :L3
  test "a non-binary argument -> {:error, :invalid_type}" do
    for bad <- [123, [1, 2, 3], nil, :atom, %{}, 1.5] do
      assert Sr25519.verify_raw(bad, <<0::512>>, <<0::256>>, "substrate") ==
               {:error, :invalid_type}

      assert Sr25519.verify_raw("m", bad, <<0::256>>, "substrate") == {:error, :invalid_type}
      assert Sr25519.verify_raw("m", <<0::512>>, bad, "substrate") == {:error, :invalid_type}
      assert Sr25519.verify_raw("m", <<0::512>>, <<0::256>>, bad) == {:error, :invalid_type}
    end
  end

  @tag rung: :L3
  test "message larger than MAX_MESSAGE_BYTES -> {:error, :message_too_large}" do
    too_big = :binary.copy(<<0>>, Sr25519.max_message_bytes() + 1)

    assert Sr25519.verify_raw(too_big, <<0::512>>, <<0::256>>, "substrate") ==
             {:error, :message_too_large}

    # exactly MAX is accepted (parses/verifies path, not a size error)
    at_max = :binary.copy(<<0>>, Sr25519.max_message_bytes())

    assert Sr25519.verify_raw(at_max, <<0::512>>, <<0::256>>, "substrate") in [
             {:ok, false},
             {:ok, true}
           ]
  end

  @tag rung: :L3
  test "a 32-byte public key schnorrkel rejects structurally -> {:error, :invalid_public_key}" do
    assert Sr25519.verify_raw("m", <<0::512>>, @bad_pubkey, "substrate") ==
             {:error, :invalid_public_key}
  end

  @tag rung: :L3
  test "context larger than max_context_bytes -> {:error, :context_too_large}" do
    big_ctx = :binary.copy(<<0>>, Sr25519.max_context_bytes() + 1)

    assert Sr25519.verify_raw("m", <<0::512>>, <<0::256>>, big_ctx) ==
             {:error, :context_too_large}

    at_max = :binary.copy(<<0>>, Sr25519.max_context_bytes())
    assert Sr25519.verify_raw("m", <<0::512>>, <<0::256>>, at_max) == {:ok, false}
  end

  @tag rung: :L3
  test "the Rust size caps backstop the NIF even when the Elixir guard is bypassed" do
    # Call the NIF directly (as no consumer should) to prove the caps are
    # enforced in Rust too, not only by the Elixir wrapper.
    too_big = :binary.copy(<<0>>, Sr25519.max_message_bytes() + 1)

    assert Sr25519.Native.verify_raw(too_big, <<0::512>>, <<0::256>>, "substrate") ==
             {:error, :message_too_large}

    big_ctx = :binary.copy(<<0>>, Sr25519.max_context_bytes() + 1)

    assert Sr25519.Native.verify_raw("m", <<0::512>>, <<0::256>>, big_ctx) ==
             {:error, :context_too_large}
  end

  @tag rung: :L3
  test "the Rust length checks backstop the NIF even when the Elixir guard is bypassed" do
    # The Elixir wrapper now rejects wrong lengths pre-NIF, so this direct call
    # is the only path that keeps the Rust invalid_length branch covered.
    assert Sr25519.Native.verify_raw("m", <<0::504>>, <<0::256>>, "substrate") ==
             {:error, :invalid_length}

    assert Sr25519.Native.verify_raw("m", <<0::512>>, <<0::248>>, "substrate") ==
             {:error, :invalid_length}
  end

  @tag rung: :L3
  test "a huge (1 MiB) signature or public key -> {:error, :invalid_length}, cheaply" do
    huge = :binary.copy(<<0>>, 1_048_576)

    assert Sr25519.verify_raw("m", huge, <<0::256>>, "substrate") == {:error, :invalid_length}
    assert Sr25519.verify_raw("m", <<0::512>>, huge, "substrate") == {:error, :invalid_length}

    # Even straight into the NIF: BEAM binaries cross by reference and the
    # length check is O(1), so an oversized sig/pk costs no hashing or copying.
    assert Sr25519.Native.verify_raw("m", huge, <<0::256>>, "substrate") ==
             {:error, :invalid_length}

    assert Sr25519.Native.verify_raw("m", <<0::512>>, huge, "substrate") ==
             {:error, :invalid_length}
  end

  @tag rung: :L3
  test "Substrate variants return {:error, :invalid_type} for non-binary arguments" do
    for bad <- [123, [1, 2, 3], nil, :atom, %{}, 1.5] do
      assert Sr25519.Substrate.verify_raw_message(bad, <<0::512>>, <<0::256>>) ==
               {:error, :invalid_type}

      assert Sr25519.Substrate.verify_raw_message("m", bad, <<0::256>>) ==
               {:error, :invalid_type}

      assert Sr25519.Substrate.verify_raw_message("m", <<0::512>>, bad) ==
               {:error, :invalid_type}

      assert Sr25519.Substrate.verify_wrapped_bytes(bad, <<0::512>>, <<0::256>>) ==
               {:error, :invalid_type}

      assert Sr25519.Substrate.verify_wrapped_bytes("m", bad, <<0::256>>) ==
               {:error, :invalid_type}

      assert Sr25519.Substrate.verify_wrapped_bytes("m", <<0::512>>, bad) ==
               {:error, :invalid_type}
    end
  end

  @tag rung: :L3
  test "the raw NIF raises ArgumentError on non-binary arguments" do
    # The typed {:error, :invalid_type} contract lives in the Elixir wrapper;
    # rustler's Binary decode raises badarg. This pins that boundary behavior
    # so a rustler upgrade can't change it unnoticed.
    assert_raise ArgumentError, fn ->
      Sr25519.Native.verify_raw(123, <<0::512>>, <<0::256>>, "substrate")
    end

    assert_raise ArgumentError, fn ->
      Sr25519.Native.verify_raw("m", <<0::512>>, <<0::256>>, :ctx)
    end
  end

  @tag rung: :L3
  test "the corpus spec cap matches the library constant" do
    assert Sr25519.Vectors.spec()["max_message_bytes"] == Sr25519.max_message_bytes()
  end

  @tag rung: :L3
  test "verify_wrapped_bytes rejects messages whose wrapped form would exceed the cap" do
    overhead = byte_size("<Bytes>") + byte_size("</Bytes>")
    just_over = :binary.copy(<<0>>, Sr25519.max_message_bytes() - overhead + 1)

    assert Sr25519.Substrate.verify_wrapped_bytes(just_over, <<0::512>>, <<0::256>>) ==
             {:error, :message_too_large}

    at_effective_max = :binary.copy(<<0>>, Sr25519.max_message_bytes() - overhead)

    assert Sr25519.Substrate.verify_wrapped_bytes(at_effective_max, <<0::512>>, <<0::256>>) ==
             {:ok, false}
  end
end
