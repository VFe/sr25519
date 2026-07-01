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
    msg = Sr25519.Vectors.unhex(@good["message_hex"])
    <<first, rest::binary>> = msg
    tampered = <<Bitwise.bxor(first, 1)>> <> rest
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])
    assert Sr25519.Substrate.verify_raw_message(tampered, sig, pk) == {:ok, false}
  end

  @tag rung: :L3
  test "single-byte tamper of a good signature -> {:ok, false}" do
    msg = Sr25519.Vectors.unhex(@good["message_hex"])
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    <<head::binary-size(10), b, rest::binary>> = sig
    tampered = <<head::binary, Bitwise.bxor(b, 1), rest::binary>>
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])
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
end
