defmodule Sr25519.PropertyTest do
  @moduledoc "L6 — universal invariants over many generated inputs (StreamData)."
  use ExUnit.Case, async: true
  use ExUnitProperties
  import Bitwise
  @moduletag :conformance

  @good Sr25519.Vectors.known_answer()

  # NOTE: generate bytes with StreamData (seeded, shrinkable), never
  # :crypto.strong_rand_bytes — CSPRNG output is not a function of the ExUnit
  # seed, so failures would not reproduce with `mix test --seed N`.

  @tag rung: :L6
  property "∀ wrong-length signature → {:error, :invalid_length}" do
    check all(
            len <- StreamData.filter(StreamData.integer(0..200), &(&1 != 64)),
            sig <- StreamData.binary(length: len)
          ) do
      assert Sr25519.verify_raw("m", sig, <<0::256>>, "substrate") == {:error, :invalid_length}
    end
  end

  @tag rung: :L6
  property "∀ wrong-length public key → {:error, :invalid_length}" do
    check all(
            len <- StreamData.filter(StreamData.integer(0..200), &(&1 != 32)),
            pk <- StreamData.binary(length: len)
          ) do
      assert Sr25519.verify_raw("m", <<0::512>>, pk, "substrate") == {:error, :invalid_length}
    end
  end

  @tag rung: :L6
  property "∀ non-binary argument → {:error, :invalid_type}" do
    non_binary =
      StreamData.one_of([
        StreamData.integer(),
        StreamData.list_of(StreamData.integer(0..255)),
        StreamData.constant(nil),
        StreamData.atom(:alphanumeric),
        StreamData.float()
      ])

    check all(bad <- non_binary) do
      assert Sr25519.verify_raw(bad, <<0::512>>, <<0::256>>, "substrate") ==
               {:error, :invalid_type}

      assert Sr25519.verify_raw("m", bad, <<0::256>>, "substrate") == {:error, :invalid_type}
      assert Sr25519.verify_raw("m", <<0::512>>, bad, "substrate") == {:error, :invalid_type}
      assert Sr25519.verify_raw("m", <<0::512>>, <<0::256>>, bad) == {:error, :invalid_type}
    end
  end

  @tag rung: :L6
  property "∀ single-byte tamper of a good message → {:ok, false}" do
    msg = Sr25519.Vectors.unhex(@good["message_hex"])
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])
    size = byte_size(msg)

    check all(
            idx <- StreamData.integer(0..(size - 1)),
            flip <- StreamData.integer(1..255)
          ) do
      <<pre::binary-size(idx), b, post::binary>> = msg
      tampered = <<pre::binary, bxor(b, flip), post::binary>>
      assert Sr25519.Substrate.verify_raw_message(tampered, sig, pk) == {:ok, false}
    end
  end

  @tag rung: :L6
  property "∀ single-byte tamper of a good signature → {:ok, false}" do
    msg = Sr25519.Vectors.unhex(@good["message_hex"])
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])

    check all(
            idx <- StreamData.integer(0..63),
            flip <- StreamData.integer(1..255)
          ) do
      <<pre::binary-size(idx), b, post::binary>> = sig
      tampered = <<pre::binary, bxor(b, flip), post::binary>>
      assert Sr25519.Substrate.verify_raw_message(msg, tampered, pk) == {:ok, false}
    end
  end

  @tag rung: :L6
  property "∀ random inputs → a typed result, never a raise or crash" do
    check all(
            msg <- StreamData.binary(max_length: 512),
            sig <- StreamData.binary(max_length: 80),
            pk <- StreamData.binary(max_length: 40),
            ctx <- StreamData.binary(max_length: 32)
          ) do
      result = Sr25519.verify_raw(msg, sig, pk, ctx)

      assert match?({:ok, b} when is_boolean(b), result) or
               match?({:error, a} when is_atom(a), result)
    end
  end
end
