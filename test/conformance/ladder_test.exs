defmodule Sr25519.Conformance.L0Test do
  # L0 — build & load: the NIF compiles and loads (no :nif_not_loaded).
  use ExUnit.Case, async: true
  @moduletag :conformance

  @tag rung: :L0
  test "the NIF is loaded and returns a typed result" do
    # A load failure would raise :nif_not_loaded instead of returning a tuple.
    assert Sr25519.verify_raw("x", <<0::512>>, <<0::256>>, "substrate") in [
             {:ok, true},
             {:ok, false}
           ]
  end
end

defmodule Sr25519.Conformance.L1Test do
  # L1 — crate conformance: the wrapper behaves as the schnorrkel crate it wraps.
  use ExUnit.Case, async: true
  @moduletag :conformance

  for v <- Sr25519.Vectors.by_tool("rust") do
    @tag rung: :L1
    test "crate conformance: #{v["name"]}" do
      vector = unquote(Macro.escape(v))
      assert Sr25519.Vectors.run(vector) == {:ok, vector["expected"]}
    end
  end
end

defmodule Sr25519.Conformance.L2Test do
  # L2 — known-answer: a frozen, independent, deterministic anchor verifies.
  use ExUnit.Case, async: true
  @moduletag :conformance

  @tag rung: :L2
  test "the known-answer anchor verifies {:ok, true}" do
    assert Sr25519.Vectors.run(Sr25519.Vectors.known_answer()) == {:ok, true}
  end

  @tag rung: :L2
  test "all oracles agree on the anchor keypair (independent derivation from the seed)" do
    anchor = Sr25519.Vectors.known_answer()

    pubkeys =
      Sr25519.Vectors.all()
      |> Enum.filter(&(&1["seed_name"] == anchor["seed_name"] and &1["expected"]))
      |> Enum.map(& &1["public_key_hex"])
      |> Enum.uniq()

    assert length(pubkeys) == 1, "oracles derived different keypairs: #{inspect(pubkeys)}"
  end
end

defmodule Sr25519.Conformance.L4Test do
  # L4 — Substrate convention: the production convention is correct and pinned.
  use ExUnit.Case, async: true
  @moduletag :conformance

  @tag rung: :L4
  test "the substrate signing context is pinned to the exact 9 bytes" do
    assert Sr25519.Substrate.signing_context() == "substrate"

    assert :binary.bin_to_list(Sr25519.Substrate.signing_context()) ==
             [0x73, 0x75, 0x62, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65]
  end

  for v <- Sr25519.Vectors.by_tool("substrate_interface") do
    @tag rung: :L4
    test "substrate-interface: #{v["name"]}" do
      vector = unquote(Macro.escape(v))
      assert Sr25519.Vectors.run(vector) == {:ok, vector["expected"]}
    end
  end

  # u8aWrapBytes is CONDITIONAL: an already-<Bytes>-wrapped or Ethereum-prefixed
  # message is signed as-is by polkadot-js signRaw. verify_wrapped_bytes/3 must
  # mirror that passthrough, so for these corpus messages (signed raw by the
  # oracles, exactly as signRaw would) it must agree with verify_raw_message/3.
  for name <- ["prewrapped", "eth_prefixed"] do
    @tag rung: :L4
    test "u8aWrapBytes passthrough: #{name} verifies identically via both variants" do
      vectors =
        Sr25519.Vectors.all()
        |> Enum.filter(
          &(&1["message_name"] == unquote(name) and &1["convention"] == "substrate_raw" and
              &1["expected"])
        )

      assert vectors != [], "no #{unquote(name)} vectors in the corpus"

      for v <- vectors do
        msg = Sr25519.Vectors.message(v)
        sig = Sr25519.Vectors.unhex(v["signature_hex"])
        pk = Sr25519.Vectors.unhex(v["public_key_hex"])

        assert Sr25519.Substrate.verify_raw_message(msg, sig, pk) == {:ok, true}
        assert Sr25519.Substrate.verify_wrapped_bytes(msg, sig, pk) == {:ok, true}
      end
    end
  end

  @tag rung: :L4
  test "a plain message still gets wrapped: raw-signed signature fails via verify_wrapped_bytes" do
    v =
      Sr25519.Vectors.all()
      |> Enum.find(
        &(&1["message_name"] == "ascii" and &1["convention"] == "substrate_raw" and
            &1["expected"])
      )

    msg = Sr25519.Vectors.message(v)
    sig = Sr25519.Vectors.unhex(v["signature_hex"])
    pk = Sr25519.Vectors.unhex(v["public_key_hex"])

    assert Sr25519.Substrate.verify_raw_message(msg, sig, pk) == {:ok, true}
    assert Sr25519.Substrate.verify_wrapped_bytes(msg, sig, pk) == {:ok, false}
  end
end

defmodule Sr25519.Conformance.L5Test do
  # L5 — independent oracle: convention-correct, not merely self-consistent.
  use ExUnit.Case, async: true
  @moduletag :conformance

  for v <- Sr25519.Vectors.by_tool("scure") do
    @tag rung: :L5
    test "independent @scure oracle: #{v["name"]}" do
      vector = unquote(Macro.escape(v))
      assert Sr25519.Vectors.run(vector) == {:ok, vector["expected"]}
    end
  end

  @tag rung: :L5
  test "cross-oracle agreement: @scure and substrate-interface both verify the same tuples" do
    key = fn v -> {v["seed_name"], v["message_name"], v["convention"]} end

    scure =
      for v <- Sr25519.Vectors.by_tool("scure"), v["expected"], into: %{}, do: {key.(v), v}

    si =
      for v <- Sr25519.Vectors.by_tool("substrate_interface"),
          v["expected"],
          into: %{},
          do: {key.(v), v}

    shared =
      MapSet.intersection(MapSet.new(Map.keys(scure)), MapSet.new(Map.keys(si)))

    assert MapSet.size(shared) > 0, "no shared (seed, message, convention) tuples to compare"

    for k <- shared do
      assert Sr25519.Vectors.run(scure[k]) == {:ok, true}, "@scure #{inspect(k)}"
      assert Sr25519.Vectors.run(si[k]) == {:ok, true}, "substrate-interface #{inspect(k)}"
    end
  end

  @tag rung: :L5
  test "required coverage: every oracle x convention x message positive cell is present" do
    spec = Sr25519.Vectors.spec()
    positives = Enum.filter(Sr25519.Vectors.all(), & &1["expected"])

    have =
      MapSet.new(positives, fn v ->
        {v["tool"], v["convention"], v["message_name"], v["seed_name"]}
      end)

    applies? = fn msg, oracle, conv, seed ->
      case msg["only"] do
        nil ->
          true

        only ->
          (only["oracle"] || oracle) == oracle and
            (only["seed_name"] || seed["name"]) == seed["name"] and
            (only["convention"] || conv["name"]) == conv["name"]
      end
    end

    missing =
      for conv <- spec["conventions"],
          oracle <- conv["oracles"],
          msg <- spec["messages"],
          msg["name"] not in (conv["skip_messages"] || []),
          seed <- spec["seeds"],
          applies?.(msg, oracle, conv, seed),
          not MapSet.member?(have, {oracle, conv["name"], msg["name"], seed["name"]}) do
        {oracle, conv["name"], msg["name"], seed["name"]}
      end

    assert missing == [], "missing required positive vectors: #{inspect(missing)}"
  end

  @tag rung: :L5
  test "required coverage: every negative kind is present" do
    required = ~w(tamper_message tamper_sig wrong_signer wrong_context wrong_wrapping)

    present =
      Sr25519.Vectors.all()
      |> Enum.reject(& &1["expected"])
      |> Enum.map(fn v -> v["name"] |> String.split(":") |> List.last() end)
      |> MapSet.new()

    missing = Enum.reject(required, &MapSet.member?(present, &1))
    assert missing == [], "missing negative kinds: #{inspect(missing)}"
  end
end
