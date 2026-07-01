defmodule Sr25519.ConcurrencyTest do
  @moduledoc """
  L6 — the NIF is safe under heavy concurrent load from many BEAM schedulers:
  correct results, no crashes, and no runaway memory (binaries cross the NIF
  boundary by reference and nothing is retained per call).
  """
  use ExUnit.Case, async: false
  @moduletag :conformance

  @good Sr25519.Vectors.known_answer()
  @tasks 64
  @iters 200

  @tag rung: :L6
  @tag timeout: 120_000
  test "concurrent verifies from #{@tasks} processes stay correct and typed" do
    msg = Sr25519.Vectors.message(@good)
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])

    results =
      1..@tasks
      |> Task.async_stream(
        fn task_i ->
          for i <- 1..@iters do
            case rem(task_i + i, 3) do
              # valid vector must verify true every time — no cross-call interference
              0 ->
                {:ok, true} = Sr25519.Substrate.verify_raw_message(msg, sig, pk)

              # deterministic tamper must verify false every time
              1 ->
                <<first, rest::binary>> = msg
                tampered = <<Bitwise.bxor(first, 0x01), rest::binary>>
                {:ok, false} = Sr25519.Substrate.verify_raw_message(tampered, sig, pk)

              # random garbage must always come back typed
              2 ->
                r = Sr25519.verify_raw(:crypto.strong_rand_bytes(64), sig, pk, "substrate")
                true = match?({:ok, b} when is_boolean(b), r)
            end
          end

          :ok
        end,
        max_concurrency: @tasks,
        ordered: false,
        timeout: 60_000
      )
      |> Enum.map(fn {:ok, :ok} -> :ok end)

    assert length(results) == @tasks
  end

  @tag rung: :L6
  @tag timeout: 120_000
  test "sustained verification does not grow VM memory" do
    msg = Sr25519.Vectors.message(@good)
    sig = Sr25519.Vectors.unhex(@good["signature_hex"])
    pk = Sr25519.Vectors.unhex(@good["public_key_hex"])

    # settle, then measure across a large batch of calls
    :erlang.garbage_collect()
    before = :erlang.memory(:total)

    for _ <- 1..20_000 do
      {:ok, true} = Sr25519.Substrate.verify_raw_message(msg, sig, pk)
    end

    :erlang.garbage_collect()
    afterwards = :erlang.memory(:total)

    # Generous bound: 20k verifies must not retain anything material. A real
    # per-call leak of even 1 KiB would add ~20 MiB and trip this.
    assert afterwards - before < 16 * 1024 * 1024,
           "VM memory grew by #{afterwards - before} bytes over 20k verifies"
  end
end
