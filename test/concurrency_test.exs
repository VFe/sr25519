defmodule Sr25519.ConcurrencyTest do
  @moduledoc """
  L6 — the NIF is safe under heavy concurrent load from many BEAM schedulers:
  correct results, no crashes, and no runaway memory (binaries cross the NIF
  boundary by reference and nothing is retained per call).

  Both tests are `:benchmark`-tagged (like the p99 gate): they are pre-release
  stress signals that `mix conformance` and CI include, kept out of the fast
  `mix test` inner loop.
  """
  use ExUnit.Case, async: false
  @moduletag :conformance

  {msg, sig, pk} = Sr25519.Vectors.triple(Sr25519.Vectors.known_answer())
  @msg msg
  @sig sig
  @pk pk

  @tasks 64
  @iters 200

  @tag rung: :L6
  @tag :benchmark
  @tag timeout: 120_000
  test "concurrent verifies from #{@tasks} processes stay correct" do
    1..@tasks
    |> Task.async_stream(
      fn task_i ->
        for i <- 1..@iters do
          case rem(task_i + i, 3) do
            # valid vector must verify true every time — no cross-call interference
            0 ->
              {:ok, true} = Sr25519.Substrate.verify_raw_message(@msg, @sig, @pk)

            # deterministic tamper must verify false every time
            1 ->
              <<first, rest::binary>> = @msg
              tampered = <<Bitwise.bxor(first, 0x01), rest::binary>>
              {:ok, false} = Sr25519.Substrate.verify_raw_message(tampered, @sig, @pk)

            # a random message under a valid sig/pk must verify false every time
            # (a spurious {:ok, true} here is exactly the cross-call corruption
            # this rung exists to catch)
            2 ->
              {:ok, false} =
                Sr25519.verify_raw(:crypto.strong_rand_bytes(64), @sig, @pk, "substrate")
          end
        end

        :ok
      end,
      max_concurrency: @tasks,
      ordered: false,
      timeout: 60_000
    )
    |> Enum.each(fn result -> assert result == {:ok, :ok} end)
  end

  @tag rung: :L6
  @tag :benchmark
  @tag timeout: 120_000
  test "sustained verification does not grow VM memory" do
    # :erlang.memory(:total) is a whole-VM measurement, so collect EVERY
    # process before each reading — a single self-GC would leave the delta
    # dominated by other processes' uncollected heaps.
    gc_all = fn ->
      Enum.each(Process.list(), &:erlang.garbage_collect/1)
    end

    gc_all.()
    before = :erlang.memory(:total)

    for _ <- 1..20_000 do
      {:ok, true} = Sr25519.Substrate.verify_raw_message(@msg, @sig, @pk)
    end

    gc_all.()
    afterwards = :erlang.memory(:total)

    # Generous bound: 20k verifies must not retain anything material. A real
    # per-call leak of even 1 KiB would add ~20 MiB and trip this.
    assert afterwards - before < 16 * 1024 * 1024,
           "VM memory grew by #{afterwards - before} bytes over 20k verifies"
  end
end
