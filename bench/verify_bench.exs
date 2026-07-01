# Human-facing verify benchmark (the hard p99 < 1 ms gate lives in the test suite).
#
#   MIX_ENV=test SR25519_FORCE_BUILD=1 mix run bench/verify_bench.exs
#
# Reads real signatures from the committed rust vector corpus and benchmarks the
# substrate-raw verify path across message sizes, including MAX_MESSAGE_BYTES.

defmodule VerifyBench do
  def vectors, do: File.read!("test/vectors/rust.json") |> Jason.decode!() |> Map.fetch!("vectors")

  def load(name) do
    Enum.find(vectors(), &(&1["message_name"] == name and &1["convention"] == "substrate_raw")) ||
      raise "no rust substrate_raw vector for #{name}"
  end

  def unhex(""), do: <<>>
  def unhex(h), do: Base.decode16!(h, case: :lower)

  def message(%{"message_repeat" => %{"hex" => hex, "count" => count}}),
    do: :binary.copy(unhex(hex), count)

  def message(%{"message_hex" => hex}), do: unhex(hex)

  def inputs(name) do
    v = load(name)
    {message(v), unhex(v["signature_hex"]), unhex(v["public_key_hex"])}
  end
end

jobs =
  for name <- ["ascii", "realistic_payload", "max_bytes"], into: %{} do
    {msg, sig, pk} = VerifyBench.inputs(name)
    label = "#{name} (#{byte_size(msg)} B)"
    {label, fn -> {:ok, true} = Sr25519.Substrate.verify_raw_message(msg, sig, pk) end}
  end

Benchee.run(jobs,
  warmup: 1,
  time: 3,
  print: [fast_warning: false],
  formatters: [{Benchee.Formatters.Console, extended_statistics: true}]
)
