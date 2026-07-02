# Human-facing verify benchmark (the hard p99 < 1 ms gate lives in the test suite).
#
#   MIX_ENV=test SR25519_FORCE_BUILD=1 mix run bench/verify_bench.exs
#
# Runs in the test env so it reuses the canonical corpus loader
# (Sr25519.Vectors) — no private copy to drift. Benchmarks the substrate-raw
# verify path across message sizes, including max_message_bytes.

jobs =
  for name <- ["ascii", "realistic_payload", "max_bytes"], into: %{} do
    v =
      Sr25519.Vectors.by_tool("rust")
      |> Enum.find(&(&1["message_name"] == name and &1["convention"] == "substrate_raw")) ||
        raise "no rust substrate_raw vector for #{name}"

    {msg, sig, pk} = Sr25519.Vectors.triple(v)

    label = "#{name} (#{byte_size(msg)} B)"
    {label, fn -> {:ok, true} = Sr25519.Substrate.verify_raw_message(msg, sig, pk) end}
  end

Benchee.run(jobs,
  warmup: 1,
  time: 3,
  print: [fast_warning: false],
  formatters: [{Benchee.Formatters.Console, extended_statistics: true}]
)
