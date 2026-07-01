defmodule Mix.Tasks.Conformance do
  @shortdoc "Run the sr25519 conformance ladder (L0–L7) + property & safety suites; emit a JSON report"
  @moduledoc """
  Runs the full conformance ladder as a single command and emits a
  machine-readable `conformance_report.json` (per-rung pass/fail + failing test
  names), plus a human summary. Exits non-zero if any rung fails.

      mix conformance            # full ladder incl. the p99 benchmark
      mix conformance --seed 0   # extra args are forwarded to `mix test`

  This task is development tooling for this repository only — it is deliberately
  excluded from the Hex package. The rungs:

    * L0 build & load        * L4 Substrate convention
    * L1 crate conformance   * L5 independent oracle (@scure) + cross-oracle agreement
    * L2 known-answer        * L6 NIF safety (panic-survives, fuzz, p99 < 1 ms)
    * L3 error taxonomy      * L7 packaging (checksum + Cargo.lock in the tarball)
  """
  use Mix.Task

  @impl true
  def run(args) do
    Mix.Task.run("test", [
      "--include",
      "benchmark",
      "--formatter",
      "Sr25519.ConformanceFormatter",
      "--formatter",
      "ExUnit.CLIFormatter"
      | args
    ])
  end
end
