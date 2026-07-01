defmodule Sr25519.ConformanceFormatter do
  @moduledoc """
  An ExUnit formatter that aggregates results by the `:rung` tag and writes a
  machine-readable `conformance_report.json` (per-rung pass/fail + the names of
  failing tests/vectors). This is the deterministic pass/fail signal the build
  loop parses — no human judgement in the loop.
  """
  use GenServer

  @report_path "conformance_report.json"

  @impl true
  def init(_opts), do: {:ok, %{rungs: %{}}}

  @impl true
  def handle_cast({:test_finished, %ExUnit.Test{} = test}, config) do
    case test.tags[:rung] do
      nil ->
        {:noreply, config}

      rung ->
        outcome = outcome(test.state)

        rungs =
          Map.update(
            config.rungs,
            to_string(rung),
            init_agg() |> bump(outcome, test),
            &bump(&1, outcome, test)
          )

        {:noreply, %{config | rungs: rungs}}
    end
  end

  def handle_cast({:suite_finished, _times_us}, config), do: write(config)
  def handle_cast(_event, config), do: {:noreply, config}

  defp init_agg, do: %{passed: 0, failed: 0, skipped: 0, failing: []}

  defp bump(agg, outcome, test) do
    agg = Map.update!(agg, outcome, &(&1 + 1))

    if outcome == :failed do
      %{agg | failing: [full_name(test) | agg.failing]}
    else
      agg
    end
  end

  defp outcome(nil), do: :passed
  defp outcome({:failed, _}), do: :failed
  defp outcome({:invalid, _}), do: :failed
  defp outcome({:excluded, _}), do: :skipped
  defp outcome({:skipped, _}), do: :skipped

  defp full_name(test), do: "#{inspect(test.module)}.#{test.name}"

  defp write(config) do
    rungs =
      Map.new(config.rungs, fn {rung, agg} ->
        status =
          cond do
            agg.failed > 0 -> "fail"
            agg.passed > 0 -> "pass"
            true -> "skip"
          end

        {rung,
         %{
           status: status,
           passed: agg.passed,
           failed: agg.failed,
           skipped: agg.skipped,
           failing: Enum.reverse(agg.failing)
         }}
      end)

    overall = if Enum.any?(rungs, fn {_, r} -> r.status == "fail" end), do: "fail", else: "pass"
    report = %{overall: overall, rungs: rungs}
    File.write!(@report_path, Jason.encode!(report) <> "\n")

    IO.puts("\n=== sr25519 conformance ladder ===")

    for {rung, r} <- Enum.sort_by(rungs, fn {k, _} -> k end) do
      IO.puts(
        "  #{rung}: #{String.upcase(r.status)}  " <>
          "(#{r.passed} passed, #{r.failed} failed, #{r.skipped} skipped)"
      )
    end

    IO.puts("  OVERALL: #{String.upcase(overall)}  ->  #{@report_path}\n")
    {:noreply, config}
  end
end
