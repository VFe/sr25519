defmodule Sr25519.DocsConsistencyTest do
  @moduledoc """
  L7 — user-facing docs must not drift from the frozen corpus: the README
  quickstart inlines the known-answer hex, so a corpus regeneration that
  changes the anchor must fail here rather than silently shipping a README
  whose first snippet returns `{:ok, false}` for every new user.
  """
  use ExUnit.Case, async: true
  @moduletag :conformance

  @readme File.read!(Path.expand(Path.join([__DIR__, "..", "README.md"])))

  @tag rung: :L7
  test "the README quickstart hex matches the frozen known-answer anchor" do
    anchor = Sr25519.Vectors.known_answer()
    {msg, _sig, _pk} = Sr25519.Vectors.triple(anchor)

    # message appears verbatim as an Elixir string literal
    assert @readme =~ ~s(msg = "#{msg}")

    # signature and public key hex appear (the signature is split across two
    # concatenated string literals in the README, so compare with quotes and
    # whitespace stripped)
    flat = String.replace(@readme, ~r/["\s<>]|\\n/, "")
    assert flat =~ anchor["signature_hex"]
    assert flat =~ anchor["public_key_hex"]
  end
end
