defmodule Sr25519.DoctestTest do
  # The @doc examples are part of the verification contract on a crypto library;
  # they must be executed, not trusted as prose.
  use ExUnit.Case, async: true

  doctest Sr25519
  doctest Sr25519.Substrate
end
