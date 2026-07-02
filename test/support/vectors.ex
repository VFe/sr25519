defmodule Sr25519.Vectors do
  @moduledoc """
  Loads the frozen vector corpus (`test/vectors/*.json`) and dispatches each
  record through the real public API. One place decides which named function a
  `(convention, wrapping)` maps to, so the rung tests stay declarative.
  """

  @vectors_dir Path.expand(Path.join([__DIR__, "..", "vectors"]))
  @spec_path Path.expand(Path.join([__DIR__, "..", "..", "vectors/corpus_spec.json"]))

  @doc "All vector records across every oracle file."
  def all do
    @vectors_dir
    |> Path.join("*.json")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.flat_map(fn file ->
      %{"vectors" => vectors} = file |> File.read!() |> Jason.decode!()
      vectors
    end)
  end

  @doc "Vector records produced by a given oracle tool (\"scure\", \"substrate_interface\", \"rust\")."
  def by_tool(tool), do: all() |> Enum.filter(&(&1["tool"] == tool))

  @doc "The shared corpus spec (seeds, messages, conventions, MAX_MESSAGE_BYTES)."
  def spec, do: @spec_path |> File.read!() |> Jason.decode!()

  @doc "All frozen known-answer anchors (generated deterministic + lifted published tuples)."
  def known_answers do
    case Enum.filter(all(), &(&1["known_answer"] == true)) do
      [] -> raise "no known-answer vectors present in corpus"
      anchors -> anchors
    end
  end

  @doc """
  The primary known-answer anchor: the deterministic @scure-generated vector over
  the shared corpus seed (stable choice — several tests tamper with it byte-wise).
  """
  def known_answer do
    Enum.find(known_answers(), &(&1["seed_name"] == "seed_ones")) ||
      raise "no seed_ones known-answer anchor present in corpus"
  end

  @doc """
  Run a vector through the public API exactly as a caller would, returning the
  actual `{:ok, boolean} | {:error, atom}` result.
  """
  def run(v) do
    msg = message(v)
    sig = unhex(v["signature_hex"])
    pk = unhex(v["public_key_hex"])
    ctx = unhex(v["context_hex"])

    case v["convention"] do
      "substrate_raw" -> Sr25519.Substrate.verify_raw_message(msg, sig, pk)
      "bytes_xml" -> Sr25519.Substrate.verify_wrapped_bytes(msg, sig, pk)
      "raw_context" -> Sr25519.verify_raw(msg, sig, pk, ctx)
      other -> raise "unknown convention #{inspect(other)} in vector #{v["name"]}"
    end
  end

  @doc """
  The decoded `{message, signature, public_key}` triple of a vector record —
  the one place record-shape knowledge (compact `message_repeat`, hex casing)
  lives, so tests never hand-decode fields.
  """
  def triple(v) do
    {message(v), unhex(v["signature_hex"]), unhex(v["public_key_hex"])}
  end

  @doc """
  The message bytes for a vector: a bulky repeated message is stored compactly as
  `message_repeat: %{"hex" => byte, "count" => n}` and expanded here; otherwise
  `message_hex` is decoded.
  """
  def message(%{"message_repeat" => %{"hex" => hex, "count" => count}}) do
    :binary.copy(unhex(hex), count)
  end

  def message(%{"message_hex" => hex}), do: unhex(hex)

  @doc "Decode lowercase hex (as emitted by the generators). Empty string → empty binary."
  def unhex(""), do: <<>>
  def unhex(hex), do: Base.decode16!(hex, case: :lower)
end
