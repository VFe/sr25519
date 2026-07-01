defmodule Sr25519.Native do
  @moduledoc false
  # The Rustler NIF surface. Precompiled by default; set SR25519_FORCE_BUILD=1
  # (with a Rust toolchain) to compile from source. Never call these directly —
  # go through `Sr25519` / `Sr25519.Substrate`, which own the validation contract.

  version = Mix.Project.config()[:version]
  source_url = Mix.Project.config()[:source_url]

  use RustlerPrecompiled,
    otp_app: :sr25519,
    crate: "sr25519_nif",
    base_url: "#{source_url}/releases/download/v#{version}",
    force_build: System.get_env("SR25519_FORCE_BUILD") in ["1", "true"],
    version: version,
    nif_versions: ["2.15"]

  # Fallback bodies; replaced by the loaded NIF. If loading failed you get a
  # clear `:nif_not_loaded` rather than a silent wrong answer.
  @spec verify_raw(binary, binary, binary, binary) ::
          {:ok, boolean} | {:error, atom}
  def verify_raw(_message, _signature, _public_key, _context),
    do: :erlang.nif_error(:nif_not_loaded)
end
