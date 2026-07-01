defmodule Sr25519.Native do
  @moduledoc false
  # The Rustler NIF surface. Precompiled by default; set SR25519_FORCE_BUILD=1
  # (with a Rust toolchain) to compile from source. Never call these directly —
  # go through `Sr25519` / `Sr25519.Substrate`, which own the validation contract.

  version = Mix.Project.config()[:version]
  source_url = Mix.Project.config()[:source_url]

  # The target list is pinned EXPLICITLY (not left to RustlerPrecompiled's
  # defaults) so a rustler_precompiled upgrade can never make consumers expect
  # artifacts the release workflow doesn't build. This list, `nif_versions`,
  # and the matrix in .github/workflows/release.yml must change together.
  @targets ~w(
    aarch64-apple-darwin
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    arm-unknown-linux-gnueabihf
    riscv64gc-unknown-linux-gnu
    x86_64-apple-darwin
    x86_64-pc-windows-gnu
    x86_64-pc-windows-msvc
    x86_64-unknown-linux-gnu
    x86_64-unknown-linux-musl
  )

  use RustlerPrecompiled,
    otp_app: :sr25519,
    crate: "sr25519_nif",
    base_url: "#{source_url}/releases/download/v#{version}",
    force_build: System.get_env("SR25519_FORCE_BUILD") in ["1", "true"],
    version: version,
    targets: @targets,
    nif_versions: ["2.15"]

  # Fallback bodies; replaced by the loaded NIF. If loading failed you get a
  # clear `:nif_not_loaded` rather than a silent wrong answer.
  @spec verify_raw(binary, binary, binary, binary) ::
          {:ok, boolean} | {:error, atom}
  def verify_raw(_message, _signature, _public_key, _context),
    do: :erlang.nif_error(:nif_not_loaded)
end
