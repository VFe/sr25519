defmodule Sr25519.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/VFe/sr25519"

  def project do
    [
      app: :sr25519,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      description: description(),
      package: package(),
      deps: deps(),
      # :mix in the PLT because lib/mix/tasks/conformance.ex (dev-only, not
      # shipped) implements a Mix.Task. PLTs live under priv/plts (gitignored,
      # never packaged) so CI can cache them — dialyxir's default puts the
      # expensive core PLTs in ~/.mix, outside any cache.
      dialyzer: [
        plt_add_apps: [:mix],
        plt_core_path: "priv/plts/core",
        plt_local_path: "priv/plts/project"
      ],
      docs: docs(),
      name: "sr25519",
      source_url: @source_url
    ]
  end

  def application do
    # Pure library: no supervision tree, no logging, no extra OTP apps.
    []
  end

  # `mix conformance` needs the test env (ExUnit + vectors); `mix docs` and the
  # docs step of `mix hex.publish` need the :docs env where ex_doc lives.
  def cli do
    [preferred_envs: [conformance: :test, docs: :docs, "hex.publish": :docs]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    "Substrate-compatible sr25519 (schnorrkel) signature verification for the BEAM — " <>
      "a thin, safety-critical Rustler NIF over the audited w3f schnorrkel crate. " <>
      "Precompiled by default; no Rust toolchain required to use it."
  end

  defp deps do
    [
      {:rustler_precompiled, "~> 0.9"},
      # Only needed to build the NIF from source (force-build escape hatch);
      # consumers use the precompiled artifact and never compile Rust.
      {:rustler, "~> 0.38", optional: true},
      {:stream_data, "~> 1.1", only: [:test]},
      {:benchee, "~> 1.3", only: [:dev, :test]},
      {:dialyxir, "~> 1.4", only: :dev, runtime: false},
      # NOTE: no direct jason dep — the conformance report + vector loader use
      # Jason, which arrives transitively via rustler; declaring it here would
      # make it a hard runtime dep of every consumer for nothing.
      # Docs-only; isolated in its own env so `mix compile`/`mix test` never pull
      # ex_doc's leex/yecc-heavy tree. Build docs with `MIX_ENV=docs mix docs`.
      {:ex_doc, "~> 0.34", only: :docs, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT", "Apache-2.0"],
      # MANDATORY for a precompiled Hex package: the checksum file + the native
      # sources + the exact Cargo.lock (so force-build users get the identical tree).
      # lib/mix (the dev-only `mix conformance` task) deliberately does NOT ship:
      # it would inject a broken, generically-named task into every consumer app.
      files: [
        "lib/sr25519.ex",
        "lib/sr25519",
        "native/sr25519_nif/src",
        "native/sr25519_nif/Cargo.toml",
        "native/sr25519_nif/Cargo.lock",
        "native/sr25519_nif/.cargo",
        "native/sr25519_nif/Cross.toml",
        "checksum-Elixir.Sr25519.Native.exs",
        "mix.exs",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "NOTICE"
      ],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "schnorrkel (upstream)" => "https://github.com/w3f/schnorrkel"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "SECURITY.md"],
      source_ref: "v#{@version}"
    ]
  end
end
