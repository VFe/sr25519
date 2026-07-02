defmodule Sr25519.Conformance.L7Test do
  @moduledoc "L7 — the artifact is shippable: the Hex tarball has the right shape."
  use ExUnit.Case, async: false
  @moduletag :conformance

  @root Path.expand(Path.join([__DIR__, "..", ".."]))
  @checksum Path.join(@root, "checksum-Elixir.Sr25519.Native.exs")

  # Spawns the `mix` executable, which System.cmd cannot do on Windows (mix.bat
  # needs cmd.exe); test_helper.exs excludes :posix_build there.
  @tag rung: :L7
  @tag :posix_build
  @tag timeout: 300_000
  test "mix hex.build tarball includes the checksum file, native sources, and Cargo.lock" do
    # The real checksum is generated from published artifacts at release time; a
    # transient placeholder lets us validate the tarball SHAPE locally.
    created = not File.exists?(@checksum)
    if created, do: File.write!(@checksum, "%{}\n")
    on_exit(fn -> if created, do: File.rm(@checksum) end)

    out_dir = Path.join(System.tmp_dir!(), "sr25519_pkg_#{System.unique_integer([:positive])}")
    File.rm_rf!(out_dir)
    on_exit(fn -> File.rm_rf(out_dir) end)

    # Note: `mix hex.build` only assembles the tarball — it never compiles the
    # project, so no NIF build happens in the child (don't add one).
    {out, code} =
      System.cmd("mix", ["hex.build", "--unpack", "-o", out_dir],
        cd: @root,
        stderr_to_stdout: true,
        env: [
          {"LANG", "C.UTF-8"},
          {"LC_ALL", "C.UTF-8"},
          {"MIX_ENV", "dev"}
        ]
      )

    assert code == 0, "mix hex.build failed:\n#{out}"

    files =
      Path.join(out_dir, "**")
      |> Path.wildcard(match_dot: true)
      |> Enum.map(&Path.relative_to(&1, out_dir))

    required = [
      "checksum-Elixir.Sr25519.Native.exs",
      "native/sr25519_nif/Cargo.lock",
      "native/sr25519_nif/Cargo.toml",
      "native/sr25519_nif/src/lib.rs",
      # the musl -crt-static rustflags force-build users need for a loadable NIF
      "native/sr25519_nif/.cargo/config.toml",
      "lib/sr25519.ex",
      "NOTICE",
      "mix.exs"
    ]

    for suffix <- required do
      assert Enum.any?(files, &String.ends_with?(&1, suffix)),
             "package tarball is missing #{suffix}"
    end

    # Dev-only tooling must never ship: the `mix conformance` task would appear
    # (broken) in every consumer's `mix help`.
    refute Enum.any?(files, &String.contains?(&1, "lib/mix")),
           "package tarball must not ship lib/mix (dev-only task leaked)"

    # The files: list enumerates lib paths (to exclude lib/mix), so a future
    # module added under lib/ outside those paths would silently not ship.
    # Assert completeness dynamically: every source file under lib/ except
    # lib/mix must be in the tarball.
    expected_lib =
      Path.wildcard(Path.join(@root, "lib/**/*.ex"))
      |> Enum.map(&Path.relative_to(&1, @root))
      |> Enum.reject(&String.starts_with?(&1, "lib/mix"))

    for source <- expected_lib do
      assert source in files,
             "#{source} exists in lib/ but is missing from the tarball — " <>
               "extend the files: list in mix.exs"
    end
  end

  @tag rung: :L7
  test "the precompile target list matches the release workflow matrix" do
    workflow = File.read!(Path.join(@root, ".github/workflows/release.yml"))

    matrix_targets =
      Regex.scan(~r/^\s+-\s+\{\s*target:\s*([a-z0-9_-]+)\s*,/m, workflow)
      |> Enum.map(fn [_, t] -> t end)
      |> Enum.sort()

    assert matrix_targets == Enum.sort(Sr25519.Native.targets()),
           "release.yml matrix and Sr25519.Native targets have drifted — " <>
             "they must change together (a missing target becomes a consumer download failure)"
  end
end
