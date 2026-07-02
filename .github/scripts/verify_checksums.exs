# Verifies that the committed rustler_precompiled checksum file exactly matches
# the artifacts attached to the GitHub release: the same file set (checked in
# both directions) and the same SHA-256 for every artifact. Run by
# release-verify.yml with the directory `gh release download` populated:
#
#     elixir .github/scripts/verify_checksums.exs assets
#
# The checksum file format is rustler_precompiled's:
#     %{"<artifact basename>" => "sha256:<lowercase hex>"}
[assets_dir] = System.argv()

checksum_file = "checksum-Elixir.Sr25519.Native.exs"
{checksums, _} = Code.eval_file(checksum_file)

assets = assets_dir |> Path.join("*") |> Path.wildcard()

if assets == [] do
  IO.puts("ERROR: no downloaded release assets found in #{assets_dir}/")
  System.halt(1)
end

asset_names = MapSet.new(assets, &Path.basename/1)
checksum_names = MapSet.new(Map.keys(checksums))

only_release = Enum.sort(MapSet.difference(asset_names, checksum_names))
only_checksums = Enum.sort(MapSet.difference(checksum_names, asset_names))

unless only_release == [] and only_checksums == [] do
  IO.puts("ERROR: the release asset set and the committed checksum file disagree")
  IO.puts("  only on the release:       #{inspect(only_release)}")
  IO.puts("  only in the checksum file: #{inspect(only_checksums)}")
  System.halt(1)
end

for path <- assets do
  got = "sha256:" <> Base.encode16(:crypto.hash(:sha256, File.read!(path)), case: :lower)
  want = Map.fetch!(checksums, Path.basename(path))

  if got != want do
    IO.puts("ERROR: checksum mismatch for #{Path.basename(path)}")
    IO.puts("  committed: #{want}")
    IO.puts("  actual:    #{got}")
    System.halt(1)
  end
end

IO.puts("OK: #{length(assets)} release artifacts match the committed checksums exactly")
