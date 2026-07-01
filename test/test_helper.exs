# The suite decides for itself what can run in this environment, so a plain
# `mix test` works out of the box everywhere (CI passes no per-OS flags):
#
#   * :benchmark      — the p99 latency gate; heavy, so excluded from the fast
#                       inner loop. `mix conformance` re-includes it.
#   * :posix_build    — tests that spawn POSIX-style executables (`mix`, a
#                       .so/.dylib artifact layout); excluded on Windows.
#   * :requires_cargo — tests that build the Rust crate; excluded when no Rust
#                       toolchain is installed (the package itself needs none).
exclude =
  [:benchmark] ++
    if(match?({:win32, _}, :os.type()), do: [:posix_build], else: []) ++
    if(System.find_executable("cargo"), do: [], else: [:requires_cargo])

ExUnit.start(exclude: exclude)
