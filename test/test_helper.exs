# The p99 benchmark is heavy; it runs under `mix conformance` (which includes it)
# and CI, but is excluded from a plain `mix test` for a fast inner loop.
ExUnit.start(exclude: [:benchmark])
