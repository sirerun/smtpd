# ADR 004: CI runs the race detector, linter, and vulnerability scanner

## Status
Accepted

## Date
2026-07-19

## Context
Finding H11: CI (`.github/workflows/ci.yml`) runs `go test ./... -short -cover` with no
`-race`, no linter, and no `govulncheck`. The queue concurrency defects (H7 close-panic, H8
deadlock, H9 spin, M14 metric race, ratelimit L3 race) are exactly what the race detector
surfaces, and they currently ship green. The repo's own CLAUDE.md pre-wave preflight expects
green race-enabled tests as the definition of done.

## Decision
The CI test job runs `go test ./... -race` (a non-`-short` race pass; keep the fast `-short`
job too if wall-clock matters). Add two gates:
- `golangci-lint run` (with `govet`, `staticcheck` including SA1029 for string context keys).
- `govulncheck ./...`.
All three must pass for the build to be green. The `-race` job is required on pull requests to
`main`.

## Consequences
Positive: the class of concurrency and shutdown bugs in this remediation cannot regress
silently; lint enforces the context-key and shadowing cleanups; dependency CVEs surface
automatically.
Negative: CI wall-clock increases (race instrumentation is slower); `golangci-lint` may flag
pre-existing issues that must be fixed or explicitly excluded before the gate can be made
required.
