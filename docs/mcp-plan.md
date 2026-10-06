# MCP stdio delivery plan

- [x] Inspect existing SMTP relay and queue boundaries.
- [x] Implementation worker: add stdio MCP binary and reusable tool handlers using official Go SDK; validated message construction, SMTP submission with secure defaults, honest acceptance results and tests. Own cmd/smtpd-mcp, internal/mcpserver, go.mod, go.sum.
- [x] Coordinator: document configuration, delivery boundaries and operational prerequisites in docs/mcp.md and README.
- [x] Coordinator: local tests, race, vet and binary stdio smoke test under shared build lease where required.
- [x] Independent reviewer: exact-head security/correctness review; fix findings.
- [x] Integrate locally and record evidence. No live mail or campaign activation in this task.
- [ ] Resolve repository-wide lint gate before merge; then verify landed revision.

Decision: keep MCP tool registration independent of stdio transport so an authenticated HTTP transport can be added later. Submit to an operator-configured SMTP endpoint (including this daemon) instead of creating a second in-process volatile queue per agent. An SMTP 250 response is acceptance by that endpoint, not inbox delivery. Existing smtpd's queue is in memory; campaign pacing, durable scheduling, suppression and bounce feedback remain separate work.

## Verification recorded 2026-10-05

Implementation revision: `39ce7a19b6ddecc14d51a80ef3839e3fe4a18407`.

- `go test -race -p 2 ./...`: passed all packages. Existing test setup races were repaired by assigning callbacks before starting session goroutines.
- `go vet ./...`: passed. Existing loadtest formatting now treats the message body as data, not a format string.
- `go build ./cmd/smtpd ./cmd/smtpd-mcp` (outputs to an external artifact directory): passed.
- `golangci-lint run ./internal/mcpserver/... ./cmd/smtpd-mcp/...`: zero issues.
- Current `govulncheck ./...`: zero reachable vulnerabilities and zero advisories in imported packages; 22 advisories remain in required modules that this code does not call. This is not a claim that every dependency is vulnerability-free.
- Real stdio binary: initialization, three-tool discovery, preview, disabled-send rejection, status redaction and clean EOF shutdown passed.
- Independent exact-head correctness/security review: no findings at the implementation revision above.
- `goreleaser check`: passed for the release configuration.
- An isolated local daemon startup smoke test verified TLS, authenticated submission connectivity and rejection of unauthenticated external relay at revision `05ecb8ef44b9d4eeaf316e7036b147e060391042`. No DATA command or external message was sent. Later changes only clean up MCP lint findings.

All coordinator multi-package checks used the shared build lease and machine load limit. An earlier worker lease-handling error was reported to the affected project; its test output is excluded from this evidence.

Repository-wide `golangci-lint run ./...` at `05ecb8ef44b9d4eeaf316e7036b147e060391042` reported 87 issues. The ten findings in the new MCP packages have been fixed and scoped lint passes. The remaining reported findings are outside those packages; a fresh full/baseline comparison was held because machine load exceeded the shared limit. The full lint gate remains unresolved under ADR 004, so the pull request stays draft and unmerged.

Hosted CI for [PR 7](https://github.com/sirerun/smtpd/pull/7) did not start: GitHub reported an account billing lock. Local results above are not hosted CI or production-delivery evidence. No billing settings, branch protections, live mail service or outreach campaign were changed.
