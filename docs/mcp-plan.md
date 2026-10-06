# MCP stdio delivery plan

- [x] Inspect existing SMTP relay and queue boundaries.
- [ ] Implementation worker: add stdio MCP binary and reusable tool handlers using official Go SDK; validated message construction, SMTP submission with secure defaults, honest acceptance results and tests. Own cmd/smtpd-mcp, internal/mcpserver, go.mod, go.sum.
- [ ] Coordinator: document configuration, delivery boundaries and operational prerequisites in docs/mcp.md and README.
- [ ] Coordinator: local tests, race, vet and binary stdio smoke test under shared build lease.
- [ ] Independent reviewer: exact-head security/correctness review; fix findings.
- [ ] Integrate locally and record evidence. No live mail or campaign activation in this task.

Decision: keep MCP tool registration independent of stdio transport so an authenticated HTTP transport can be added later. Submit to an operator-configured SMTP endpoint (including this daemon) instead of creating a second in-process volatile queue per agent. An SMTP 250 response is acceptance by that endpoint, not inbox delivery. Existing smtpd's queue is in memory; campaign pacing, durable scheduling, suppression and bounce feedback remain separate work.
