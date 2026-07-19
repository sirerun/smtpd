# smtpd Documentation

- [configuration.md](configuration.md) -- full configuration field reference and CLI flags.
- [operations.md](operations.md) -- running the server, TLS, users, relay control,
  observability, and shutdown.
- [plan.md](plan.md) -- the remediation and hardening plan (epics, tasks, milestones).
- [roadmap.md](roadmap.md) -- planned / in progress / done.
- [adr/](adr/) -- architecture decision records:
  - [001](adr/001-durable-inbound-persistence-via-spool.md) -- durable inbound persistence via the spool service.
  - [002](adr/002-outbound-relay-queue-durability.md) -- outbound relay queue durability and per-recipient state.
  - [003](adr/003-mail-authentication-advisory-to-dmarc.md) -- SPF/DKIM advisory, DMARC decides.
  - [004](adr/004-ci-race-lint-vuln-gates.md) -- CI runs race detector, linter, and vuln scanner.

For an overview and quick start, see the top-level [README](../README.md).
