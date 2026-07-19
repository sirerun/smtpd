# smtpd

[![Go Reference](https://pkg.go.dev/badge/github.com/sirerun/smtpd.svg)](https://pkg.go.dev/github.com/sirerun/smtpd)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirerun/smtpd)](https://goreportcard.com/report/github.com/sirerun/smtpd)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A configurable, observable SMTP server written in Go. It accepts inbound mail on the
standard (25) and submission (587) ports, enforces relay control and TLS, runs message
authentication checks (SPF, DKIM, DMARC), and relays outbound mail with DKIM signing and
retry. Structured logging, Prometheus metrics, and health endpoints are built in.

smtpd runs standalone or as the inbound MTA of the Sire mail platform (alongside `spool`
for durable storage and `imapd` for retrieval).

> **Project status:** smtpd is under active hardening. Several features are wired and
> tested; a few configuration knobs (per-connection rate limiting and IP/domain filtering)
> are parsed but not yet enforced. See [Status and roadmap](#status-and-roadmap) before
> relying on it for untrusted production traffic.

## Features

- **Standard and submission ports.** Listens on SMTP (default 25) and Submission (default 587).
- **STARTTLS.** Opportunistic TLS on the SMTP port; TLS can be required on submission.
- **Authentication.** File-based users with bcrypt-hashed credentials, `AUTH PLAIN` and
  `AUTH LOGIN`.
- **Relay control.** Unauthenticated senders may only deliver to a configured local domain;
  authenticated senders may relay anywhere (standard MSA/MX behavior).
- **Message size limits.** Enforced while reading DATA, with a configurable maximum.
- **Inbound mail authentication.** SPF, DKIM, and DMARC checking as plugins.
- **Outbound delivery.** MX lookup, connection pooling, DKIM signing, and retry with backoff.
- **DNS caching.** Configurable TTL, cache size, and per-message lookup limits.
- **Observability.** Prometheus `/metrics`, a `/health` endpoint, and `net/http/pprof`.
- **Structured logging.** `slog`-based, with configurable level, format (text/JSON), and output.
- **Graceful shutdown.** Clean termination on SIGINT/SIGTERM.

## Install

Requires Go 1.22 or later.

```bash
# Install the binary
go install github.com/sirerun/smtpd/cmd/smtpd@latest

# Or build from a clone
git clone https://github.com/sirerun/smtpd.git
cd smtpd
go build ./cmd/smtpd
```

## Quick start

```bash
# Run with a config file
smtpd -config /etc/smtpd/config.yaml

# Run with flag overrides (flags override config-file values)
smtpd -config /etc/smtpd/config.yaml -port 2525 -submission-port 5870 -debug

# See all flags
smtpd -h
```

A minimal config to accept mail for a local domain over TLS with authenticated submission:

```yaml
server:
  listen_addr: "0.0.0.0"
  port: 25
  submission_port: 587
  max_message_size: 33554432   # 32 MB
  local_domains:
    - "example.com"

security:
  tls_enabled: true
  tls_cert_file: "/etc/smtpd/cert.pem"
  tls_key_file: "/etc/smtpd/key.pem"

auth:
  enabled: true
  users_file: "/etc/smtpd/users.json"
  auth_methods: ["PLAIN", "LOGIN"]

metrics:
  enabled: true
  listen_addr: "0.0.0.0:9090"
  metrics_path: "/metrics"
```

A fuller example lives at [`config/smtpd.yaml`](config/smtpd.yaml). The complete field
reference is in [`docs/configuration.md`](docs/configuration.md).

## Configuration

Configuration is loaded from a YAML file (`-config`), then command-line flags override
individual values. The `-debug` flag forces the log level to `debug`.

Top-level sections: `server`, `auth`, `security`, `logging`, `metrics`, `plugins`,
`outbound`, `dns`, `dmarc_reporting`. Every field and default is documented in
[`docs/configuration.md`](docs/configuration.md).

Common CLI flags:

| Flag | Description |
|------|-------------|
| `-config` | Path to the YAML config file |
| `-debug` | Force debug logging |
| `-listen-addr`, `-port`, `-submission-port` | Listener address and ports |
| `-max-connections`, `-max-message-size` | Connection and message limits |
| `-read-timeout`, `-write-timeout`, `-idle-timeout`, `-shutdown-timeout` | Timeouts |
| `-auth-enabled`, `-auth-users-file` | Authentication |
| `-tls-enabled`, `-tls-cert-file`, `-tls-key-file` | TLS |
| `-metrics-enabled`, `-metrics-addr`, `-metrics-path` | Metrics server |

## Observability

- **Metrics:** Prometheus exposition at the configured `metrics_path` (default `/metrics`
  on `:9090`). Connection counts, command timings, message status, and queue depth.
- **Health:** `/health` returns the server's status for liveness/readiness probes.
- **Profiling:** `net/http/pprof` is mounted under `/debug/pprof/` on the metrics server.

## Architecture

smtpd is organized as an inbound SMTP front end plus an outbound relay:

- `internal/server` -- connection handling and the SMTP session state machine.
- `internal/plugins/{spf,dkim,dmarc}` -- inbound mail authentication.
- `internal/queue`, `internal/processor` -- accepted-message queue and delivery workers.
- `pkg/outbound` -- outbound SMTP client, MX resolution, connection pool, DKIM signing.
- `internal/dns` -- caching DNS resolver.
- `internal/{config,auth,security,metrics,health,logging}` -- supporting subsystems.

As part of the Sire mail platform, inbound mail for local mailboxes is intended to be stored
durably in the `spool` service and read back by `imapd`; see
[`docs/adr/001-durable-inbound-persistence-via-spool.md`](docs/adr/001-durable-inbound-persistence-via-spool.md).

## Documentation

- [`docs/configuration.md`](docs/configuration.md) -- full configuration reference.
- [`docs/operations.md`](docs/operations.md) -- running, TLS, users, observability, shutdown.
- [`docs/plan.md`](docs/plan.md) -- remediation and hardening plan.
- [`docs/roadmap.md`](docs/roadmap.md) -- what is planned, in progress, and done.
- [`docs/adr/`](docs/adr/) -- architecture decision records.

## Status and roadmap

smtpd is being hardened for production per [`docs/plan.md`](docs/plan.md). Notable items
that are configuration-visible but **not yet enforced**, so do not rely on them today:

- Per-connection rate limiting and IP/domain allow/block lists (`security.rate_limit`,
  `allowed_ips`, `blocked_ips`, `allowed_domains`, `blocked_domains`) are parsed but not
  yet wired into the accept path.
- Durable persistence of accepted mail is in progress; the current queue is in-memory.

Track progress in [`docs/roadmap.md`](docs/roadmap.md).

## Development

```bash
go test ./...          # run the suite
go test ./... -race    # run with the race detector (recommended)
go vet ./...
```

Contributions are welcome. Please open an issue to discuss substantial changes first, keep
commits small and focused, and ensure `go test ./... -race` and `go vet ./...` pass.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Support

Report bugs and request features via [GitHub Issues](https://github.com/sirerun/smtpd/issues).
