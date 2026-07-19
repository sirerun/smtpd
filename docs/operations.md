# Operations Guide

How to run and operate smtpd. For every configuration field see
[configuration.md](configuration.md).

## Running

```bash
# From a config file (recommended)
smtpd -config /etc/smtpd/config.yaml

# Built-in defaults, overriding a couple of values
smtpd -port 2525 -submission-port 5870 -debug
```

smtpd binds two listeners: the SMTP port (default 25) and the submission port (default 587).
It also starts an HTTP server for metrics, health, and profiling when `metrics.enabled` is
true.

The process runs in the foreground and shuts down gracefully on SIGINT or SIGTERM, draining
within `server.shutdown_timeout`.

## TLS

Set `security.tls_enabled: true` and provide a certificate and key:

```yaml
security:
  tls_enabled: true
  tls_cert_file: "/etc/smtpd/cert.pem"
  tls_key_file: "/etc/smtpd/key.pem"
```

With TLS enabled, smtpd advertises `STARTTLS` on the SMTP port and supports TLS on the
submission port. AUTH is only offered once the connection is secured.

## Users and authentication

Enable AUTH and point at a users file:

```yaml
auth:
  enabled: true
  users_file: "/etc/smtpd/users.json"
  auth_methods: ["PLAIN", "LOGIN"]
```

The users file is a list of username/password entries:

```json
[
  { "username": "alice@example.com", "password": "s3cret" },
  { "username": "bob@example.com",   "password": "hunter2" }
]
```

Passwords are hashed with bcrypt when the file is loaded, and only the hash is kept in
memory. Supplied credentials are compared in constant time.

> **Security note:** the users file currently stores passwords in plaintext on disk;
> restrict its permissions (`chmod 600`, owned by the smtpd user). Support for supplying
> pre-hashed credentials is tracked in [plan.md](plan.md) (epic E5). Authentication is only
> safe to offer over TLS.

## Relay control

Unauthenticated clients may deliver only to a domain listed in `server.local_domains`.
Authenticated clients may relay to any destination. Configure the domains this server is the
MX for:

```yaml
server:
  local_domains:
    - "example.com"
    - "example.org"
```

With no `local_domains` and auth disabled, the server accepts no relayable recipients.

## Observability

When `metrics.enabled` is true, the HTTP server exposes:

| Path | Purpose |
|------|---------|
| `metrics.metrics_path` (default `/metrics`) | Prometheus metrics. |
| `/health` | Liveness/readiness status. |
| `/debug/pprof/` | Go runtime profiling (`net/http/pprof`). |

Restrict access to this server (bind to a private interface or firewall it); pprof and
internal metrics should not be publicly reachable.

Logs are structured via `slog`. Use `logging.format: json` for machine ingestion and
`logging.add_source: true` to include `file:line`.

## Graceful shutdown

On SIGINT/SIGTERM, smtpd stops accepting new connections and drains in-flight work within
`server.shutdown_timeout`. Durable persistence of accepted-but-undelivered mail across
restarts is being implemented; see [plan.md](plan.md) epic E2 and
[adr/002-outbound-relay-queue-durability.md](adr/002-outbound-relay-queue-durability.md).
Until that lands, avoid hard-killing the process with mail in the queue.

## Health checks

Point your orchestrator's liveness/readiness probe at `GET /health`. Note that the current
health check reflects listener and buffer state, not end-to-end delivery health; deeper
liveness signals are tracked in [plan.md](plan.md).

## Deployment notes

- Run as a non-root user; bind privileged ports (25/587) via capabilities
  (`CAP_NET_BIND_SERVICE`) or a front-end rather than running as root.
- Provide a real `server.hostname` so the greeting and EHLO response are correct.
- Release binaries are built with GoReleaser; see [`../.goreleaser.yml`](../.goreleaser.yml).
