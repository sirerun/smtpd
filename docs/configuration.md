# Configuration Reference

smtpd loads a YAML config file (via `-config`), applies defaults for any omitted field, then
lets command-line flags override individual values. If `-config` is not given, built-in
defaults are used. `-debug` forces `logging.level` to `debug`.

A working example is in [`../config/smtpd.yaml`](../config/smtpd.yaml).

> Fields marked **not yet enforced** are parsed and validated but not yet acted on. See
> [roadmap.md](roadmap.md). Do not depend on them for security today.

## server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | `0.0.0.0` | Address the SMTP and submission listeners bind to. |
| `port` | int | `25` | Standard SMTP port. |
| `submission_port` | int | `587` | Submission port (authenticated clients). |
| `max_connections` | int | `1000` | Maximum concurrent connections. |
| `read_buffer_size` | int | `16384` | Per-connection read buffer (bytes). |
| `write_buffer_size` | int | `16384` | Per-connection write buffer (bytes). |
| `read_timeout` | duration | `5m` | Per-command read deadline. |
| `write_timeout` | duration | `5m` | Write deadline. |
| `idle_timeout` | duration | `10m` | Idle connection timeout. |
| `shutdown_timeout` | duration | `30s` | Grace period for graceful shutdown. |
| `max_message_size` | int64 | `33554432` (32 MB) | Maximum accepted message size, enforced while reading DATA. |
| `worker_pool_size` | int | `4` | Outbound delivery worker count. |
| `connection_backlog` | int | `128` | Listener accept backlog. |
| `local_domains` | []string | `[]` | Domains this server accepts unauthenticated mail for. Unauthenticated senders may only deliver to these; authenticated senders may relay anywhere. |
| `hostname` | string | `""` | Hostname used in the SMTP greeting and EHLO response. |

## auth

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable SMTP AUTH. |
| `users_file` | string | `users.json` | Path to the users file (bcrypt-hashed credentials). |
| `auth_methods` | []string | `["PLAIN", "LOGIN"]` | Advertised/accepted SASL mechanisms. |

See [operations.md](operations.md#users-and-authentication) for the users-file format.

## security

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls_enabled` | bool | `false` | Enable TLS (required for STARTTLS and for AUTH over the wire). |
| `tls_cert_file` | string | `""` | PEM certificate path (required when `tls_enabled`). |
| `tls_key_file` | string | `""` | PEM private key path (required when `tls_enabled`). |
| `rate_limit` | int | `100` | Intended per-source connection rate per minute. **Not yet enforced.** |
| `allowed_ips` | []string (CIDR) | `[]` | Allow-list. **Not yet enforced.** |
| `blocked_ips` | []string (CIDR) | `[]` | Block-list. **Not yet enforced.** |
| `allowed_domains` | []string | `[]` | Sender-domain allow-list. **Not yet enforced.** |
| `blocked_domains` | []string | `[]` | Sender-domain block-list. **Not yet enforced.** |

## logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `info` | `debug`, `info`, `warn`, or `error`. |
| `format` | string | `text` | `text` or `json`. |
| `output` | string | `stdout` | `stdout`, `stderr`, or a file path. |
| `add_source` | bool | `false` | Include `file:line` in log records. |

## metrics

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Serve the metrics/health/pprof HTTP server. |
| `listen_addr` | string | `0.0.0.0:9090` | Metrics server bind address. |
| `metrics_path` | string | `/metrics` | Prometheus exposition path. |

## plugins

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the plugin subsystem. |
| `paths` | []string | `[]` | Plugin search paths. |

## outbound

Outbound relay client settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `smtp_client.connect_timeout` | duration | `10s` | Dial timeout to a remote MX. |
| `smtp_client.max_connections` | int | `100` | Outbound connection pool size. |
| `smtp_client.idle_timeout` | duration | `5m` | Pooled-connection idle timeout. |
| `dkim` | map[domain]DKIMConfig | `{}` | Per-domain DKIM signing config. |

Each `dkim` entry:

| Field | Type | Description |
|-------|------|-------------|
| `selector` | string | DKIM selector (the `s=` tag). |
| `private_key_path` | string | Path to the signing key (RSA). |

## dns

| Field | Type | Description |
|-------|------|-------------|
| `cache_ttl` | duration | How long resolved records are cached. |
| `max_lookups_per_msg` | int | Cap on DNS lookups per message (SPF/DMARC evaluation). |
| `max_cache_size` | int | Maximum cached entries. |

## dmarc_reporting

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable DMARC aggregate report generation. |
| `report_interval` | duration | Aggregation interval. |
| `storage_path` | string | Where reports are written. |

## Command-line flags

Flags override the corresponding config value. Run `smtpd -h` for the authoritative list.
Commonly used: `-config`, `-debug`, `-listen-addr`, `-port`, `-submission-port`,
`-max-connections`, `-max-message-size`, `-read-timeout`, `-write-timeout`, `-idle-timeout`,
`-shutdown-timeout`, `-auth-enabled`, `-auth-users-file`, `-tls-enabled`, `-tls-cert-file`,
`-tls-key-file`, `-metrics-enabled`, `-metrics-addr`, `-metrics-path`.
