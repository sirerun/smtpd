# Mailtive SMTPd

[![Go Reference](https://pkg.go.dev/badge/github.com/mailtive/smtpd.svg)](https://pkg.go.dev/github.com/mailtive/smtpd)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<!-- Add badges for Build Status, Code Coverage, Go Report Card etc. once CI/CD is set up -->

**Mailtive SMTPd is a modern, configurable, and observable SMTP server written in Go, designed for reliability, performance, and ease of use.**

Whether you need a simple mail relay, a server for development testing, or a foundation for a more complex email infrastructure, Mailtive SMTPd provides the essential features with a focus on modern practices.

## Key Features

*   **Standard & Submission Ports:** Listens on standard SMTP (default 25) and Submission (default 587) ports.
*   **Configuration Flexibility:** Configure via a clear YAML file (`config.yaml`) or override settings with command-line flags.
*   **TLS Security:** Secure connections using STARTTLS with configurable certificate and key files.
*   **Authentication:** Basic file-based authentication support (PLAIN/LOGIN). *(Currently placeholder, requires implementation)*
*   **Structured Logging:** Powerful logging built on `slog` with configurable levels (Debug, Info, Warn, Error), formats (Text, JSON), and outputs (stdout, stderr, file). Logs include useful context like service name and environment.
*   **Observability:**
    *   **Prometheus Metrics:** Exposes key operational metrics via a `/metrics` endpoint (configurable).
    *   **Health Checks:** Simple `/health` endpoint for monitoring server status.
    *   **Profiling:** Includes `net/http/pprof` endpoint (`/debug/pprof/`) for performance diagnostics.
*   **Rate Limiting:** Basic connection rate limiting per minute. *(Currently placeholder, requires implementation)*
*   **Extensibility:** Designed with a plugin system in mind to easily add custom functionality. *(Currently placeholder, requires implementation)*
*   **Robustness:** Graceful shutdown handling ensures connections are terminated cleanly on signal events (SIGINT, SIGTERM).

## Getting Started

### Prerequisites

*   **Go:** Version 1.21 or later.

### Installation

**From Source:**

```bash
go install github.com/mailtive/smtpd/cmd/smtpd@latest
```

This will install the `smtpd` binary in your `$GOPATH/bin` directory.

**(Optional) Build from Clone:**

```bash
git clone https://github.com/mailtive/smtpd.git
cd smtpd
go build ./cmd/smtpd
```

### Configuration

Mailtive SMTPd uses a `config.yaml` file for configuration by default. You can specify a different path using the `-config` flag. Command-line flags can override any setting in the config file.

**Example `config.yaml`:**

```yaml
# config.yaml
server:
  listen_addr: "0.0.0.0"
  port: 2525            # Use a non-standard port for testing
  submission_port: 5870 # Use a non-standard port for testing
  max_connections: 100
  max_message_size: 10485760 # 10MB
  read_timeout: 60s
  write_timeout: 60s
  idle_timeout: 300s
  shutdown_timeout: 30s

logging:
  level: "info"         # "debug", "info", "warn", "error"
  format: "text"        # "text" or "json"
  output: "stderr"      # "stdout", "stderr", or "/path/to/logfile.log"
  add_source: true      # Include file:line in logs

security:
  tls_enabled: false    # Set to true to enable TLS
  # tls_cert_file: /path/to/cert.pem # Required if tls_enabled is true
  # tls_key_file: /path/to/key.pem   # Required if tls_enabled is true
  # rate_limit: 100     # Max connections per source IP per minute (Placeholder)

auth:
  enabled: false        # Set to true to enable authentication
  # users_file: /path/to/users.db  # Path to auth database (Placeholder)

metrics:
  enabled: true
  listen_addr: ":9090"
  metrics_path: "/metrics"

# plugins:             # Placeholder for plugin configuration
#   spam_filter:
#     enabled: true
#     threshold: 5.0
```

### Running the Server

1.  **Create a configuration file** (e.g., `config.yaml`) based on the example above. Adjust paths and settings as needed.
2.  **Run the binary:**

    ```bash
    # Using default config.yaml in the current directory
    smtpd

    # Specifying a config file path
    smtpd -config /etc/smtpd/config.yaml

    # Overriding config file settings with flags
    smtpd -config /etc/smtpd/config.yaml -port 25 -debug
    ```

    Use `smtpd -h` to see all available command-line flags and their defaults.

## Configuration Details

*(This section can be expanded with detailed explanations for each configuration parameter)*

### Command-Line Flags vs. Config File

*   The server first loads the configuration file specified by `-config` (or attempts to load `config.yaml` if the flag is not provided).
*   Then, it parses command-line flags. Any flag provided will **override** the corresponding value loaded from the configuration file.
*   The `-debug` flag specifically overrides the logging level to "debug".

## Contributing

Contributions are welcome! Please refer to the `CONTRIBUTING.md` file (to be created) for guidelines on reporting issues, submitting pull requests, and code style.

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

## Support

Please report bugs or request features using the [GitHub Issues](https://github.com/mailtive/smtpd/issues) tracker. 