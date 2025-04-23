package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mailtive/smtpd/internal/auth"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/pkg/plugin"
)

// Config represents the server configuration
type Config struct {
	Server   ServerConfig   `json:"server" yaml:"server"`
	Auth     AuthConfig     `json:"auth" yaml:"auth"`
	Logging  LoggingConfig  `json:"logging" yaml:"logging"`
	Metrics  MetricsConfig  `json:"metrics" yaml:"metrics"`
	Plugins  PluginsConfig  `json:"plugins" yaml:"plugins"`
	Security SecurityConfig `json:"security" yaml:"security"`
	Outbound OutboundConfig `json:"outbound" yaml:"outbound"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	ListenAddr        string        `json:"listen_addr" yaml:"listen_addr"`
	Port              int           `json:"port" yaml:"port"`
	SubmissionPort    int           `json:"submission_port" yaml:"submission_port"`
	MaxConnections    int           `json:"max_connections" yaml:"max_connections"`
	ReadBufferSize    int           `json:"read_buffer_size" yaml:"read_buffer_size"`
	WriteBufferSize   int           `json:"write_buffer_size" yaml:"write_buffer_size"`
	ReadTimeout       time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	ShutdownTimeout   time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout"`
	MaxMessageSize    int64         `json:"max_message_size" yaml:"max_message_size"`
	WorkerPoolSize    int           `json:"worker_pool_size" yaml:"worker_pool_size"`
	ConnectionBacklog int           `json:"connection_backlog" yaml:"connection_backlog"`
	LocalDomains      []string      `json:"local_domains" yaml:"local_domains"`
	Hostname          string        `json:"hostname" yaml:"hostname"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	UsersFile   string   `json:"users_file" yaml:"users_file"`
	AuthMethods []string `json:"auth_methods" yaml:"auth_methods"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level     string `json:"level" yaml:"level"`
	Format    string `json:"format" yaml:"format"`
	Output    string `json:"output" yaml:"output"`
	AddSource bool   `json:"add_source" yaml:"add_source"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled     bool   `json:"enabled" yaml:"enabled"`
	ListenAddr  string `json:"listen_addr" yaml:"listen_addr"`
	MetricsPath string `json:"metrics_path" yaml:"metrics_path"`
}

// PluginsConfig holds plugin configuration
type PluginsConfig struct {
	Enabled bool     `json:"enabled" yaml:"enabled"`
	Paths   []string `json:"paths" yaml:"paths"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	TLSEnabled     bool     `json:"tls_enabled" yaml:"tls_enabled"`
	TLSCertFile    string   `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile     string   `json:"tls_key_file" yaml:"tls_key_file"`
	RateLimit      int      `json:"rate_limit" yaml:"rate_limit"`
	AllowedIPs     []string `json:"allowed_ips" yaml:"allowed_ips"`
	BlockedIPs     []string `json:"blocked_ips" yaml:"blocked_ips"`
	AllowedDomains []string `json:"allowed_domains" yaml:"allowed_domains"`
	BlockedDomains []string `json:"blocked_domains" yaml:"blocked_domains"`
}

// OutboundConfig holds configuration for outbound mail delivery
type OutboundConfig struct {
	SMTPClient SMTPClientConfig      `json:"smtp_client" yaml:"smtp_client"`
	DKIM       map[string]DKIMConfig `json:"dkim" yaml:"dkim"`
}

// SMTPClientConfig holds configuration for outbound SMTP client connections
type SMTPClientConfig struct {
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout"`
	MaxConnections int           `json:"max_connections" yaml:"max_connections"`
	IdleTimeout    time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
}

// DKIMConfig holds configuration for DKIM signing
type DKIMConfig struct {
	Selector       string `json:"selector" yaml:"selector"`
	PrivateKeyPath string `json:"private_key_path" yaml:"private_key_path"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:        "0.0.0.0",
			Port:              25,
			SubmissionPort:    587,
			MaxConnections:    1000,
			ReadBufferSize:    16 * 1024,
			WriteBufferSize:   16 * 1024,
			ReadTimeout:       5 * time.Minute,
			WriteTimeout:      5 * time.Minute,
			IdleTimeout:       10 * time.Minute,
			ShutdownTimeout:   30 * time.Second,
			MaxMessageSize:    32 * 1024 * 1024,
			WorkerPoolSize:    4,
			ConnectionBacklog: 128,
			LocalDomains:      []string{},
			Hostname:          "",
		},
		Auth: AuthConfig{
			Enabled:     false,
			UsersFile:   "users.json",
			AuthMethods: []string{"PLAIN", "LOGIN"},
		},
		Logging: LoggingConfig{
			Level:     "info",
			Format:    "text",
			Output:    "stdout",
			AddSource: false,
		},
		Metrics: MetricsConfig{
			Enabled:     true,
			ListenAddr:  "0.0.0.0:9090",
			MetricsPath: "/metrics",
		},
		Plugins: PluginsConfig{
			Enabled: false,
			Paths:   []string{},
		},
		Security: SecurityConfig{
			TLSEnabled:     false,
			TLSCertFile:    "",
			TLSKeyFile:     "",
			RateLimit:      100,
			AllowedIPs:     []string{},
			BlockedIPs:     []string{},
			AllowedDomains: []string{},
			BlockedDomains: []string{},
		},
		Outbound: OutboundConfig{
			SMTPClient: SMTPClientConfig{
				ConnectTimeout: 10 * time.Second,
				MaxConnections: 100,
				IdleTimeout:    5 * time.Minute,
			},
			DKIM: map[string]DKIMConfig{},
		},
	}
}

// LoadConfig loads the configuration from a file.
func LoadConfig(configFile string) (*Config, error) {
	if configFile == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Start with defaults
	config := DefaultConfig()

	// Unmarshal YAML data into the existing config struct (overwriting defaults)
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file '%s': %w", configFile, err)
	}

	return config, nil
}

// ValidateConfig validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Server.Port)
	}

	if c.Server.SubmissionPort < 1 || c.Server.SubmissionPort > 65535 {
		return fmt.Errorf("invalid submission port number: %d", c.Server.SubmissionPort)
	}

	if c.Security.TLSEnabled {
		if c.Security.TLSCertFile == "" || c.Security.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but certificate or key file not specified")
		}
		if _, err := os.Stat(c.Security.TLSCertFile); err != nil {
			return fmt.Errorf("TLS certificate file not found: %w", err)
		}
		if _, err := os.Stat(c.Security.TLSKeyFile); err != nil {
			return fmt.Errorf("TLS key file not found: %w", err)
		}
	}

	return nil
}

// CreateAuthStore creates an auth.Store from the config
func (c *Config) CreateAuthStore(logger *logging.Logger) (auth.AuthStore, error) {
	if !c.Auth.Enabled {
		if logger != nil {
			logger.Info("Authentication disabled")
		}
		return nil, nil
	}

	store := auth.NewStore()

	// Only attempt to load users if a file is specified
	if c.Auth.UsersFile != "" {
		if logger != nil {
			logger.Debug("Loading users for auth store", "file", c.Auth.UsersFile)
		}

		data, err := os.ReadFile(c.Auth.UsersFile)
		if err != nil {
			if logger != nil {
				logger.Error("Failed to read users file", "file", c.Auth.UsersFile, "error", err)
			}
			return nil, fmt.Errorf("failed to read users file: %w", err)
		}

		var users []struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := yaml.Unmarshal(data, &users); err != nil {
			if logger != nil {
				logger.Error("Failed to parse users file", "file", c.Auth.UsersFile, "error", err)
			}
			return nil, fmt.Errorf("failed to parse users file: %w", err)
		}

		for _, user := range users {
			if err := store.AddUser(user.Username, user.Password); err != nil {
				if logger != nil {
					logger.Error("Failed to add user", "username", user.Username, "error", err)
				}
				// Continue adding other users even if one fails
				continue
			}
			if logger != nil {
				logger.Debug("Added user", "username", user.Username)
			}
		}

		if logger != nil {
			logger.Info("Auth store initialized", "users_count", len(users))
		}
	} else {
		if logger != nil {
			logger.Warn("Auth is enabled but no users file specified")
		}
	}

	return store, nil
}

// LoadPlugins loads plugins from configured paths
func (c *Config) LoadPlugins(logger *logging.Logger) ([]plugin.Plugin, error) {
	if !c.Plugins.Enabled {
		return nil, nil
	}

	var plugins []plugin.Plugin
	if logger != nil {
		logger.Info("Loading plugins", "paths", c.Plugins.Paths)
	}

	return plugins, nil
}
