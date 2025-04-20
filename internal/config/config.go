package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mailtive/smtpd/internal/auth"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/server"
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
	}
}

// LoadConfig loads configuration from a file, applying defaults first.
func LoadConfig(configFile string) (*Config, error) {
	// Start with defaults
	config := DefaultConfig()

	// If no file specified, return defaults
	if configFile == "" {
		return config, nil
	}

	// Load from file and overwrite defaults
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file '%s': %w", configFile, err)
	}

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

// CreateServerConfig creates a server.ServerConfig from the config
func (c *Config) CreateServerConfig(logger *logging.Logger) *server.ServerConfig {
	return &server.ServerConfig{
		MaxConnections:    c.Server.MaxConnections,
		ReadBufferSize:    c.Server.ReadBufferSize,
		WriteBufferSize:   c.Server.WriteBufferSize,
		ReadTimeout:       c.Server.ReadTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		ShutdownTimeout:   c.Server.ShutdownTimeout,
		MaxMessageSize:    c.Server.MaxMessageSize,
		WorkerPoolSize:    c.Server.WorkerPoolSize,
		ConnectionBacklog: c.Server.ConnectionBacklog,
	}
}

// CreateAuthStore creates an auth.Store from the config
func (c *Config) CreateAuthStore(logger *logging.Logger) (*auth.Store, error) {
	if !c.Auth.Enabled {
		return nil, nil
	}

	store := auth.NewStore()

	if logger != nil {
		logger.Debug("Loading users for auth store", "file", c.Auth.UsersFile)
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
