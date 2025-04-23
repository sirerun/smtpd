package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, "0.0.0.0", cfg.Server.ListenAddr)
	assert.Equal(t, 25, cfg.Server.Port)
	assert.Equal(t, 587, cfg.Server.SubmissionPort)
	assert.Equal(t, 1000, cfg.Server.MaxConnections)
	assert.Equal(t, 16*1024, cfg.Server.ReadBufferSize)
	assert.Equal(t, 16*1024, cfg.Server.WriteBufferSize)
	assert.Equal(t, 5*time.Minute, cfg.Server.ReadTimeout)
	assert.Equal(t, 5*time.Minute, cfg.Server.WriteTimeout)
	assert.Equal(t, 10*time.Minute, cfg.Server.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.ShutdownTimeout)
	assert.Equal(t, int64(32*1024*1024), cfg.Server.MaxMessageSize)
	assert.Equal(t, 4, cfg.Server.WorkerPoolSize)
	assert.Equal(t, 128, cfg.Server.ConnectionBacklog)
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write test config
	configData := `
server:
  listen_addr: "127.0.0.1"
  port: 2525
  submission_port: 2587
  max_connections: 500
auth:
  enabled: true
  users_file: "test-users.json"
security:
  tls_enabled: true
  tls_cert_file: "test-cert.pem"
  tls_key_file: "test-key.pem"
  rate_limit: 50
`
	_, err = tmpFile.WriteString(configData)
	require.NoError(t, err)
	tmpFile.Close()

	// Test loading config (LoadConfig no longer parses flags)
	cfg, err := LoadConfig(tmpFile.Name())
	require.NoError(t, err)
	// Assertions should match the YAML file exactly
	assert.Equal(t, "127.0.0.1", cfg.Server.ListenAddr)
	assert.Equal(t, 2525, cfg.Server.Port)
	assert.Equal(t, 2587, cfg.Server.SubmissionPort)
	assert.Equal(t, 500, cfg.Server.MaxConnections)
	assert.True(t, cfg.Auth.Enabled)
	assert.Equal(t, "test-users.json", cfg.Auth.UsersFile)
	assert.True(t, cfg.Security.TLSEnabled)
	assert.Equal(t, "test-cert.pem", cfg.Security.TLSCertFile)
	assert.Equal(t, "test-key.pem", cfg.Security.TLSKeyFile)
	assert.Equal(t, 50, cfg.Security.RateLimit)

	// Test loading with empty path (should return defaults)
	cfgDefault, err := LoadConfig("")
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfgDefault)

	// Test loading non-existent file
	_, err = LoadConfig("/non/existent/path/config.yaml")
	assert.Error(t, err)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Server: ServerConfig{
					Port:           25,
					SubmissionPort: 587,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			cfg: &Config{
				Server: ServerConfig{
					Port:           0,
					SubmissionPort: 587,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid submission port",
			cfg: &Config{
				Server: ServerConfig{
					Port:           25,
					SubmissionPort: 0,
				},
			},
			wantErr: true,
		},
		{
			name: "TLS enabled but no cert",
			cfg: &Config{
				Server: ServerConfig{
					Port:           25,
					SubmissionPort: 587,
				},
				Security: SecurityConfig{
					TLSEnabled:  true,
					TLSCertFile: "",
					TLSKeyFile:  "key.pem",
				},
			},
			wantErr: true,
		},
		{
			name: "TLS enabled but no key",
			cfg: &Config{
				Server: ServerConfig{
					Port:           25,
					SubmissionPort: 587,
				},
				Security: SecurityConfig{
					TLSEnabled:  true,
					TLSCertFile: "cert.pem",
					TLSKeyFile:  "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
