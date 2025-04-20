package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "Default config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "Custom config",
			config: &Config{
				Level:      DebugLevel,
				Format:     "json",
				Output:     "stdout",
				AddSource:  true,
				TimeFormat: time.RFC3339,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.config)
			assert.NotNil(t, logger)
		})
	}
}

func TestLoggerWithContext(t *testing.T) {
	logger := New(nil)
	require.NotNil(t, logger)

	// Test without request ID
	ctx := context.Background()
	loggerWithCtx := logger.WithContext(ctx)
	assert.Equal(t, logger, loggerWithCtx)

	// Test with request ID
	ctx = context.WithValue(ctx, "request_id", "test-123")
	loggerWithCtx = logger.WithContext(ctx)
	assert.NotEqual(t, logger, loggerWithCtx)
}

func TestLoggerWithComponent(t *testing.T) {
	logger := New(nil)
	require.NotNil(t, logger)

	loggerWithComponent := logger.WithComponent("test-component")
	assert.NotEqual(t, logger, loggerWithComponent)
}

func TestLoggerWithError(t *testing.T) {
	logger := New(nil)
	require.NotNil(t, logger)

	// Test with nil error
	loggerWithError := logger.WithError(nil)
	assert.Equal(t, logger, loggerWithError)

	// Test with regular error
	err := errors.New("test error")
	loggerWithError = logger.WithError(err)
	assert.NotEqual(t, logger, loggerWithError)

	// Test with error that has stack trace
	type stackError struct {
		error
	}
	errWithStack := &stackError{errors.New("stack error")}
	loggerWithError = logger.WithError(errWithStack)
	assert.NotEqual(t, logger, loggerWithError)
}

func TestLoggerWithFields(t *testing.T) {
	logger := New(nil)
	require.NotNil(t, logger)

	// Test with empty fields
	loggerWithFields := logger.WithFields(map[string]interface{}{})
	assert.Equal(t, logger, loggerWithFields)

	// Test with fields
	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}
	loggerWithFields = logger.WithFields(fields)
	assert.NotEqual(t, logger, loggerWithFields)
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		expected slog.Level
	}{
		{
			name:     "Debug level",
			level:    DebugLevel,
			expected: slog.LevelDebug,
		},
		{
			name:     "Info level",
			level:    InfoLevel,
			expected: slog.LevelInfo,
		},
		{
			name:     "Warn level",
			level:    WarnLevel,
			expected: slog.LevelWarn,
		},
		{
			name:     "Error level",
			level:    ErrorLevel,
			expected: slog.LevelError,
		},
		{
			name:     "Invalid level",
			level:    LogLevel("invalid"),
			expected: slog.LevelInfo, // Default fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLevel(tt.level)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestLoggerOutput(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := &Config{
		Level:       InfoLevel,
		Format:      "json",
		Output:      logFile,
		AddSource:   true,
		TimeFormat:  time.RFC3339,
		ServiceName: "test-service",
		Environment: "test",
	}

	logger := New(config)
	require.NotNil(t, logger)

	// Log some messages
	logger.Info("test message", "key", "value")
	logger.Error("error message", "err", errors.New("test error"))

	// Read the log file
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	// Verify the log entries
	lines := bytes.Split(content, []byte("\n"))
	require.GreaterOrEqual(t, len(lines), 2)

	// Parse the first log entry
	var entry1 map[string]interface{}
	err = json.Unmarshal(lines[0], &entry1)
	require.NoError(t, err)

	// Verify JSON structure
	assert.Equal(t, "INFO", entry1["level"])
	assert.Equal(t, "test message", entry1["msg"])
	assert.Equal(t, "value", entry1["key"])
	assert.Equal(t, "test-service", entry1["service"])
	assert.Equal(t, "test", entry1["environment"])
	assert.Contains(t, entry1, "time")
	assert.Contains(t, entry1, "source")

	// Parse the second log entry
	var entry2 map[string]interface{}
	err = json.Unmarshal(lines[1], &entry2)
	require.NoError(t, err)

	assert.Equal(t, "ERROR", entry2["level"])
	assert.Equal(t, "error message", entry2["msg"])
	assert.Equal(t, "test error", entry2["err"])
}

func TestLogLevels(t *testing.T) {
	// Create a temporary file for testing
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := &Config{
		Level:       InfoLevel,
		Format:      "text",
		Output:      logFile,
		AddSource:   false,
		TimeFormat:  time.RFC3339,
		ServiceName: "test-service",
		Environment: "test",
	}

	logger := New(config)
	require.NotNil(t, logger)

	// Test different log levels
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	// Read the log file
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	// Verify that debug message is not logged (level is info)
	assert.NotContains(t, string(content), "debug message")

	// Verify text format
	assert.Contains(t, string(content), "INFO")
	assert.Contains(t, string(content), "info message")
	assert.Contains(t, string(content), "WARN")
	assert.Contains(t, string(content), "warn message")
	assert.Contains(t, string(content), "ERROR")
	assert.Contains(t, string(content), "error message")

	// Verify service and environment are included
	assert.Contains(t, string(content), "test-service")
	assert.Contains(t, string(content), "test")
}

func TestFatal(t *testing.T) {
	// Cannot directly test os.Exit(1)
	// We can test that the method exists and logs the error
	config := &Config{
		Level:      InfoLevel,
		Format:     "text",
		Output:     "stderr",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	}

	// Temporarily redirect stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	config.Output = "stderr"

	logger := New(config)
	require.NotNil(t, logger)

	// Close the writer side of the pipe after logging
	defer func() {
		w.Close()
		os.Stderr = oldStderr
	}()

	// Call Fatal (will attempt os.Exit(1) which we can't stop)
	// We mainly verify the log output
	logger.Fatal("fatal message", "extra", "data")

	// Read captured output
	w.Close()
	out, _ := io.ReadAll(r)
	content := string(out)

	assert.Contains(t, content, "fatal message")
	assert.Contains(t, content, "extra=data")
}
