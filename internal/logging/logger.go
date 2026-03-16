package logging

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sirerun/smtpd/internal/metrics"
)

// LogLevel represents the logging level
type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
)

// Format represents the logging output format
type Format string

const (
	JSONFormat Format = "json"
	TextFormat Format = "text"
)

// Config holds the logging configuration
type Config struct {
	// Level is the minimum log level to output
	Level LogLevel
	// Format specifies the output format (json or text)
	Format Format
	// Output is where logs will be written ("stdout", "stderr", or file path)
	Output string
	// ServiceName is the name of the service, used in all log entries
	ServiceName string
	// Environment is the deployment environment (e.g., "dev", "prod")
	Environment string
	// AddSource adds file/line information to logs
	AddSource bool
	// TimeFormat specifies the time format for log entries
	TimeFormat string
}

// globalDefaultLogger holds the package-level default logger instance.
// It's set by SetDefault and returned by Default.
var globalDefaultLogger *Logger

// DefaultConfig returns the default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:       InfoLevel,
		Format:      TextFormat,
		Output:      "stderr",
		ServiceName: "smtpd",
		Environment: "dev",
		AddSource:   true,
		TimeFormat:  time.RFC3339Nano,
	}
}

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
	config *Config
}

// New creates a new logger with the given configuration
func New(config *Config) *Logger {
	if config == nil {
		config = DefaultConfig()
	}

	// Set up the output writer
	var output io.Writer
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// Create directory if it doesn't exist
		dir := filepath.Dir(config.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			// Fall back to stderr if file can't be created
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v, falling back to stderr\n", err)
			output = os.Stderr
		} else {
			// Open the log file
			f, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %v, falling back to stderr\n", err)
				output = os.Stderr
			} else {
				output = f
			}
		}
	}

	// Set up the handler options
	opts := &slog.HandlerOptions{
		AddSource: config.AddSource,
		Level:     parseLevel(config.Level),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize time format
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(config.TimeFormat))
				}
			}
			return a
		},
	}

	// Create the handler based on format
	var handler slog.Handler
	switch config.Format {
	case JSONFormat:
		handler = slog.NewJSONHandler(output, opts)
	default:
		handler = slog.NewTextHandler(output, opts)
	}

	// Add service and environment to all logs
	attrs := []slog.Attr{
		slog.String("service", config.ServiceName),
		slog.String("environment", config.Environment),
	}

	// Create logger with base attributes
	logger := slog.New(handler.WithAttrs(attrs))

	// Create the wrapper Logger
	customLogger := &Logger{
		Logger: logger,
		config: config,
	}

	// Set the *slog* default AND our package default
	slog.SetDefault(logger)
	SetDefault(customLogger) // Set our package default

	return customLogger // Return our wrapper type
}

// Default returns the globally configured default Logger.
// It returns nil if SetDefault has not been called.
func Default() *Logger {
	return globalDefaultLogger
}

// SetDefault sets the globally accessible default Logger instance.
// This is useful for accessing the logger from parts of the application
// where it's not explicitly passed.
func SetDefault(logger *Logger) {
	globalDefaultLogger = logger
	// Optionally, also set the underlying slog default if needed,
	// though New() already does this.
	// slog.SetDefault(logger.Logger)
}

// WithContext creates a new logger with context values
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Add request ID if available
	if reqID, ok := ctx.Value("request_id").(string); ok {
		return &Logger{
			Logger: l.Logger.With("request_id", reqID),
			config: l.config,
		}
	}
	return l
}

// WithComponent creates a new logger with component name
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.Logger.With("component", component),
		config: l.config,
	}
}

// WithError creates a new logger with error details
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}

	// Extract stack trace if available
	var stack []byte
	if e, ok := err.(interface{ StackTrace() []byte }); ok {
		stack = e.StackTrace()
	}

	// Create error context
	attrs := []any{
		"error", err.Error(),
		"error_type", fmt.Sprintf("%T", err),
	}
	if stack != nil {
		attrs = append(attrs, "stack", string(stack))
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
		config: l.config,
	}
}

// WithFields creates a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	if len(fields) == 0 {
		return l
	}

	// Convert fields to slog.Attr
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
		config: l.config,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...any) {
	l.Logger.Debug(msg, args...)
	metrics.RecordLogMessage("debug")
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...any) {
	l.Logger.Info(msg, args...)
	metrics.RecordLogMessage("info")
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...any) {
	l.Logger.Warn(msg, args...)
	metrics.RecordLogMessage("warn")
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...any) {
	l.Logger.Error(msg, args...)
	metrics.RecordLogMessage("error")
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, args ...any) {
	l.Logger.Error(msg, args...)
	metrics.RecordLogMessage("fatal")
	os.Exit(1)
}

// parseLevel converts LogLevel to slog.Level
func parseLevel(level LogLevel) slog.Level {
	switch level {
	case DebugLevel:
		return slog.LevelDebug
	case InfoLevel:
		return slog.LevelInfo
	case WarnLevel:
		return slog.LevelWarn
	case ErrorLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// GetSource returns the source file and line number
func GetSource(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

// logWithContext logs a message with context and fields
func (l *Logger) logWithContext(ctx context.Context, level slog.Level, msg string, fields map[string]interface{}) {
	// Convert fields to slog attributes
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}

	// Log with context and fields
	l.Logger.With(attrs...).Log(ctx, level, msg)
}

// NewSlogAdapter creates a standard library *log.Logger that writes
// to the provided *Logger (which wraps *slog.Logger).
// This is useful for libraries like http.Server that expect a standard logger.
func NewSlogAdapter(logger *Logger) *log.Logger {
	// Use the Info level for messages coming from the standard logger.
	// The component attribute helps identify the source.
	l := logger.WithComponent("stdlib")
	return slog.NewLogLogger(l.Handler(), slog.LevelInfo)
}

// ToSlog returns the underlying *slog.Logger
func (l *Logger) ToSlog() *slog.Logger {
	return l.Logger
}
