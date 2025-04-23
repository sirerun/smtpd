package outbound

import (
	"context"
	"crypto"
	"io"
	"net"

	"github.com/emersion/go-dkim"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/metrics"
)

// Resolver defines the interface for DNS lookups.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Dialer defines an interface for creating network connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// SMTPClientInterface defines the interface for an SMTP client connection.
type SMTPClientInterface interface {
	Send(from string, to []string, msg []byte) error
	Close() error
	Host() string // To know which host this client is connected to
}

// SMTPClientPoolInterface defines the interface for managing SMTP client connections.
type SMTPClientPoolInterface interface {
	GetClient(ctx context.Context, host string) (SMTPClientInterface, error)
	ReleaseClient(client SMTPClientInterface) // Optional: for explicit release if needed
	CloseAll()                                // Added to allow graceful shutdown
}

// DKIMSignerInterface defines the interface for signing messages with DKIM.
type DKIMSignerInterface interface {
	Sign(w io.Writer, r io.Reader, opts *dkim.SignOptions) error
}

// MetricsRecorderInterface defines the interface for recording delivery metrics.
type MetricsRecorderInterface interface {
	RecordMessageStatusByDomain(status string, domain string)
}

// LoggerInterface defines a basic logging interface compatible with internal/logging.
type LoggerInterface interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	WithComponent(name string) LoggerInterface // Allow creating sub-loggers
}

// --- Default Implementations ---

// defaultDKIMSigner wraps the dkim.Sign function.
type defaultDKIMSigner struct{}

func (s *defaultDKIMSigner) Sign(w io.Writer, r io.Reader, opts *dkim.SignOptions) error {
	return dkim.Sign(w, r, opts)
}

// DefaultDKIMSigner implements DKIMSignerInterface using the standard library.
type DefaultDKIMSigner struct{}

func (s *DefaultDKIMSigner) Sign(w io.Writer, r io.Reader, opts *dkim.SignOptions) error {
	return dkim.Sign(w, r, opts)
}

// --- Adapters ---

// LoggerAdapter adapts internal/logging.Logger to LoggerInterface.
type LoggerAdapter struct {
	logger *logging.Logger
}

func NewLoggerAdapter(l *logging.Logger) *LoggerAdapter {
	if l == nil {
		// Avoid nil panic if a nil logger is somehow passed
		// Use the local NoOpLogger definition instead of logging.NewNopLogger()
		return &LoggerAdapter{logger: nil} // Represent Nop by having nil internal logger
	}
	return &LoggerAdapter{logger: l}
}
func (a *LoggerAdapter) Debug(msg string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Debug(msg, args...)
}
func (a *LoggerAdapter) Info(msg string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Info(msg, args...)
}
func (a *LoggerAdapter) Warn(msg string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Warn(msg, args...)
}
func (a *LoggerAdapter) Error(msg string, args ...any) {
	if a.logger == nil {
		return
	}
	a.logger.Error(msg, args...)
}
func (a *LoggerAdapter) WithComponent(name string) LoggerInterface {
	// Ensure the wrapped logger is not nil before calling WithComponent
	if a.logger == nil {
		return a // Return the Nop adapter
	}
	return NewLoggerAdapter(a.logger.WithComponent(name))
}

// MetricsAdapter adapts internal/metrics functions to MetricsRecorderInterface.
type MetricsAdapter struct{}

func (m *MetricsAdapter) RecordMessageStatusByDomain(status string, domain string) {
	metrics.RecordMessageStatusByDomain(status, domain)
}

// --- No-Op Implementations (for defaults/testing) ---

type NoOpLogger struct{}

func (l *NoOpLogger) Debug(msg string, args ...any)             {}
func (l *NoOpLogger) Info(msg string, args ...any)              {}
func (l *NoOpLogger) Warn(msg string, args ...any)              {}
func (l *NoOpLogger) Error(msg string, args ...any)             {}
func (l *NoOpLogger) WithComponent(name string) LoggerInterface { return l }

type NoOpMetricsRecorder struct{}

func (m *NoOpMetricsRecorder) RecordMessageStatusByDomain(status string, domain string) {}

// DKIMSignerOptions holds configuration for DKIM signing (used by caller).
// Moved here as it's closely related to the interfaces.
type DKIMSignerOptions struct {
	Domain     string
	Selector   string
	PrivateKey crypto.Signer       // The actual key, loaded by the caller
	Headers    []string            // Optional: Specific headers to sign (often defaults are fine)
	Signer     DKIMSignerInterface // The interface for signing
}
