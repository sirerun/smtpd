package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// SMTPClientConfig holds configuration for the SMTP client
type SMTPClientConfig struct {
	// Connection settings
	DialTimeout    time.Duration // Timeout for initial connection
	CommandTimeout time.Duration // Timeout for SMTP commands
	MaxConnections int           // Maximum number of concurrent connections per host
	MaxMessageSize int64         // Maximum message size to advertise in EHLO
	ForceTLS       bool          // Whether to require TLS
	SkipVerify     bool          // Whether to skip TLS certificate verification
	LocalName      string        // Local hostname to use in HELO/EHLO
	Auth           smtp.Auth     // Optional authentication credentials
}

// DefaultSMTPClientConfig returns default configuration
func DefaultSMTPClientConfig() *SMTPClientConfig {
	return &SMTPClientConfig{
		DialTimeout:    30 * time.Second,
		CommandTimeout: 5 * time.Minute,
		MaxConnections: 5,
		MaxMessageSize: 32 * 1024 * 1024, // 32MB
		ForceTLS:       false,
		SkipVerify:     false,
		LocalName:      "localhost",
	}
}

// SMTPClient represents a connection to an SMTP server
type SMTPClient struct {
	conn         net.Conn
	client       interface{} // Changed from *smtp.Client to interface{} for testing
	host         string
	config       *SMTPClientConfig
	capabilities map[string]bool
	mockSendFunc func(from string, to []string, msg []byte) error // for testing
}

// SMTPClientPool manages a pool of SMTP clients
type SMTPClientPool struct {
	config     *SMTPClientConfig
	clients    map[string][]*SMTPClient
	mu         sync.Mutex
	mockClient smtpClient                                                  // for testing
	newClient  func(ctx context.Context, host string) (*SMTPClient, error) // for testing
}

// NewSMTPClientPool creates a new pool of SMTP clients
func NewSMTPClientPool(config *SMTPClientConfig) *SMTPClientPool {
	if config == nil {
		config = DefaultSMTPClientConfig()
	}

	pool := &SMTPClientPool{
		config:  config,
		clients: make(map[string][]*SMTPClient),
	}

	// Set the default newClient implementation
	pool.newClient = pool.createNewClient

	return pool
}

// GetClient gets or creates an SMTP client for the given host
func (p *SMTPClientPool) GetClient(ctx context.Context, host string) (*SMTPClient, error) {
	// If we have a mock client for testing, create a wrapper that uses it
	if p.mockClient != nil {
		return &SMTPClient{
			host:   host,
			config: p.config,
			mockSendFunc: func(from string, to []string, msg []byte) error {
				return p.mockClient.SendMail(host, nil, from, to, msg)
			},
		}, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for available client in pool
	if clients, ok := p.clients[host]; ok {
		for i, client := range clients {
			if client != nil {
				// Remove from pool
				p.clients[host] = append(clients[:i], clients[i+1:]...)
				return client, nil
			}
		}
	}

	// Create new client using the newClient function
	return p.newClient(ctx, host)
}

// ReturnClient returns a client to the pool
func (p *SMTPClientPool) ReturnClient(client *SMTPClient) {
	if client == nil {
		return
	}

	// Handle mock clients - don't try to pool them
	if _, ok := client.client.(*MockSMTPClient); ok {
		client.Close()
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Initialize map if nil
	if p.clients == nil {
		p.clients = make(map[string][]*SMTPClient)
	}

	// Check if pool is full
	clients := p.clients[client.host]
	if len(clients) >= p.config.MaxConnections {
		client.Close()
		return
	}

	// Return to pool
	p.clients[client.host] = append(clients, client)
}

// createNewClient is the default implementation for creating a new SMTP client
func (p *SMTPClientPool) createNewClient(ctx context.Context, host string) (*SMTPClient, error) {
	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: p.config.DialTimeout,
	}

	// Connect to server
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}

	// Set deadline for initial connection
	conn.SetDeadline(time.Now().Add(p.config.CommandTimeout))
	defer conn.SetDeadline(time.Time{}) // Clear deadline after initial setup

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Create our wrapper
	smtpClient := &SMTPClient{
		conn:         conn,
		client:       client,
		host:         host,
		config:       p.config,
		capabilities: make(map[string]bool),
	}

	// Perform EHLO/HELO
	if err := smtpClient.hello(); err != nil {
		smtpClient.Close()
		return nil, err
	}

	// Check for STARTTLS
	if p.config.ForceTLS || smtpClient.HasCapability("STARTTLS") {
		if err := smtpClient.startTLS(); err != nil {
			smtpClient.Close()
			return nil, err
		}
	}

	// Authenticate if configured
	if p.config.Auth != nil && smtpClient.HasCapability("AUTH") {
		// Use type assertion to get the real smtp.Client
		realClient, ok := smtpClient.client.(*smtp.Client)
		if !ok {
			smtpClient.Close()
			return nil, fmt.Errorf("unexpected client type for authentication")
		}

		if err := realClient.Auth(p.config.Auth); err != nil {
			smtpClient.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	return smtpClient, nil
}

// hello performs EHLO/HELO
func (c *SMTPClient) hello() error {
	// Handle mock client for tests
	if mockClient, ok := c.client.(*MockSMTPClient); ok {
		// For tests, just set capabilities based on the mock
		caps, err := mockClient.EHLO(c.config.LocalName)
		if err != nil {
			// Fall back to HELO
			if err := mockClient.Hello(c.config.LocalName); err != nil {
				return fmt.Errorf("HELO failed: %w", err)
			}
			return nil
		}
		for _, cap := range caps {
			c.capabilities[cap] = true
		}
		return nil
	}

	// Real implementation for smtp.Client
	smtpClient, ok := c.client.(*smtp.Client)
	if !ok {
		return fmt.Errorf("client is not a valid SMTP client")
	}

	// Try EHLO first
	if err := smtpClient.Hello(c.config.LocalName); err != nil {
		// Fall back to HELO
		if err := smtpClient.Hello(c.config.LocalName); err != nil {
			return fmt.Errorf("HELO failed: %w", err)
		}
	}

	// Get capabilities
	if supported, _ := smtpClient.Extension("STARTTLS"); supported {
		c.capabilities["STARTTLS"] = true
	}
	if supported, _ := smtpClient.Extension("AUTH"); supported {
		c.capabilities["AUTH"] = true
	}

	return nil
}

// startTLS upgrades the connection to TLS
func (c *SMTPClient) startTLS() error {
	// Handle mock client for tests
	if mockClient, ok := c.client.(*MockSMTPClient); ok {
		// For tests, call the mock startTLS which may return an error
		if err := mockClient.StartTLS(nil); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
		return nil
	}

	// Real implementation for smtp.Client
	smtpClient, ok := c.client.(*smtp.Client)
	if !ok {
		return fmt.Errorf("client is not a valid SMTP client")
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(c.host, ":")[0],
		InsecureSkipVerify: c.config.SkipVerify,
	}

	if err := smtpClient.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS failed: %w", err)
	}

	return nil
}

// HasCapability checks if the server supports a capability
func (c *SMTPClient) HasCapability(cap string) bool {
	return c.capabilities[strings.ToUpper(cap)]
}

// Send sends a message
func (c *SMTPClient) Send(from string, to []string, msg []byte) error {
	// If we have a mock function for testing, use it
	if c.mockSendFunc != nil {
		return c.mockSendFunc(from, to, msg)
	}

	// Handle mock client for tests
	if mockClient, ok := c.client.(*MockSMTPClient); ok {
		if err := mockClient.Mail(from); err != nil {
			return fmt.Errorf("MAIL FROM failed: %w", err)
		}

		for _, addr := range to {
			if err := mockClient.Rcpt(addr); err != nil {
				return fmt.Errorf("RCPT TO failed for %s: %w", addr, err)
			}
		}

		writer, err := mockClient.Data()
		if err != nil {
			return fmt.Errorf("DATA command failed: %w", err)
		}

		if _, err := writer.Write(msg); err != nil {
			return fmt.Errorf("writing message failed: %w", err)
		}

		if err := writer.Close(); err != nil {
			return fmt.Errorf("closing message failed: %w", err)
		}

		return nil
	}

	// Real implementation for smtp.Client
	smtpClient, ok := c.client.(*smtp.Client)
	if !ok {
		return fmt.Errorf("client is not a valid SMTP client")
	}

	// Set deadline for the entire send operation
	c.conn.SetDeadline(time.Now().Add(c.config.CommandTimeout))
	defer c.conn.SetDeadline(time.Time{})

	// Send MAIL FROM
	if err := smtpClient.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Send RCPT TO for each recipient
	for _, addr := range to {
		if err := smtpClient.Rcpt(addr); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", addr, err)
		}
	}

	// Send DATA
	w, err := smtpClient.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing message failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message failed: %w", err)
	}

	return nil
}

// Close closes the connection
func (c *SMTPClient) Close() error {
	// Handle mock client for tests
	if mockClient, ok := c.client.(*MockSMTPClient); ok {
		if mockClient != nil {
			mockClient.Quit()
		}
		c.client = nil
		c.conn = nil
		return nil
	}

	// Real implementation for smtp.Client
	if smtpClient, ok := c.client.(*smtp.Client); ok && smtpClient != nil {
		smtpClient.Quit()
	}

	if c.conn != nil {
		c.conn.Close()
	}

	// Make sure all fields are properly set to nil
	c.client = nil
	c.conn = nil
	return nil
}

// MockSMTPClient implements a mock SMTP client for testing
type MockSMTPClient struct {
	capabilities  []string
	authError     error
	mailError     error
	rcptError     error
	dataError     error
	quitError     error
	startTLSError error
}

func (m *MockSMTPClient) Hello(localName string) error {
	return nil
}

func (m *MockSMTPClient) EHLO(localName string) ([]string, error) {
	return m.capabilities, nil
}

func (m *MockSMTPClient) StartTLS(config *tls.Config) error {
	return m.startTLSError
}

func (m *MockSMTPClient) Auth(a smtp.Auth) error {
	return m.authError
}

func (m *MockSMTPClient) Mail(from string) error {
	return m.mailError
}

func (m *MockSMTPClient) Rcpt(to string) error {
	return m.rcptError
}

// MockWriter implements a mock io.WriteCloser for testing
type MockWriter struct{}

func (m *MockWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *MockWriter) Close() error {
	return nil
}

func (m *MockSMTPClient) Data() (io.WriteCloser, error) {
	if m.dataError != nil {
		return nil, m.dataError
	}
	return &MockWriter{}, nil
}

func (m *MockSMTPClient) Quit() error {
	return m.quitError
}

func (m *MockSMTPClient) Close() error {
	return nil
}
