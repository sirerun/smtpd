package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// SMTPClientConfig holds configuration for SMTP clients.
type SMTPClientConfig struct {
	ConnectTimeout time.Duration
	SendTimeout    time.Duration
	IdleTimeout    time.Duration // Time before an idle connection is closed
	MaxConnections int           // Max connections per host in the pool
	TLSEnabled     bool          // Whether to attempt STARTTLS
	TLSConfig      *tls.Config   // Custom TLS config (optional)
	HeloHostname   string
}

// DefaultSMTPClientConfig returns a default configuration.
func DefaultSMTPClientConfig() SMTPClientConfig {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost.localdomain"
	}
	return SMTPClientConfig{
		ConnectTimeout: 10 * time.Second,
		SendTimeout:    30 * time.Second,
		IdleTimeout:    5 * time.Minute,
		MaxConnections: 10,
		TLSEnabled:     true,
		HeloHostname:   hostname,
	}
}

// SMTPClient represents a connection to a single SMTP server.
// It implements the SMTPClientInterface.
type SMTPClient struct {
	config SMTPClientConfig
	host   string // Target host (e.g., "mx.example.com")
	client *smtp.Client
	conn   net.Conn
	logger LoggerInterface // Add logger
	mu     sync.Mutex      // Mutex to protect concurrent Send/Close operations on the same client
}

// newSMTPClient creates and initializes a new SMTP client connection.
func newSMTPClient(ctx context.Context, host string, config SMTPClientConfig, dialer Dialer, logger LoggerInterface) (*SMTPClient, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "25")
	}

	logger.Debug("Dialing SMTP server", "address", addr)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		logger.Error("Failed to dial SMTP server", "address", addr, "error", err)
		return nil, fmt.Errorf("failed to dial %s: %w", addr, err)
	}
	logger.Debug("Successfully connected", "address", addr)

	connectDeadline := time.Now().Add(config.ConnectTimeout)
	conn.SetDeadline(connectDeadline)
	defer conn.SetDeadline(time.Time{})

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		logger.Error("Failed to create SMTP client", "host", host, "error", err)
		return nil, fmt.Errorf("failed to create smtp client for %s: %w", host, err)
	}
	logger.Debug("SMTP client created", "host", host)

	logger.Debug("Sending HELO/EHLO", "host", host, "helo_name", config.HeloHostname)
	if err := c.Hello(config.HeloHostname); err != nil {
		c.Close()
		logger.Error("HELO/EHLO failed", "host", host, "error", err)
		return nil, fmt.Errorf("failed HELO/EHLO to %s: %w", host, err)
	}
	logger.Debug("HELO/EHLO successful", "host", host)

	if config.TLSEnabled {
		logger.Debug("Checking for STARTTLS support", "host", host)
		if ok, _ := c.Extension("STARTTLS"); ok {
			logger.Info("Attempting STARTTLS", "host", host)
			tlsConfig := config.TLSConfig
			if tlsConfig == nil {
				tlsConfig = &tls.Config{
					ServerName: host,
					MinVersion: tls.VersionTLS12,
				}
			} else {
				if tlsConfig.ServerName == "" {
					tlsConfig.ServerName = host
				}
			}

			conn.SetDeadline(time.Now().Add(config.ConnectTimeout))
			err = c.StartTLS(tlsConfig)
			conn.SetDeadline(time.Time{})

			if err != nil {
				c.Close()
				logger.Error("STARTTLS failed", "host", host, "error", err)
				return nil, fmt.Errorf("STARTTLS failed for %s: %w", host, err)
			}
			logger.Info("STARTTLS successful", "host", host)

			logger.Debug("Sending HELO/EHLO after STARTTLS", "host", host)
			if err := c.Hello(config.HeloHostname); err != nil {
				c.Close()
				logger.Error("HELO/EHLO after STARTTLS failed", "host", host, "error", err)
				return nil, fmt.Errorf("failed HELO/EHLO after STARTTLS to %s: %w", host, err)
			}
			logger.Debug("HELO/EHLO after STARTTLS successful", "host", host)
		} else {
			logger.Info("STARTTLS not supported by server", "host", host)
		}
	}

	return &SMTPClient{
		config: config,
		host:   host,
		client: c,
		conn:   conn,
		logger: logger.WithComponent(fmt.Sprintf("smtp_client(%s)", host)),
	}, nil
}

// Send sends an email using the established connection.
func (c *SMTPClient) Send(from string, to []string, msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil || c.conn == nil {
		return errors.New("SMTP client is closed or not initialized")
	}

	var deadline time.Time
	if c.config.SendTimeout > 0 {
		deadline = time.Now().Add(c.config.SendTimeout)
		c.conn.SetDeadline(deadline)
		defer c.conn.SetDeadline(time.Time{})
	}
	c.logger.Debug("Starting message transmission", "from", from, "to_count", len(to))

	if err := c.client.Reset(); err != nil {
		c.logger.Error("Failed to reset SMTP client state, closing connection", "error", err)
		_ = c.Close()
		return fmt.Errorf("failed to reset SMTP client state: %w", err)
	}

	c.logger.Debug("Sending MAIL FROM", "from", from)
	if err := c.client.Mail(from); err != nil {
		c.logger.Error("MAIL FROM command failed", "from", from, "error", err)
		return fmt.Errorf("MAIL FROM %s failed: %w", from, err)
	}

	for _, addr := range to {
		c.logger.Debug("Sending RCPT TO", "recipient", addr)
		if err := c.client.Rcpt(addr); err != nil {
			c.logger.Warn("RCPT TO command failed for recipient", "recipient", addr, "error", err)
			return fmt.Errorf("RCPT TO %s failed: %w", addr, err)
		}
	}
	c.logger.Debug("All RCPT TO commands successful")

	c.logger.Debug("Sending DATA command")
	w, err := c.client.Data()
	if err != nil {
		c.logger.Error("DATA command failed", "error", err)
		return fmt.Errorf("DATA command failed: %w", err)
	}
	c.logger.Debug("Writing message data")
	_, err = w.Write(msg)
	if err != nil {
		_ = w.Close()
		c.logger.Error("Failed writing message data", "error", err)
		return fmt.Errorf("failed writing message data: %w", err)
	}
	c.logger.Debug("Closing data writer")
	err = w.Close()
	if err != nil {
		c.logger.Error("Failed closing data writer", "error", err)
		return fmt.Errorf("failed closing data writer: %w", err)
	}

	c.logger.Info("Message transmission successful")
	return nil
}

// Close closes the SMTP connection gracefully.
func (c *SMTPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		c.logger.Debug("Client already closed or not initialized")
		return nil
	}

	c.logger.Debug("Closing SMTP client connection")
	errQuit := c.client.Quit()
	if errQuit != nil {
		c.logger.Warn("QUIT command failed, closing connection directly", "error", errQuit)
	}

	errClose := c.client.Close()
	c.client = nil
	c.conn = nil

	if errClose != nil {
		c.logger.Error("Error closing SMTP connection", "error", errClose)
		if errQuit != nil {
			return fmt.Errorf("quit failed (%v) and close failed: %w", errQuit, errClose)
		}
		return fmt.Errorf("failed to close connection: %w", errClose)
	}
	if errQuit != nil {
		return fmt.Errorf("QUIT command failed: %w", errQuit)
	}

	c.logger.Debug("SMTP client connection closed successfully")
	return nil
}

// Host returns the target host for this client.
func (c *SMTPClient) Host() string {
	return c.host
}

// SMTPClientPool manages a pool of SMTP client connections.
// It implements the SMTPClientPoolInterface.
type SMTPClientPool struct {
	config          SMTPClientConfig
	dialer          Dialer
	logger          LoggerInterface
	mu              sync.RWMutex // Changed from sync.Mutex to sync.RWMutex to support RLock/RUnlock
	pools           map[string]chan *SMTPClient
	maxConnsPerHost int
	idleTimeout     time.Duration
}

// NewSMTPClientPool creates a new pool.
func NewSMTPClientPool(config SMTPClientConfig, dialer Dialer, logger LoggerInterface) *SMTPClientPool {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: config.ConnectTimeout}
		logger.Info("No dialer provided, using default net.Dialer", "timeout", config.ConnectTimeout)
	}
	if logger == nil {
		logger = &NoOpLogger{}
		logger.Warn("No logger provided for SMTPClientPool, using NoOpLogger")
	}

	poolLogger := logger.WithComponent("smtp_client_pool")

	return &SMTPClientPool{
		config:          config,
		dialer:          dialer,
		logger:          poolLogger,
		pools:           make(map[string]chan *SMTPClient),
		maxConnsPerHost: config.MaxConnections,
		idleTimeout:     config.IdleTimeout,
	}
}

// getOrCreateHostPool returns the channel (pool) for a given host, creating it if necessary.
func (p *SMTPClientPool) getOrCreateHostPool(host string) chan *SMTPClient {
	p.mu.Lock()
	defer p.mu.Unlock()

	poolChan, ok := p.pools[host]
	if !ok {
		size := p.maxConnsPerHost
		if size <= 0 {
			size = 1
		}
		p.logger.Info("Creating new connection pool for host", "host", host, "size", size)
		poolChan = make(chan *SMTPClient, size)
		p.pools[host] = poolChan
	}
	return poolChan
}

// GetClient retrieves or creates an SMTP client for the specified host.
func (p *SMTPClientPool) GetClient(ctx context.Context, host string) (SMTPClientInterface, error) {
	hostPool := p.getOrCreateHostPool(host)

	select {
	case client := <-hostPool:
		if client == nil {
			p.logger.Error("Received nil client from pool channel", "host", host)
		} else {
			p.logger.Debug("Reusing existing SMTP client from pool", "host", host)
			if client.conn != nil {
				client.conn.SetDeadline(time.Time{})
			} else {
				p.logger.Warn("Reused client has nil connection, discarding", "host", host)
			}
			return client, nil
		}
	default:
		p.logger.Info("Pool empty, creating new SMTP client", "host", host)
		client, err := newSMTPClient(ctx, host, p.config, p.dialer, p.logger)
		if err != nil {
			p.logger.Error("Failed to create new SMTP client", "host", host, "error", err)
			return nil, err
		}
		return client, nil
	}

	p.logger.Info("Creating new SMTP client after issue with pooled client", "host", host)
	client, err := newSMTPClient(ctx, host, p.config, p.dialer, p.logger)
	if err != nil {
		p.logger.Error("Failed to create new SMTP client", "host", host, "error", err)
		return nil, err
	}
	return client, nil
}

// ReleaseClient returns a client to the pool.
func (p *SMTPClientPool) ReleaseClient(client SMTPClientInterface) {
	smtpClient, ok := client.(*SMTPClient)
	if !ok || smtpClient == nil {
		p.logger.Warn("Attempted to release an invalid client type or nil client")
		if client != nil {
			_ = client.Close()
		}
		return
	}

	host := smtpClient.Host()
	hostPool := p.getOrCreateHostPool(host)

	if smtpClient.conn != nil {
		smtpClient.conn.SetDeadline(time.Time{})
	} else {
		p.logger.Warn("Attempted to release client with nil connection, discarding", "host", host)
		return
	}

	select {
	case hostPool <- smtpClient:
		p.logger.Debug("Released SMTP client back to pool", "host", host)
	default:
		p.logger.Info("Pool full, closing released client instead of pooling", "host", host)
		err := smtpClient.Close()
		if err != nil {
			p.logger.Warn("Error closing excess client", "host", host, "error", err)
		}
	}
}

// CloseAll closes all connections currently in the pool and removes the pools.
func (p *SMTPClientPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Info("Closing all pooled SMTP client connections")
	for host, poolChan := range p.pools {
		close(poolChan)
		for client := range poolChan {
			if client != nil {
				p.logger.Debug("Closing pooled client", "host", host)
				err := client.Close()
				if err != nil {
					p.logger.Warn("Error closing pooled client during CloseAll", "host", host, "error", err)
				}
			}
		}
		delete(p.pools, host)
	}
	p.logger.Info("Finished closing all pooled connections")
}

// Helper function to ensure SMTPClient implements SMTPClientInterface
var _ SMTPClientInterface = (*SMTPClient)(nil)

// Helper function to ensure SMTPClientPool implements SMTPClientPoolInterface
var _ SMTPClientPoolInterface = (*SMTPClientPool)(nil)
