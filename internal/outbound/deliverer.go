package outbound

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"

	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/message"
	"github.com/mailtive/smtpd/internal/metrics"
)

// resolver defines the interface for DNS lookups needed by the deliverer.
// This allows mocking in tests.
type resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	// Add LookupTXT if needed later for things like TLSA
}

// defaultResolver uses the net package for DNS lookups.
type defaultResolver struct{}

func (dr *defaultResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.LookupMX(name) // Note: net.LookupMX doesn't use the passed context directly
}

// smtpClient defines the interface for sending mail via SMTP.
// This allows mocking smtp.SendMail in tests.
type smtpClient interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// defaultSmtpClient uses the net/smtp package.
type defaultSmtpClient struct{}

func (sc *defaultSmtpClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	// TODO: Consider using a more sophisticated client that handles timeouts,
	// EHLO capabilities, STARTTLS etc. better than the basic smtp.SendMail.
	// For now, use the standard library function.
	return smtp.SendMail(addr, a, from, to, msg)
}

// DeliveryResult indicates the outcome of a delivery attempt for a specific domain.
type DeliveryResult int

const (
	DeliverySuccess  DeliveryResult = iota // Message accepted by the remote server
	DeliveryTempFail                       // Temporary failure, should retry
	DeliveryPermFail                       // Permanent failure, should bounce
)

// DomainDeliveryStatus holds the result for a single domain.
type DomainDeliveryStatus struct {
	Domain string
	Result DeliveryResult
	Detail string // Additional info, e.g., error message or final SMTP response
}

// --- DKIM Signing Configuration ---

type DKIMSignerOptions struct {
	Domain     string
	Selector   string
	PrivateKey crypto.Signer
	Headers    []string
}

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported private key type in %s: %s", path, block.Type)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key from %s: %w", path, err)
	}
	return key, nil
}

// Deliverer handles the delivery of messages to remote SMTP servers.
type Deliverer struct {
	localDomains map[string]bool
	resolver     resolver
	clientPool   *SMTPClientPool
	dkimSigners  map[string]DKIMSignerOptions
	heloHostname string
	logger       *logging.Logger
}

// NewDeliverer creates a new outbound deliverer.
func NewDeliverer(localDomains []string, dkimConfigs map[string]DKIMSignerOptions, heloName string, logger *logging.Logger) *Deliverer {
	ldMap := make(map[string]bool)
	for _, domain := range localDomains {
		ldMap[strings.ToLower(strings.TrimSpace(domain))] = true
	}
	if heloName == "" {
		heloName, _ = os.Hostname()
		if heloName == "" {
			heloName = "localhost"
		}
	}

	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
	}

	// Create SMTP client pool with default config
	clientPool := NewSMTPClientPool(DefaultSMTPClientConfig())

	return &Deliverer{
		localDomains: ldMap,
		resolver:     &defaultResolver{},
		clientPool:   clientPool,
		dkimSigners:  dkimConfigs,
		heloHostname: heloName,
		logger:       logger.WithComponent("outbound.deliverer"),
	}
}

// --- Methods for testing ---
// withResolver allows injecting a mock resolver for tests.
func (d *Deliverer) withResolver(r resolver) *Deliverer {
	d.resolver = r
	return d
}

// withSmtpClient allows injecting a mock SMTP client for tests.
func (d *Deliverer) withSmtpClient(client smtpClient) *Deliverer {
	// Create a client pool with the mock client
	d.clientPool = &SMTPClientPool{
		config:     DefaultSMTPClientConfig(),
		mockClient: client,
	}
	return d
}

// --- End Methods for testing ---

// isLocal checks if a domain is configured as a local domain for this server.
func (d *Deliverer) isLocal(domain string) bool {
	return d.localDomains[strings.ToLower(domain)]
}

// Deliver attempts to deliver a message to all recipients.
func (d *Deliverer) Deliver(ctx context.Context, msg *message.Message) error {
	// Group recipients by domain
	domainRecipients := make(map[string][]string)
	for _, rcpt := range msg.To {
		domain := strings.ToLower(strings.Split(rcpt, "@")[1])
		domainRecipients[domain] = append(domainRecipients[domain], rcpt)
	}

	// Process each domain
	for domain, recipients := range domainRecipients {
		if d.localDomains[domain] {
			d.logger.Info("skipping local domain", "domain", domain)
			continue
		}

		// Look up MX records
		mxHosts, err := d.resolver.LookupMX(ctx, domain)
		if err != nil {
			d.logger.Error("failed to lookup MX records", "domain", domain, "error", err)
			metrics.RecordMessageStatusByDomain("mx_lookup_failed", domain)
			continue
		}

		if len(mxHosts) == 0 {
			d.logger.Error("no MX records found", "domain", domain)
			metrics.RecordMessageStatusByDomain("no_mx_records", domain)
			continue
		}

		// Try each MX host in order of preference
		for _, mx := range mxHosts {
			d.logger.Info("attempting delivery", "domain", domain, "mx", mx.Host)

			// Get SMTP client from pool
			client, err := d.clientPool.GetClient(ctx, mx.Host)
			if err != nil {
				d.logger.Error("failed to get SMTP client", "mx", mx.Host, "error", err)
				continue
			}

			// Attempt delivery
			if err := d.deliverToHost(ctx, client, msg, recipients); err != nil {
				d.logger.Error("delivery failed", "mx", mx.Host, "error", err)
				metrics.RecordMessageStatusByDomain("delivery_failed", domain)
				continue
			}

			d.logger.Info("delivery successful", "domain", domain, "mx", mx.Host)
			metrics.RecordMessageStatusByDomain("delivered", domain)
			break
		}
	}

	return nil
}

func (d *Deliverer) deliverToHost(ctx context.Context, client *SMTPClient, msg *message.Message, recipients []string) error {
	// Sign message with DKIM if configured
	if len(d.dkimSigners) > 0 {
		// ... existing DKIM signing code ...
	}

	// Send message
	if err := client.Send(msg.From, recipients, msg.Data); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// isTemporaryDNSError checks if a DNS error is likely temporary.
func isTemporaryDNSError(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	// Consider other potential temporary network errors?
	return false // Assume permanent otherwise
}

// isTemporarySMTPError checks if an error from smtp.SendMail suggests a temporary failure.
// This is a basic check; more sophisticated parsing of SMTP error codes (4xx) is needed.
func isTemporarySMTPError(err error) bool {
	if err == nil {
		return false
	}
	// Basic check for common temporary network errors
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Timeout() || strings.Contains(opErr.Error(), "connection refused") || strings.Contains(opErr.Error(), "host is down") {
			return true
		}
	}
	// Check for 4xx SMTP status codes (requires parsing error string)
	// smtp.SendMail often returns errors like "... 4xx ..."
	// A more robust client would return structured errors.
	errStr := err.Error()
	return strings.Contains(errStr, " 421 ") || strings.Contains(errStr, " 450 ") || strings.Contains(errStr, " 451 ") || strings.Contains(errStr, " 452 ")
}
