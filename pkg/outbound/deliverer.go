package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/emersion/go-dkim"
	"github.com/sirerun/smtpd/pkg/message"
)

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

// Deliverer handles the delivery of messages to remote SMTP servers.
type Deliverer struct {
	localDomains    map[string]bool
	resolver        Resolver                     // Use interface
	clientPool      SMTPClientPoolInterface      // Use interface
	dkimSigners     map[string]DKIMSignerOptions // Map domain to signer options (incl. interface)
	heloHostname    string
	logger          LoggerInterface          // Use interface
	metricsRecorder MetricsRecorderInterface // Use interface
}

// NewDeliverer creates a new outbound deliverer with injected dependencies.
func NewDeliverer(
	localDomains []string,
	dkimConfigs map[string]DKIMSignerOptions, // Pass fully configured options
	heloName string,
	resolver Resolver,
	clientPool SMTPClientPoolInterface,
	logger LoggerInterface,
	metricsRecorder MetricsRecorderInterface,
) (*Deliverer, error) { // Return error for invalid config
	ldMap := make(map[string]bool)
	for _, domain := range localDomains {
		ldMap[strings.ToLower(strings.TrimSpace(domain))] = true
	}

	// Validate required dependencies
	if logger == nil {
		logger = &NoOpLogger{} // Use NoOp for now
	}
	if resolver == nil {
		logger.Error("NewDeliverer called with nil resolver")
		return nil, errors.New("resolver cannot be nil")
	}
	if clientPool == nil {
		logger.Error("NewDeliverer called with nil clientPool")
		return nil, errors.New("clientPool cannot be nil")
	}
	if metricsRecorder == nil {
		logger.Warn("NewDeliverer called with nil metricsRecorder, using NoOpMetricsRecorder")
		metricsRecorder = &NoOpMetricsRecorder{} // Use no-op otherwise
	}

	if heloName == "" {
		var err error
		heloName, err = os.Hostname()
		if err != nil || heloName == "" {
			logger.Warn("Failed to get OS hostname, using 'localhost' as HELO name", "error", err)
			heloName = "localhost" // Fallback
		}
	}
	logger.Info("Using HELO name", "helo_name", heloName)

	// Validate DKIM configs - ensure Signer interface is set if PrivateKey is present
	validDKIMSigners := make(map[string]DKIMSignerOptions)
	for domain, opts := range dkimConfigs {
		if !strings.EqualFold(domain, opts.Domain) {
			logger.Warn("DKIM config map key differs from Domain field", "map_key", domain, "opt_domain", opts.Domain)
			opts.Domain = domain // Standardize
		}

		if opts.PrivateKey != nil && opts.Signer == nil {
			logger.Info("DKIM config provided PrivateKey but no Signer, using defaultDKIMSigner", "domain", domain)
			opts.Signer = &defaultDKIMSigner{}
		} else if opts.PrivateKey == nil && opts.Signer != nil {
			logger.Warn("DKIM config provided Signer but no PrivateKey, signing might fail if key is required", "domain", domain)
		} else if opts.PrivateKey == nil && opts.Signer == nil {
			logger.Debug("DKIM config skipped for domain (no PrivateKey or Signer)", "domain", domain)
			continue // Skip adding this domain to the map
		}
		validDKIMSigners[strings.ToLower(domain)] = opts // Store with lowercase domain key
	}
	if len(validDKIMSigners) > 0 {
		logger.Info("DKIM signing configured for domains", "count", len(validDKIMSigners))
	}

	return &Deliverer{
		localDomains:    ldMap,
		resolver:        resolver,
		clientPool:      clientPool,
		dkimSigners:     validDKIMSigners, // Use validated map
		heloHostname:    heloName,
		logger:          logger.WithComponent("outbound.deliverer"), // Create sub-logger
		metricsRecorder: metricsRecorder,
	}, nil // Return deliverer and nil error
}

// isLocal checks if a domain is configured as a local domain for this server.
func (d *Deliverer) isLocal(domain string) bool {
	return d.localDomains[strings.ToLower(domain)]
}

// Deliver attempts to deliver a message to all recipients concurrently by domain.
// Returns an error only if there's a fundamental issue preventing any delivery attempt
// (e.g., no valid recipients). Individual domain delivery failures are logged and
// recorded via metrics but do not cause this function to return an error.
func (d *Deliverer) Deliver(ctx context.Context, msg *message.Message) error {
	if msg == nil {
		d.logger.Error("Deliver called with nil message")
		return errors.New("cannot deliver nil message")
	}
	msgID := msg.ID // Cache for logging
	d.logger.Info("Starting delivery process", "message_id", msgID, "from", msg.From, "to_count", len(msg.To))

	domainRecipients := make(map[string][]string)
	for _, rcpt := range msg.To {
		parts := strings.Split(rcpt, "@")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			d.logger.Warn("Skipping invalid recipient address", "recipient", rcpt, "message_id", msgID)
			continue
		}
		domain := strings.ToLower(parts[1])
		domainRecipients[domain] = append(domainRecipients[domain], rcpt)
	}

	if len(domainRecipients) == 0 {
		d.logger.Warn("No valid external recipients found for message", "message_id", msgID)
		return nil
	}

	var wg sync.WaitGroup

	d.logger.Info("Processing domains for delivery", "message_id", msgID, "domain_count", len(domainRecipients))
	for domain, recipients := range domainRecipients {
		if d.isLocal(domain) {
			d.logger.Info("Skipping local domain", "domain", domain, "message_id", msgID)
			continue
		}

		wg.Add(1)
		go func(dom string, rcpts []string) {
			defer wg.Done()
			domainCtx := ctx

			err := d.deliverToDomain(domainCtx, msg, dom, rcpts)
			if err != nil {
				d.logger.Error("Goroutine finished: delivery failed for domain", "domain", dom, "message_id", msgID, "error", err)
			} else {
				d.logger.Info("Goroutine finished: delivery successful for domain", "domain", dom, "message_id", msgID)
			}
		}(domain, recipients)
	}

	d.logger.Debug("Waiting for domain delivery goroutines to complete", "message_id", msgID)
	wg.Wait()
	d.logger.Info("Finished all delivery attempts for message", "message_id", msgID)

	return nil
}

// deliverToDomain handles delivery attempts for a single domain.
// It finds MX records, prepares the message (DKIM), and tries delivery via each MX.
// Returns an error if delivery permanently fails for the domain after trying all MX hosts,
// or if a temporary failure occurs that should halt retries for this domain.
func (d *Deliverer) deliverToDomain(ctx context.Context, msg *message.Message, domain string, recipients []string) error {
	msgID := msg.ID
	d.logger.Info("Processing delivery for domain", "domain", domain, "recipients_count", len(recipients), "message_id", msgID)

	d.logger.Debug("Looking up MX records", "domain", domain, "message_id", msgID)
	mxHosts, err := d.resolver.LookupMX(ctx, domain)
	if err != nil {
		d.logger.Error("MX lookup failed", "domain", domain, "message_id", msgID, "error", err)
		if isTemporaryDNSError(err) {
			d.metricsRecorder.RecordMessageStatusByDomain("mx_lookup_temp_failed", domain)
			return fmt.Errorf("temporary MX lookup failure for %s: %w", domain, err)
		}
		d.metricsRecorder.RecordMessageStatusByDomain("mx_lookup_perm_failed", domain)
		return fmt.Errorf("permanent MX lookup failure for %s: %w", domain, err)
	}

	if len(mxHosts) == 0 {
		d.logger.Error("No MX records found", "domain", domain, "message_id", msgID)
		d.metricsRecorder.RecordMessageStatusByDomain("no_mx_records", domain)
		return fmt.Errorf("no MX records found for domain %s", domain)
	}
	d.logger.Info("Found MX records", "domain", domain, "count", len(mxHosts), "message_id", msgID)

	d.logger.Debug("Preparing message data (DKIM signing?)", "domain", domain, "message_id", msgID)
	signedData, err := d.prepareMessageData(msg, domain)
	if err != nil {
		d.logger.Error("Failed to prepare/sign message data, attempting delivery with original data", "domain", domain, "message_id", msgID, "error", err)
		signedData = msg.Data
	} else if len(signedData) != len(msg.Data) {
		d.logger.Info("Message data prepared (DKIM signed)", "domain", domain, "message_id", msgID)
	} else {
		d.logger.Debug("Message data prepared (no DKIM signing needed/configured)", "domain", domain, "message_id", msgID)
	}

	var lastErr error
	deliverySuccessful := false
	for i, mx := range mxHosts {
		mxHost := strings.TrimSuffix(mx.Host, ".")
		d.logger.Info("Attempting delivery via MX", "domain", domain, "mx_host", mxHost, "mx_pref", mx.Pref, "attempt", i+1, "total_mxs", len(mxHosts), "message_id", msgID)

		client, err := d.clientPool.GetClient(ctx, mxHost)
		if err != nil {
			d.logger.Error("Failed to get SMTP client from pool", "mx_host", mxHost, "message_id", msgID, "error", err)
			lastErr = fmt.Errorf("failed to get client for %s: %w", mxHost, err)
			continue
		}

		err = client.Send(msg.From, recipients, signedData)

		d.clientPool.ReleaseClient(client)

		if err != nil {
			d.logger.Error("Delivery attempt failed", "mx_host", mxHost, "message_id", msgID, "error", err)
			lastErr = err

			if isTemporarySMTPError(err) {
				d.logger.Warn("Temporary delivery failure reported by MX", "mx_host", mxHost, "message_id", msgID, "error", err)
				d.metricsRecorder.RecordMessageStatusByDomain("delivery_temp_failed", domain)
				return fmt.Errorf("temporary failure at %s: %w", mxHost, err)
			}
			if isPermanentSMTPError(err) {
				d.logger.Warn("Permanent delivery failure reported by MX", "mx_host", mxHost, "message_id", msgID, "error", err)
				d.metricsRecorder.RecordMessageStatusByDomain("delivery_perm_failed_mx", domain)
				continue
			}
		}

		d.logger.Info("Delivery successful via MX", "domain", domain, "mx_host", mxHost, "message_id", msgID)
		d.metricsRecorder.RecordMessageStatusByDomain("delivered", domain)
		deliverySuccessful = true
		break
	}

	if !deliverySuccessful {
		d.logger.Error("Failed to deliver to domain after trying all MX hosts", "domain", domain, "message_id", msgID, "last_error", lastErr)
		d.metricsRecorder.RecordMessageStatusByDomain("delivery_perm_failed_domain", domain)
		if lastErr != nil {
			return fmt.Errorf("failed to deliver to domain %s after trying all MX hosts: %w", domain, lastErr)
		}
		return fmt.Errorf("failed to deliver to domain %s after trying all MX hosts (no specific error)", domain)
	}

	return nil
}

// prepareMessageData signs the message with DKIM if applicable for the sender's domain.
func (d *Deliverer) prepareMessageData(msg *message.Message, deliveryDomain string) ([]byte, error) {
	data := msg.Data
	msgID := msg.ID

	fromDomain := ""
	if parts := strings.Split(msg.From, "@"); len(parts) == 2 {
		fromDomain = strings.ToLower(parts[1])
	} else {
		d.logger.Warn("Cannot determine sender domain for DKIM", "sender", msg.From, "message_id", msgID)
		return data, nil
	}

	signerOpts, ok := d.dkimSigners[fromDomain]
	if !ok || signerOpts.Signer == nil || signerOpts.PrivateKey == nil {
		d.logger.Debug("No valid DKIM signer configured for sender domain", "sender_domain", fromDomain, "message_id", msgID)
		return data, nil
	}

	d.logger.Info("Signing message with DKIM", "sender_domain", fromDomain, "selector", signerOpts.Selector, "delivery_domain", deliveryDomain, "message_id", msgID)

	options := &dkim.SignOptions{
		Domain:                 signerOpts.Domain,
		Selector:               signerOpts.Selector,
		Signer:                 signerOpts.PrivateKey,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}

	var signedBuf bytes.Buffer
	err := signerOpts.Signer.Sign(&signedBuf, bytes.NewReader(data), options)
	if err != nil {
		d.logger.Error("DKIM signing failed", "sender_domain", fromDomain, "message_id", msgID, "error", err)
		return data, fmt.Errorf("dkim signing failed for domain %s: %w", fromDomain, err)
	}

	d.logger.Info("Message signed successfully with DKIM", "sender_domain", fromDomain, "message_id", msgID)
	return signedBuf.Bytes(), nil
}

// isTemporaryDNSError checks if a DNS error is likely temporary.
func isTemporaryDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// isTemporarySMTPError checks if an error from the SMTP client suggests a temporary failure (4xx).
func isTemporarySMTPError(err error) bool {
	if err == nil {
		return false
	}

	// Context cancellation/timeout is always temporary
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// Network operation errors are usually temporary
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return true
		}
		errStr := opErr.Err.Error()
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "host is down") ||
			strings.Contains(errStr, "network is unreachable") ||
			strings.Contains(errStr, "no route to host") ||
			strings.Contains(errStr, "connection reset by peer") {
			return true
		}
	}

	// Try to extract SMTP code if present
	errStr := err.Error()

	// Parse SMTP response code - improved pattern for matching SMTP codes
	// Look for patterns like "451 4.4.1 Temporary failure" or "451 Temporary failure"
	for _, prefix := range []string{" ", ": "} {
		for _, code := range []string{"421", "450", "451", "452", "454", "455"} {
			if strings.Contains(errStr, prefix+code+" ") {
				return true
			}
		}
	}

	// Also check for codes at the start of the string, e.g., "451 Temporary failure"
	for _, code := range []string{"421", "450", "451", "452", "454", "455"} {
		if strings.HasPrefix(errStr, code+" ") {
			return true
		}
	}

	// Check for enhanced status codes (RFC 3463)
	for _, code := range []string{"4.0.", "4.1.", "4.2.", "4.3.", "4.4.", "4.5.", "4.6.", "4.7."} {
		if strings.Contains(errStr, code) {
			return true
		}
	}

	// Check for common temporary error phrases
	return strings.Contains(strings.ToLower(errStr), "temporary") ||
		strings.Contains(strings.ToLower(errStr), "try again later") ||
		strings.Contains(strings.ToLower(errStr), "greylisted") ||
		strings.Contains(strings.ToLower(errStr), "retry") ||
		strings.Contains(strings.ToLower(errStr), "timeout") ||
		strings.Contains(strings.ToLower(errStr), "rate limit") ||
		strings.Contains(strings.ToLower(errStr), "service unavailable")
}

// isPermanentSMTPError checks if an error from the SMTP client suggests a permanent failure (5xx).
func isPermanentSMTPError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors, context cancellations, and timeouts are never permanent
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return false
		}
	}

	// Try to extract SMTP code if present
	errStr := err.Error()

	// Parse SMTP response code
	for _, prefix := range []string{" ", ": "} {
		for _, code := range []string{"500", "501", "502", "503", "504", "521", "530", "541", "550", "551", "552", "553", "554", "555", "571"} {
			if strings.Contains(errStr, prefix+code+" ") {
				return true
			}
		}
	}

	// Also check for codes at the start of the string
	for _, code := range []string{"500", "501", "502", "503", "504", "521", "530", "541", "550", "551", "552", "553", "554", "555", "571"} {
		if strings.HasPrefix(errStr, code+" ") {
			return true
		}
	}

	// Check for enhanced status codes (RFC 3463)
	for _, code := range []string{"5.0.", "5.1.", "5.2.", "5.3.", "5.4.", "5.5.", "5.6.", "5.7."} {
		if strings.Contains(errStr, code) {
			return true
		}
	}

	// Check for common permanent error phrases
	return strings.Contains(strings.ToLower(errStr), "permanent") ||
		strings.Contains(strings.ToLower(errStr), "rejected") ||
		strings.Contains(strings.ToLower(errStr), "blocked") ||
		strings.Contains(strings.ToLower(errStr), "spam") ||
		strings.Contains(strings.ToLower(errStr), "denied") ||
		strings.Contains(strings.ToLower(errStr), "banned") ||
		strings.Contains(strings.ToLower(errStr), "blacklisted") ||
		strings.Contains(strings.ToLower(errStr), "invalid") && strings.Contains(strings.ToLower(errStr), "address")
}
