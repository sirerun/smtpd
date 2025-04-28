package dmarc

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-dkim"
	"github.com/mailtive/smtpd/internal/ctxkeys"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/config"
	"github.com/mailtive/smtpd/internal/plugins/spf"
	"github.com/mailtive/smtpd/pkg/plugin"
	pkgsmtp "github.com/mailtive/smtpd/pkg/smtp"
)

var eventStore = &DMARCEventStore{}
var reportSchedulerStarted sync.Once

// StartDMARCReportScheduler launches a goroutine to periodically aggregate, generate, and send DMARC reports.
func StartDMARCReportScheduler(cfg *config.DMARCReportingConfig, getLastPolicy func() string) {
	reportSchedulerStarted.Do(func() {
		go func() {
			interval := cfg.ReportInterval
			orgName := cfg.StoragePath // fallback to storage path for org name if not set
			orgEmail := cfg.StoragePath + "@localhost" // fallback
			storagePath := cfg.StoragePath
			if orgName == "" {
				orgName = "Mailnative"
			}
			if orgEmail == "@localhost" {
				orgEmail = "postmaster@mailnative.local"
			}
			for {
				begin := time.Now().Add(-interval).Unix()
				end := time.Now().Unix()
				reportPath, err := eventStore.AggregateAndGenerateReport(storagePath, orgName, orgEmail, begin, end)
				if err != nil {
					fmt.Printf("Error generating DMARC report: %v\n", err)
				} else if reportPath != "" {
					// Parse RUA from last DMARC record
					lastPolicy := getLastPolicy()
					rua := ParseRUA(lastPolicy)
					_ = SendAggregateReport(reportPath, rua, orgEmail)
					eventStore.Clear()
				}
				time.Sleep(interval)
			}
		}()
	})
}

// resolver defines the interface for DNS lookups, allowing mocks.
type resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DMARCChecker implements the plugin.Plugin interface for DMARC checks.
type DMARCChecker struct {
	plugin.BasePlugin
	resolver resolver
	logger   *logging.Logger
}

// NewDMARCChecker creates a new DMARCChecker plugin instance.
func NewDMARCChecker(logger *logging.Logger) *DMARCChecker {
	if logger == nil {
		logger = logging.Default()
	}
	return &DMARCChecker{
		resolver: net.DefaultResolver,
		logger:   logger.WithFields(map[string]interface{}{"plugin": "dmarc"}),
	}
}

// Name returns the name of the plugin.
func (p *DMARCChecker) Name() string {
	return "DMARC Checker"
}

// dmarcRecord holds parsed DMARC policy information.
// Simplified for this example.
type dmarcRecord struct {
	Policy          string // p= tag (none, quarantine, reject)
	SubdomainPolicy string // sp= tag
	SPFAlignment    string // aspf= tag (r or s)
	DKIMAlignment   string // adkim= tag (r or s)
	// TODO: Add other tags like rua, ruf, pct, fo
}

// OnMessage is called after the full message data is received.
func (p *DMARCChecker) OnMessage(ctx context.Context, session *plugin.SessionInfo, msg *plugin.MessageInfo) error {
	// --- DMARC reporting: fill in real values and schedule reports ---
	// (Scheduler is started once per process, not per message)
	StartDMARCReportScheduler(&config.DMARCReportingConfig{
		Enabled:        true,
		ReportInterval: 24 * time.Hour,
		StoragePath:    "/tmp",
	}, func() string {
		// Use last DMARC policy string for RUA parsing; stub for now
		return "rua=mailto:postmaster@mailnative.local" // TODO: use actual DMARC record
	})

	// After DMARC evaluation, record event for reporting
	// Fill in real values after policy evaluation
	var (
		dmarcDisposition = "none"
		dkimResultStr    = "fail"
		spfResultStr     = "none"
		policy           = ""
		subdomainPolicy  = ""
		fromDomain       = ""
	)
	defer func() {
		eventStore.AddEvent(DMARCEvent{
			Timestamp:   time.Now(),
			SourceIP:    session.RemoteAddr.String(),
			EnvelopeFrom: msg.From,
			HeaderFrom:  "", // Not available in MessageInfo, could parse from msg.Data
			PolicyDomain: fromDomain,
			Disposition: dmarcDisposition,
			DKIMResult:  dkimResultStr,
			SPFResult:   spfResultStr,
			Policy:      policy,
			SubdomainPolicy: subdomainPolicy,
			Reason:      "",
		})
	}()



	logger := p.logger.WithFields(map[string]interface{}{
		"session_id":  session.SessionID,
		"remote_addr": session.RemoteAddr,
		"mail_from":   msg.From,
	})
	logger.Info("Starting DMARC check")

	// 1. Get From Header Domain
	fromHeaderAddr, err := parseFromHeader(msg.Data)
	if err != nil {
		logger.Warn("Failed to parse From header for DMARC", "error", err)
		return pkgsmtp.NewError(451, "4.6.0", "Error processing message headers for DMARC")
	}
	// Extract domain from address string (user@domain)
	fromDomain := ""
	if parts := strings.Split(fromHeaderAddr.Address, "@"); len(parts) == 2 {
		fromDomain = parts[1]
	}
	if fromDomain == "" {
		logger.Info("No domain found in From header address", "address", fromHeaderAddr.Address)
		return nil // Cannot perform DMARC check
	}
	logger = logger.WithFields(map[string]interface{}{"dmarc_domain": fromDomain})

	// 2. Get SPF Result from Context
	spfValue := ctx.Value(ctxkeys.SPFResultKey)
	// Use the correctly exported type spf.StoredSPFResult
	spfResultData, spfOk = spfValue.(spf.StoredSPFResult)
	spfResult := spf.None // Default if not found
	spfDomain := ""
	if spfOk {
		spfResult = spfResultData.Result
		spfDomain = spfResultData.Domain
	}
	logger.Debug("Retrieved SPF context", "found", spfOk, "result", spfResult, "domain", spfDomain)

	// 3. Get DKIM Results from Context
	dkimValue := ctx.Value(ctxkeys.DKIMResultsKey)
	dkimResults, dkimOk = dkimValue.([]*dkim.Verification)
	if !dkimOk {
		dkimResults = []*dkim.Verification{} // Ensure non-nil slice
	}
	logger.Debug("Retrieved DKIM context", "found", dkimOk, "count", len(dkimResults))

	// 4. Lookup DMARC Record
	dmarcPolicy, err := p.lookupDMARC(ctx, logger, fromDomain)
	if err != nil {
		logger.Warn("DMARC DNS lookup error", "error", err)
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				logger.Info("No DMARC record found")
				return nil // No record, DMARC passes implicitly
			} else if dnsErr.IsTimeout || dnsErr.IsTemporary {
				return pkgsmtp.NewError(451, "4.4.3", "Temporary error during DMARC DNS lookup")
			}
		}
		return pkgsmtp.NewError(451, "4.4.3", "Error resolving DMARC record")
	}
	if dmarcPolicy == nil {
		logger.Info("No valid DMARC record found (v=DMARC1 not present)")
		return nil // No valid DMARC record found
	}

	logger = logger.WithFields(map[string]interface{}{
		"dmarc_policy": dmarcPolicy.Policy,
		"aspf":         dmarcPolicy.SPFAlignment,
		"adkim":        dmarcPolicy.DKIMAlignment,
	})
	logger.Info("Found DMARC policy")

	// 5. Check Alignment and Evaluate Policy
	spfAligned := checkSPFAlignment(spfResult, spfDomain, fromDomain, dmarcPolicy.SPFAlignment)
	dkimAligned := checkDKIMAlignment(dkimResults, fromDomain, dmarcPolicy.DKIMAlignment)

	logger.Info("DMARC alignment check", "spf_result", spfResult, "spf_domain", spfDomain, "spf_aligned", spfAligned, "dkim_aligned", dkimAligned)

	dmarcPass := spfAligned || dkimAligned

	if dmarcPass {
		logger.Info("DMARC check PASSED")
		return nil
	}

	logger.Warn("DMARC check FAILED")
	switch dmarcPolicy.Policy {
	case "reject":
		logger.Warn("Applying DMARC action: reject")
		return pkgsmtp.NewError(550, "5.7.26", fmt.Sprintf("Message rejected due to DMARC policy for %s", fromDomain))
	case "quarantine":
		logger.Warn("Applying DMARC action: quarantine (accepting for now)")
		// TODO: Add header or move to spam folder in a real implementation
		return nil
	case "none":
		logger.Info("Applying DMARC action: none")
		return nil
	default:
		logger.Warn("Unknown DMARC policy value", "policy_value", dmarcPolicy.Policy)
		return nil
	}
}

// lookupDMARC finds and parses the DMARC record for a domain.
func (p *DMARCChecker) lookupDMARC(ctx context.Context, logger *logging.Logger, domain string) (*dmarcRecord, error) {
	lookupDomain := "_dmarc." + domain
	logger.Debug("Looking up DMARC record", "lookup_domain", lookupDomain)
	txtRecords, err := p.resolver.LookupTXT(ctx, lookupDomain)
	if err != nil {
		return nil, err // Return error for DNS issues
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			logger.Debug("Found DMARC record string", "record", record)
			return parseDMARCRecord(record), nil
		}
	}
	return nil, nil // No record starting with v=DMARC1 found
}

// parseDMARCRecord extracts policy information from a DMARC TXT record string.
// Extremely simplified parser.
func parseDMARCRecord(record string) *dmarcRecord {
	policy := &dmarcRecord{
		Policy:        "none", // Default policy
		SPFAlignment:  "r",    // Default alignment
		DKIMAlignment: "r",    // Default alignment
	}
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue // Ignore malformed tags
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch key {
		case "p":
			policy.Policy = strings.ToLower(value)
		case "sp":
			policy.SubdomainPolicy = strings.ToLower(value)
		case "aspf":
			policy.SPFAlignment = strings.ToLower(value)
		case "adkim":
			policy.DKIMAlignment = strings.ToLower(value)
			// Add cases for other tags (rua, ruf, pct, fo) if needed
		}
	}
	return policy
}

// checkSPFAlignment determines if the SPF result aligns with the From domain.
func checkSPFAlignment(result spf.SPFResult, spfDomain string, fromDomain string, alignment string) bool {
	if result != spf.Pass {
		return false // SPF must pass to be considered for alignment
	}
	if spfDomain == "" || fromDomain == "" {
		return false
	}

	if alignment == "s" { // Strict
		return strings.EqualFold(spfDomain, fromDomain)
	} else { // Relaxed (default)
		// Check if spfDomain is the same as or a subdomain of fromDomain
		return strings.EqualFold(spfDomain, fromDomain) || strings.HasSuffix(strings.ToLower(spfDomain), "."+strings.ToLower(fromDomain))
	}
}

// checkDKIMAlignment determines if any DKIM signature aligns with the From domain.
func checkDKIMAlignment(results []*dkim.Verification, fromDomain string, alignment string) bool {
	if fromDomain == "" {
		return false
	}
	for _, v := range results {
		if v.Err != nil {
			continue // Only consider signatures that passed verification
		}
		dkimDomain := v.Domain
		if dkimDomain == "" {
			continue
		}

		aligned := false
		if alignment == "s" { // Strict
			aligned = strings.EqualFold(dkimDomain, fromDomain)
		} else { // Relaxed (default)
			aligned = strings.EqualFold(dkimDomain, fromDomain) || strings.HasSuffix(strings.ToLower(dkimDomain), "."+strings.ToLower(fromDomain))
		}

		if aligned {
			return true // Found at least one valid and aligned signature
		}
	}
	return false // No valid and aligned signatures found
}

// parseFromHeader extracts the display name and address (user@domain) from the From header.
func parseFromHeader(msgData []byte) (*mail.Address, error) {
	// Create a reader for the message data
	r := bytes.NewReader(msgData)
	// Parse the email message headers
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read message headers: %w", err)
	}

	// Get the From header value
	fromHeaderValue := msg.Header.Get("From")
	if fromHeaderValue == "" {
		return nil, fmt.Errorf("no From header found")
	}

	// Parse the From header value
	// Use ParseAddressList for potentially multiple addresses, take the first
	addrs, err := mail.ParseAddressList(fromHeaderValue)
	if err != nil || len(addrs) == 0 {
		// Fallback for simpler cases if list parsing fails
		addr, errSimple := mail.ParseAddress(fromHeaderValue)
		if errSimple != nil {
			return nil, fmt.Errorf("failed to parse From header value '%s': %w (list err: %v)", fromHeaderValue, errSimple, err)
		}
		addrs = []*mail.Address{addr}
	}

	// Ensure DMARCChecker implements the Plugin interface
	var _ plugin.Plugin = (*DMARCChecker)(nil)

	return addrs[0], nil
}

// Ensure DMARCChecker implements the Plugin interface
var _ plugin.Plugin = (*DMARCChecker)(nil)
