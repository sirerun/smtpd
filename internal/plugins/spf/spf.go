package spf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/mailtive/smtpd/internal/ctxkeys"
	"github.com/mailtive/smtpd/internal/smtp"
	"github.com/mailtive/smtpd/pkg/plugin"
)

// SPFChecker implements the plugin.Plugin interface for SPF checks.
type SPFChecker struct {
	plugin.BasePlugin          // Embed base plugin for default methods
	resolver          resolver // Use resolver interface
	logger            *slog.Logger
}

// resolver defines the interface for DNS lookups, allowing mocks.
type resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// defaultResolver uses net.DefaultResolver.
type defaultResolver struct{}

func (dr *defaultResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// NewSPFChecker creates a new SPFChecker plugin instance.
func NewSPFChecker(logger *slog.Logger) *SPFChecker {
	if logger == nil {
		logger = slog.Default()
	}
	return &SPFChecker{
		resolver: &defaultResolver{}, // Use default implementation
		logger:   logger.With("plugin", "spf"),
	}
}

// withResolver is a test helper to inject a mock resolver.
func (p *SPFChecker) withResolver(r resolver) *SPFChecker {
	p.resolver = r
	return p
}

// Name returns the name of the plugin.
func (p *SPFChecker) Name() string {
	return "SPF Checker"
}

// OnConnect is called when a new client connects.
func (p *SPFChecker) OnConnect(ctx context.Context, session *plugin.SessionInfo) error {
	// No action needed on connect for SPF
	return nil
}

// OnHelo is called after HELO/EHLO command.
func (p *SPFChecker) OnHelo(ctx context.Context, session *plugin.SessionInfo, heloDomain string) error {
	// No action needed on HELO/EHLO for SPF
	return nil
}

// StoredSPFResult bundles the SPF result and the domain it applies to.
// Needs to be exported to be used by DMARC plugin.
type StoredSPFResult struct {
	Result SPFResult
	Domain string
}

// OnMailFrom is called after MAIL FROM command.
// This is where the core SPF check logic will reside.
func (p *SPFChecker) OnMailFrom(ctx context.Context, session *plugin.SessionInfo, from string) error {
	logger := p.logger.With("session_id", session.SessionID, "remote_addr", session.RemoteAddr)

	clientIP := getClientIP(session)
	if clientIP == nil {
		logger.Warn("Could not determine client IP for SPF check")
		// Store the result in context
		ctx = context.WithValue(ctx, ctxkeys.SPFResultKey, StoredSPFResult{Result: None, Domain: ""})
		return smtp.NewError(451, "4.3.0", "Temporary error: Could not determine client IP")
	}

	logger = logger.With("client_ip", clientIP.String())

	if from == "<>" {
		logger.Info("Skipping SPF check for null sender")
		// Store the result in context
		ctx = context.WithValue(ctx, ctxkeys.SPFResultKey, StoredSPFResult{Result: None, Domain: ""})
		return nil
	}

	parts := strings.Split(from, "@")
	if len(parts) != 2 || parts[1] == "" {
		logger.Warn("Invalid MAIL FROM address format for SPF check", "mail_from", from)
		// Store the result in context
		ctx = context.WithValue(ctx, ctxkeys.SPFResultKey, StoredSPFResult{Result: PermError, Domain: ""})
		return smtp.NewError(553, "5.1.7", "Sender address format invalid")
	}
	domain := parts[1]
	logger = logger.With("spf_domain", domain)
	logger.Info("Initiating SPF check")

	// Perform DNS TXT lookup for SPF record
	txtRecords, err := p.resolver.LookupTXT(ctx, domain)
	finalResult := None
	var returnErr error = nil

	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				logger.Info("No SPF record found (NXDOMAIN or no TXT)")
				finalResult = None
			} else if dnsErr.IsTimeout {
				logger.Warn("DNS lookup timed out during SPF check", "error", err)
				finalResult = TempError
				returnErr = smtp.NewError(451, "4.3.2", "Temporary error: DNS lookup timeout during SPF check")
			} else if dnsErr.Temporary() {
				logger.Warn("Temporary DNS error during SPF check", "error", err)
				finalResult = TempError
				returnErr = smtp.NewError(451, "4.3.0", "Temporary error: DNS issue during SPF check")
			} else {
				logger.Error("Permanent DNS error during SPF lookup", "error", err)
				finalResult = PermError
				returnErr = smtp.NewError(451, "4.3.0", "Temporary error: Cannot resolve SPF record")
			}
		} else {
			logger.Error("Non-DNS error during SPF lookup", "error", err)
			finalResult = TempError
			returnErr = smtp.NewError(451, "4.3.0", "Temporary error: SPF record lookup issue")
		}
	} else {
		spfRecord := ""
		foundVSPF1 := false
		for _, record := range txtRecords {
			if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
				if spfRecord != "" {
					logger.Warn("Multiple SPF records found, treating as PermError")
					finalResult = PermError
					returnErr = smtp.NewError(451, "4.3.0", "Temporary error: Multiple SPF records found")
					break
				}
				spfRecord = record
				foundVSPF1 = true
			}
		}

		if returnErr == nil {
			if !foundVSPF1 {
				logger.Info("No v=spf1 record found among TXT records")
				finalResult = None
			} else {
				logger.Debug("Found SPF record", "record", spfRecord)
				evalResult, evalErr := p.evaluateSPF(ctx, logger, spfRecord, clientIP, domain, session.HeloDomain)
				if evalErr != nil {
					logger.Error("Temporary error during SPF evaluation", "error", evalErr)
					finalResult = TempError
					returnErr = smtp.NewError(451, "4.4.3", "Temporary error during SPF evaluation")
				} else {
					finalResult = evalResult
					logger.Info("SPF evaluation completed", "result", finalResult)

					switch finalResult {
					case Fail:
						returnErr = smtp.NewError(550, "5.7.23", "Message rejected due to SPF policy")
					case TempError:
						returnErr = smtp.NewError(451, "4.4.3", "Temporary error during SPF evaluation")
					case PermError:
						returnErr = smtp.NewError(550, "5.5.2", "Permanent error evaluating SPF policy")
					case Pass, SoftFail, Neutral, None:
						returnErr = nil
					default:
						logger.Error("Unknown SPF evaluation result", "result", finalResult)
						finalResult = TempError
						returnErr = smtp.NewError(451, "4.4.3", "Temporary error during SPF evaluation")
					}
				}
			}
		}
	}

	// Store the final SPF result in context before returning
	ctx = context.WithValue(ctx, ctxkeys.SPFResultKey, StoredSPFResult{Result: finalResult, Domain: domain})

	return returnErr
}

// OnRcptTo is called after RCPT TO command.
func (p *SPFChecker) OnRcptTo(ctx context.Context, session *plugin.SessionInfo, rcptTo string) error {
	// No action needed on RCPT TO for SPF
	return nil
}

// OnData is called before receiving the message data.
func (p *SPFChecker) OnData(ctx context.Context, session *plugin.SessionInfo) error {
	// No action needed on DATA for SPF
	return nil
}

// OnMessage is called after the message data is received.
func (p *SPFChecker) OnMessage(ctx context.Context, session *plugin.SessionInfo, msg *plugin.MessageInfo) error {
	// No action needed after message receipt for SPF
	return nil
}

// OnDisconnect is called when a client disconnects.
func (p *SPFChecker) OnDisconnect(ctx context.Context, session *plugin.SessionInfo) {
	// No cleanup needed for SPF
}

// Ensure SPFChecker implements the Plugin interface
var _ plugin.Plugin = (*SPFChecker)(nil)

// Helper function to get client IP address
func getClientIP(session *plugin.SessionInfo) net.IP {
	if session == nil || session.RemoteAddr == nil {
		return nil
	}
	if tcpAddr, ok := session.RemoteAddr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	if ipAddr, ok := session.RemoteAddr.(*net.IPAddr); ok {
		return ipAddr.IP
	}
	// Use default logger or inject one if this needs logging
	// log.Printf("SPF Check: Unsupported remote address type: %T", session.RemoteAddr)
	slog.Default().Warn("Unsupported remote address type for SPF check", "type", fmt.Sprintf("%T", session.RemoteAddr)) // Requires fmt import
	return nil
}

// SPFResult represents the outcome of an SPF check.
type SPFResult string

const (
	Pass      SPFResult = "Pass"
	Fail      SPFResult = "Fail"
	SoftFail  SPFResult = "SoftFail"
	Neutral   SPFResult = "Neutral"
	TempError SPFResult = "TempError" // Temporary error during processing (e.g., DNS timeout)
	PermError SPFResult = "PermError" // Permanent error in record (e.g., syntax)
	None      SPFResult = "None"      // No SPF record found
)

// evaluateSPF parses and evaluates an SPF record string.
func (p *SPFChecker) evaluateSPF(ctx context.Context, logger *slog.Logger, record string, clientIP net.IP, domain, heloDomain string) (SPFResult, error) {
	parts := strings.Fields(strings.TrimPrefix(strings.ToLower(record), "v=spf1 "))

	for _, part := range parts {
		qualifier := Pass
		mechanism := part

		switch part[0] {
		case '+':
			qualifier = Pass
			mechanism = part[1:]
		case '-':
			qualifier = Fail
			mechanism = part[1:]
		case '~':
			qualifier = SoftFail
			mechanism = part[1:]
		case '?':
			qualifier = Neutral
			mechanism = part[1:]
		}

		// Handle mechanisms
		if strings.HasPrefix(mechanism, "ip4:") {
			cidrStr := strings.TrimPrefix(mechanism, "ip4:")
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				logger.Warn("Invalid ip4 CIDR in SPF record", "cidr", cidrStr, "error", err)
				return PermError, nil // Syntax error
			}
			if clientIP.To4() != nil && ipNet.Contains(clientIP) {
				logger.Debug("SPF matched ip4 mechanism", "mechanism", mechanism, "qualifier", qualifier)
				return qualifier, nil
			}
		} else if strings.HasPrefix(mechanism, "ip6:") {
			cidrStr := strings.TrimPrefix(mechanism, "ip6:")
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				logger.Warn("Invalid ip6 CIDR in SPF record", "cidr", cidrStr, "error", err)
				return PermError, nil // Syntax error
			}
			if clientIP.To16() != nil && clientIP.To4() == nil && ipNet.Contains(clientIP) {
				logger.Debug("SPF matched ip6 mechanism", "mechanism", mechanism, "qualifier", qualifier)
				return qualifier, nil
			}
		} else if mechanism == "all" {
			logger.Debug("SPF matched 'all' mechanism", "qualifier", string(qualifier))
			return qualifier, nil
		} else {
			logger.Warn("Unsupported SPF mechanism encountered", "mechanism", mechanism)
		}
	}

	logger.Debug("No SPF mechanism matched, defaulting to Neutral")
	return Neutral, nil
}

// TODO: Implement evaluateSPF function
// This function would parse the spfRecord string and check mechanisms
// (ip4, ip6, a, mx, ptr, exists, include, all) and qualifiers (+, -, ~, ?).
// It needs to handle recursion for 'include' and 'redirect',
// potential DNS lookup limits, and return an SPF result (Pass, Fail, etc.).

// Note: The actual plugin.SessionInfo and plugin.MessageInfo structures
// would need to be defined in pkg/plugin/plugin.go and provide necessary
// details like RemoteAddr. This implementation assumes such fields exist.
