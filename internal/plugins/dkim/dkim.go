package dkim

import (
	"bytes"
	"context"
	"fmt"
	"io" // Added for io.Reader

	"github.com/emersion/go-msgauth/dkim"
	"github.com/mailtive/smtpd/internal/ctxkeys"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/pkg/plugin"
	"github.com/mailtive/smtpd/pkg/smtp"
	// DKIM library will be added here
)

// Define verification function type
type dkimVerifyFunc func(r io.Reader) ([]*dkim.Verification, error)

// DKIMVerifier implements the plugin.Plugin interface for DKIM checks.
type DKIMVerifier struct {
	plugin.BasePlugin
	logger   *logging.Logger
	verifyFn dkimVerifyFunc // Store the verification function
	// Potential configuration: DNS resolver, required result (e.g., must pass vs. informational)
	// resolver *net.Resolver // go-dkim uses its own resolver logic internally by default
}

// NewDKIMVerifier creates a new DKIMVerifier plugin instance.
// It now accepts a verification function dependency.
func NewDKIMVerifier(logger *logging.Logger, verifyFn dkimVerifyFunc) *DKIMVerifier {
	if logger == nil {
		logger = logging.Default()
	}
	if verifyFn == nil { // Default to the actual library function
		verifyFn = dkim.Verify
	}
	return &DKIMVerifier{
		logger:   logger.WithFields(map[string]interface{}{"plugin": "dkim"}),
		verifyFn: verifyFn,
		// resolver: net.DefaultResolver, // Not directly used by go-dkim Verify
	}
}

// Name returns the name of the plugin.
func (p *DKIMVerifier) Name() string {
	return "DKIM Verifier"
}

// OnMessage is called after the message data is received.
func (p *DKIMVerifier) OnMessage(ctx context.Context, session *plugin.SessionInfo, msg *plugin.MessageInfo) error {
	logger := p.logger.WithFields(map[string]interface{}{
		"session_id":  session.SessionID,
		"remote_addr": session.RemoteAddr,
	})
	logger.Info("Performing DKIM verification")

	// Use the stored verification function
	verifications, err := p.verifyFn(bytes.NewReader(msg.Data))
	if err != nil {
		logger.Error("DKIM verification function failed", "error", err)
		// Determine if it's a temporary or permanent failure based on dkim helpers
		if dkim.IsTempFail(err) {
			return smtp.NewError(451, "4.7.0", fmt.Sprintf("Temporary DKIM processing error: %v", err))
		} else {
			// Treat non-temp errors (including perm fail or unknown) as potential config/permanent issues
			// Or potentially return a different code like 550?
			return smtp.NewError(451, "4.7.0", fmt.Sprintf("DKIM processing error: %v", err)) // 4xx for safety
		}
	}

	if len(verifications) == 0 {
		logger.Info("No DKIM signatures found")
		ctx = context.WithValue(ctx, ctxkeys.DKIMResultsKey, []*dkim.Verification{}) // Store empty slice
		return nil
	}

	logger.Info("DKIM signatures found", "count", len(verifications))
	ctx = context.WithValue(ctx, ctxkeys.DKIMResultsKey, verifications) // Store results

	// Check results - fail if *all* signatures are invalid
	oneValid := false
	var firstError error = nil
	for _, v := range verifications {
		if v.Err == nil {
			oneValid = true
			logger.Info("Valid DKIM signature found", "domain", v.Domain)
			break // One valid signature is enough for the message to pass this check
		} else {
			logger.Warn("Invalid DKIM signature", "domain", v.Domain, "error", v.Err)
			if firstError == nil {
				firstError = v.Err // Store the first error encountered
			}
		}
	}

	if !oneValid {
		logger.Warn("No valid DKIM signatures found on the message")
		if firstError == nil {
			firstError = fmt.Errorf("no valid DKIM signatures found") // Should not happen if len > 0
		}

		// Determine failure type based on the first error encountered
		if dkim.IsPermFail(firstError) {
			return smtp.NewError(550, "5.7.24", fmt.Sprintf("DKIM check failed (permanent): %v", firstError))
		} else {
			// Treat TempFail or unknown errors as temporary for SMTP response
			return smtp.NewError(451, "4.7.0", fmt.Sprintf("DKIM check failed (temporary): %v", firstError))
		}
	}

	logger.Info("DKIM verification passed (at least one valid signature)")
	return nil
}

// Ensure DKIMVerifier implements the Plugin interface
var _ plugin.Plugin = (*DKIMVerifier)(nil)
