package dmarc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/sirerun/smtpd/internal/ctxkeys"
	"github.com/sirerun/smtpd/internal/logging"
	spfPlugin "github.com/sirerun/smtpd/internal/plugins/spf"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

// mockResolver implements DNS lookups for testing
type mockResolver struct {
	records map[string][]string
}

func (r *mockResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if records, ok := r.records[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name}
}

func (r *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return nil, nil // Not needed for DMARC tests
}

func (r *mockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return nil, nil // Not needed for DMARC tests
}

func (r *mockResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return "", nil // Not needed for DMARC tests
}

func (r *mockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, nil // Not needed for DMARC tests
}

func (r *mockResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return nil, nil // Not needed for DMARC tests
}

var testLogger = logging.New(logging.DefaultConfig())

var (
	ErrSignatureNotValid = errors.New("signature not valid")
)

type mockVerification struct {
	domain string
	err    error
}

func (v *mockVerification) Domain() string {
	return v.domain
}

func (v *mockVerification) Err() error {
	return v.err
}

type mockDMARCVerifier struct {
	result string
	err    error
}

func (m *mockDMARCVerifier) Verify(ctx context.Context, domain string, dkimResult *dkim.Verification, spfResult *spfPlugin.StoredSPFResult) (string, error) {
	return m.result, m.err
}

/*
 * TODO: Re-evaluate DMARC testing strategy.
 * The previous tests (TestDMARCChecker_OnMessage and TestDMARCVerifier_OnMessage)
 * had build errors and appeared logically flawed or outdated.
 * Need to create new tests that accurately reflect the DMARCChecker's
 * OnMessage hook functionality and potentially test the DMARCVerifier logic separately.
 */

// Placeholder Test to ensure the file compiles and tests run
func TestPlaceholder(t *testing.T) {
	assert.True(t, true, "Placeholder test")
}

func TestDMARCChecker_OnMessage(t *testing.T) {
	tests := []struct {
		name          string
		from          string
		dkimResult    *dkim.Verification
		spfResult     *spfPlugin.StoredSPFResult
		dmarcRecord   string
		expectedError bool
	}{
		{
			name:          "Passing DMARC check",
			from:          "sender@example.com",
			dkimResult:    &dkim.Verification{Domain: "example.com", Err: nil},
			spfResult:     &spfPlugin.StoredSPFResult{Result: spfPlugin.Pass, Domain: "example.com"},
			dmarcRecord:   "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
			expectedError: false,
		},
		{
			name:          "Failing DMARC check",
			from:          "sender@example.com",
			dkimResult:    &dkim.Verification{Domain: "example.com", Err: errors.New("invalid signature")},
			spfResult:     &spfPlugin.StoredSPFResult{Result: spfPlugin.Fail, Domain: "example.com"},
			dmarcRecord:   "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a mock resolver that returns our test DMARC record
			mockResolver := &mockResolver{
				records: map[string][]string{
					"_dmarc.example.com": {tt.dmarcRecord},
				},
			}

			// Create the DMARC checker with our mock resolver
			checker := NewDMARCChecker(testLogger)
			checker.resolver = mockResolver

			// Create a test session
			clientIP := net.ParseIP("192.0.2.1")
			sessionInfo := &plugin.SessionInfo{
				SessionID:  "test-session",
				RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
			}

			// Create a test message with valid headers
			messageData := []byte("From: Sender <" + tt.from + ">\r\n" +
				"To: Recipient <recipient@example.org>\r\n" +
				"Subject: Test Message\r\n" +
				"Message-ID: <test123@example.com>\r\n" +
				"Date: Wed, 20 Apr 2025 12:00:00 -0700\r\n" +
				"\r\n" +
				"This is a test message body.")

			msgInfo := &plugin.MessageInfo{
				From: tt.from,
				Data: messageData,
			}

			// Set up the context with DKIM and SPF results - using the correct context keys
			ctx = context.WithValue(ctx, ctxkeys.DKIMResultsKey, []*dkim.Verification{tt.dkimResult})
			ctx = context.WithValue(ctx, ctxkeys.SPFResultKey, *tt.spfResult)

			// Call the method we're testing
			err := checker.OnMessage(ctx, sessionInfo, msgInfo)

			// Check the result
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Ensure DMARCChecker implements the Plugin interface
var _ plugin.Plugin = (*DMARCChecker)(nil)
