package spf

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/sirerun/smtpd/pkg/smtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockResolver implements the lookup behavior needed for tests.
type mockResolver struct {
	txtRecords map[string][]string
	lookupErr  map[string]error
}

// LookupTXT satisfies the resolver interface used by the plugin.
func (r *mockResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	if err, exists := r.lookupErr[domain]; exists {
		return nil, err
	}
	if records, exists := r.txtRecords[domain]; exists {
		return records, nil
	}
	// Simulate NXDOMAIN or no TXT records found
	return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
}

var testLogger = logging.New(logging.DefaultConfig())

func TestSPFChecker_OnMailFrom(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		clientIP       string
		heloDomain     string
		mockTXT        map[string][]string
		mockErr        map[string]error
		expectedResult SPFResult
		expectedError  bool
	}{
		{
			name:       "Valid SPF record",
			from:       "sender@example.com",
			clientIP:   "192.0.2.1",
			heloDomain: "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
			},
			expectedResult: Pass,
			expectedError:  false,
		},
		{
			name:       "Invalid SPF record",
			from:       "sender@example.com",
			clientIP:   "203.0.113.1", // IP not in allowed range
			heloDomain: "mail.example.com",
			mockTXT: map[string][]string{
				"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
			},
			expectedResult: Fail,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a custom resolver for testing that returns our mock data
			mockResolver := &mockResolver{
				txtRecords: tt.mockTXT,
				lookupErr:  tt.mockErr,
			}

			// Create our SPF checker with the mock resolver
			checker := &SPFChecker{
				logger:   testLogger,
				resolver: mockResolver,
			}

			clientIP := net.ParseIP(tt.clientIP)
			require.NotNil(t, clientIP)

			sessionInfo := &plugin.SessionInfo{
				SessionID:  "test-session",
				RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
				HeloDomain: tt.heloDomain,
			}

			// Call the method we're testing
			err := checker.OnMailFrom(ctx, sessionInfo, tt.from)

			// Directly test the SPF record evaluation using our mocks
			domain := strings.Split(tt.from, "@")[1]
			record := tt.mockTXT[domain][0]
			result, evalErr := checker.evaluateSPF(ctx, testLogger, record, clientIP, domain, tt.heloDomain)
			require.NoError(t, evalErr, "SPF evaluation should not error")
			assert.Equal(t, tt.expectedResult, result, "SPF evaluation result should match expected")

			// Check for expected error
			if tt.expectedError {
				assert.Error(t, err)
				smtpErr, ok := err.(smtp.Error)
				assert.True(t, ok, "Error should implement smtp.Error interface")
				if tt.expectedResult == Fail {
					assert.Equal(t, 550, smtpErr.Code(), "Should be a 550 error for SPF Fail")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TODO: Add tests for SPF logic, including:
// - Mocking DNS lookups (net.LookupTXT)
// - Testing different SPF results (Pass, Fail, SoftFail, Neutral, TempError, PermError)
// - Testing various mechanisms (a, mx, ip4, ip6, include, all)
// - Testing modifiers (redirect, exp)
// - Handling edge cases (malformed records, empty records, multiple records)
// - Checking domain extraction from 'from' address
