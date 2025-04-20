package outbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	//	"crypto/tls"
	//	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	//	"strings"
	"sync"
	"testing"
	//	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mailtive/smtpd/internal/message"
)

// mockResolver implements the resolver interface for testing DNS lookups.
type mockResolver struct {
	mxRecords map[string][]*net.MX
	lookupErr map[string]error
}

func (r *mockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err, exists := r.lookupErr[name]; exists {
		return nil, err
	}
	if records, exists := r.mxRecords[name]; exists {
		// Return a copy to prevent modification by sorting
		recordsCopy := make([]*net.MX, len(records))
		copy(recordsCopy, records)
		return recordsCopy, nil
	}
	// Simulate no records found (not an error per se for LookupMX)
	return []*net.MX{}, nil
}

// mockSmtpClient implements the smtpClient interface for testing SendMail calls.
type mockSmtpClient struct {
	sendMailFunc func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
	mu           sync.Mutex
	calls        []SendMailCall // Store details of each call
}

// SendMailCall stores arguments passed to SendMail.
type SendMailCall struct {
	Addr string
	Auth smtp.Auth
	From string
	To   []string
	Msg  []byte // Captured message data
}

func (sc *mockSmtpClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	sc.mu.Lock()
	// Capture a copy of the message data
	msgCopy := make([]byte, len(msg))
	copy(msgCopy, msg)
	sc.calls = append(sc.calls, SendMailCall{Addr: addr, Auth: a, From: from, To: to, Msg: msgCopy})
	sc.mu.Unlock()

	if sc.sendMailFunc != nil {
		return sc.sendMailFunc(addr, a, from, to, msg)
	}
	return nil // Default mock success
}

func (sc *mockSmtpClient) GetCalls() []SendMailCall {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	// Return a copy of the slice
	callsCopy := make([]SendMailCall, len(sc.calls))
	copy(callsCopy, sc.calls)
	return callsCopy
}

// --- Helper ---
var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

// --- Tests ---

func TestDeliverer_Deliver_MXLookup(t *testing.T) {
	// Setup mock resolver
	mockRes := &mockResolver{
		mxRecords: map[string][]*net.MX{
			"remote.com": {
				{Host: "mx2.remote.com.", Pref: 20},
				{Host: "mx1.remote.com.", Pref: 10},
			},
			"another-remote.com": {
				{Host: "mx.another-remote.com.", Pref: 10},
			},
			"no-mx.com": {}, // Explicitly no MX records
		},
		lookupErr: map[string]error{
			"fail-lookup.com": fmt.Errorf("dns lookup failed"),
		},
	}

	deliverer := NewDeliverer([]string{"local.com"}, nil, "test-helo", testLogger)
	deliverer = deliverer.withResolver(mockRes) // Inject mock resolver

	msg := &message.Message{
		ID:   "test-mx-msg-1",
		From: "sender@origin.com",
		To: []string{
			"rcpt1@remote.com",         // Should lookup MX
			"rcpt2@local.com",          // Should skip (local)
			"rcpt3@no-mx.com",          // Should lookup, find none
			"rcpt4@fail-lookup.com",    // Should fail lookup
			"rcpt5@another-remote.com", // Should lookup MX
		},
		Data: []byte("Subject: Test MX\r\n\r\nHello."),
	}

	deliveryStatus := deliverer.Deliver(msg)

	// Assertions on the returned status map
	assert.Contains(t, deliveryStatus, "remote.com")
	assert.Equal(t, DeliveryPermFail, deliveryStatus["remote.com"].Result, "Should default to PermFail as SendMail not mocked to succeed")

	assert.Contains(t, deliveryStatus, "local.com")
	assert.Equal(t, DeliverySuccess, deliveryStatus["local.com"].Result)

	assert.Contains(t, deliveryStatus, "no-mx.com")
	assert.Equal(t, DeliveryPermFail, deliveryStatus["no-mx.com"].Result)
	assert.Contains(t, deliveryStatus["no-mx.com"].Detail, "No MX records")

	assert.Contains(t, deliveryStatus, "fail-lookup.com")
	assert.Equal(t, DeliveryPermFail, deliveryStatus["fail-lookup.com"].Result)
	assert.Contains(t, deliveryStatus["fail-lookup.com"].Detail, "Permanent DNS error")

	assert.Contains(t, deliveryStatus, "another-remote.com")
	assert.Equal(t, DeliveryPermFail, deliveryStatus["another-remote.com"].Result)
}

func TestDeliverer_Deliver(t *testing.T) {
	localDomains := []string{"local.com"}
	deliverer := NewDeliverer(localDomains, nil, "test-helo", testLogger)
	deliverer = deliverer.withResolver(&mockResolver{})
	deliverer = deliverer.withSmtpClient(&mockSmtpClient{})

	msg := &message.Message{
		ID:   "test-msg-1",
		From: "sender@origin.com",
		To: []string{
			"rcpt1@remote.com",
			"rcpt2@local.com",
			"rcpt3@remote.com",
			"invalid-recipient",
			"rcpt4@another-remote.com",
		},
		Data: []byte("Subject: Test Outbound\r\n\r\nHello world."),
	}

	deliveryStatus := deliverer.Deliver(msg)
	assert.NotEmpty(t, deliveryStatus) // Basic check
}

func TestDeliverer_isLocal(t *testing.T) {
	deliverer := NewDeliverer([]string{"example.com", " DOMAIN.NET ", " Test.ORG "}, nil, "", testLogger)

	assert.True(t, deliverer.isLocal("example.com"))
	assert.True(t, deliverer.isLocal("EXAMPLE.com"))
	assert.True(t, deliverer.isLocal("domain.net"))
	assert.True(t, deliverer.isLocal("DOMAIN.net"))
	assert.True(t, deliverer.isLocal("test.org"))

	assert.False(t, deliverer.isLocal("sub.example.com"))
	assert.False(t, deliverer.isLocal("example.org"))
	assert.False(t, deliverer.isLocal(""))
	assert.False(t, deliverer.isLocal("gmail.com"))
}

func TestDeliverer_Deliver_DKIMSigning(t *testing.T) {
	// Generate a test RSA key (in real tests, load from fixture or mock crypto.Signer)
	testKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Failed to generate test RSA key")

	// Setup DKIM config
	dkimConfigs := map[string]DKIMSignerOptions{
		"sign-this.com": {
			Domain:     "sign-this.com",
			Selector:   "test",
			PrivateKey: testKey,
		},
	}

	// Setup mocks
	mockRes := &mockResolver{
		mxRecords: map[string][]*net.MX{
			"remote.com":       {{Host: "mx.remote.com", Pref: 10}},
			"other-remote.com": {{Host: "mx.other-remote.com", Pref: 10}},
		},
	}
	mockSMTP := &mockSmtpClient{}

	deliverer := NewDeliverer([]string{}, dkimConfigs, "test-helo", testLogger)
	deliverer = deliverer.withResolver(mockRes)
	deliverer = deliverer.withSmtpClient(mockSMTP)

	// Message 1: Should be signed
	msg1 := &message.Message{
		ID:   "dkim-sign-1",
		From: "sender@sign-this.com",
		To:   []string{"rcpt@remote.com"},
		Data: []byte("Subject: Sign Me\r\n\r\nBody 1"),
	}

	// Message 2: Should NOT be signed
	msg2 := &message.Message{
		ID:   "dkim-nosign-1",
		From: "sender@no-sign.com",
		To:   []string{"rcpt@other-remote.com"},
		Data: []byte("Subject: Do Not Sign Me\r\n\r\nBody 2"),
	}

	// Deliver messages
	status1 := deliverer.Deliver(msg1)
	status2 := deliverer.Deliver(msg2)

	// Assertions
	assert.Equal(t, DeliverySuccess, status1["remote.com"].Result, "Msg1 delivery should succeed (mock)")
	assert.Equal(t, DeliverySuccess, status2["other-remote.com"].Result, "Msg2 delivery should succeed (mock)")

	smtpCalls := mockSMTP.GetCalls()
	require.Len(t, smtpCalls, 2, "Expected 2 calls to SendMail")

	// Check msg1 call (should be signed)
	call1 := smtpCalls[0]
	assert.Equal(t, msg1.From, call1.From)
	assert.Equal(t, "mx.remote.com:25", call1.Addr)
	assert.Contains(t, string(call1.Msg), "DKIM-Signature:", "Message 1 should contain DKIM-Signature header")
	assert.Contains(t, string(call1.Msg), "d=sign-this.com", "DKIM header should have correct domain")
	assert.Contains(t, string(call1.Msg), "s=test", "DKIM header should have correct selector")
	assert.True(t, bytes.HasSuffix(call1.Msg, []byte("Body 1")), "Signed message should end with original body")

	// Check msg2 call (should be unsigned)
	call2 := smtpCalls[1]
	assert.Equal(t, msg2.From, call2.From)
	assert.Equal(t, "mx.other-remote.com:25", call2.Addr)
	assert.NotContains(t, string(call2.Msg), "DKIM-Signature:", "Message 2 should NOT contain DKIM-Signature header")
	// Ensure original data is passed
	assert.Equal(t, msg2.Data, call2.Msg, "Message 2 data should be unchanged")
}
