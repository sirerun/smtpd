package outbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirerun/smtpd/internal/message"
)

// --- Tests ---

func TestDeliverer_Deliver_MXLookup(t *testing.T) {
	ctx := context.Background()
	mockRes := new(mockResolver)
	mockPool := new(mockSmtpClientPool)
	mockMetrics := newMockMetricsRecorder() // Using newMockMetricsRecorder() factory
	mockLogger := newMockLogger()

	// Setup mock resolver for different domains
	mockRes.mxRecords = map[string][]*net.MX{
		"remote.com": {
			{Host: "mx.remote.com", Pref: 10},
		},
		"another-remote.com": {
			{Host: "mx.another-remote.com", Pref: 10},
		},
	}
	mockRes.lookupErr = map[string]error{
		"fail-lookup.com": errors.New("lookup failed"),
	}

	deliverer, err := NewDeliverer(
		[]string{"local.com"},
		nil,
		"test-helo",
		mockRes,
		mockPool,
		mockLogger,
		mockMetrics,
	)
	require.NoError(t, err)

	msg := &message.Message{
		ID:   "test-mx-msg-1",
		From: "sender@origin.com",
		To: []string{
			"rcpt1@remote.com",
			"rcpt2@local.com",
			"rcpt3@no-mx.com",
			"rcpt4@fail-lookup.com",
			"rcpt5@another-remote.com",
		},
		Data: []byte("Subject: Test MX\r\n\r\nHello."),
	}

	err = deliverer.Deliver(ctx, msg)
	assert.NoError(t, err, "Deliver method should not return an error even if individual deliveries fail")

	assert.GreaterOrEqual(t, mockMetrics.statuses["mx_lookup_perm_failed_fail-lookup.com"], 1)
	assert.GreaterOrEqual(t, mockMetrics.statuses["no_mx_records_no-mx.com"], 1)
	assert.GreaterOrEqual(t, mockMetrics.statuses["delivery_perm_failed_mx_remote.com"], 1)
	assert.GreaterOrEqual(t, mockMetrics.statuses["delivery_perm_failed_domain_remote.com"], 1)
	assert.GreaterOrEqual(t, mockMetrics.statuses["delivery_perm_failed_mx_another-remote.com"], 1)
}

func TestDeliverer_Deliver(t *testing.T) {
	ctx := context.Background()
	localDomains := []string{"local.com"}
	mockRes := new(mockResolver)
	mockPool := new(mockSmtpClientPool)
	mockMetrics := newMockMetricsRecorder() // Using factory instead of new()
	mockLogger := newMockLogger()

	// Setup mock resolver for MX records
	mockRes.mxRecords = map[string][]*net.MX{
		"remote.com": {
			{Host: "mx.remote.com", Pref: 10},
		},
		"another-remote.com": {
			{Host: "mx.another-remote.com", Pref: 10},
		},
	}

	deliverer, err := NewDeliverer(
		localDomains,
		nil,
		"test-helo",
		mockRes,
		mockPool,
		mockLogger,
		mockMetrics,
	)
	require.NoError(t, err)

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

	err = deliverer.Deliver(ctx, msg)
	assert.NoError(t, err, "Delivery should succeed with mock client")

	assert.Equal(t, 1, mockMetrics.statuses["delivered_remote.com"])
	assert.Equal(t, 1, mockMetrics.statuses["delivered_another-remote.com"])

	require.Contains(t, mockPool.clients, "mx.remote.com")
	require.Contains(t, mockPool.clients, "mx.another-remote.com")
	assert.True(t, mockPool.clients["mx.remote.com"][0].wasReleased)
	assert.True(t, mockPool.clients["mx.another-remote.com"][0].wasReleased)

	client1 := mockPool.clients["mx.remote.com"][0]
	calls1 := client1.GetSendCalls()
	require.Len(t, calls1, 1)
	assert.ElementsMatch(t, []string{"rcpt1@remote.com", "rcpt3@remote.com"}, calls1[0].To)

	client2 := mockPool.clients["mx.another-remote.com"][0]
	calls2 := client2.GetSendCalls()
	require.Len(t, calls2, 1)
	assert.ElementsMatch(t, []string{"rcpt4@another-remote.com"}, calls2[0].To)
}

func TestDeliverer_isLocal(t *testing.T) {
	// Use a mock logger instead of trying to create one from a non-existent Config
	mockLogger := newMockLogger()
	mockRes := &mockResolver{
		mxRecords: map[string][]*net.MX{},
		lookupErr: map[string]error{},
	}
	mockMetrics := newMockMetricsRecorder()
	
	deliverer, err := NewDeliverer(
		[]string{"example.com", " DOMAIN.NET ", " Test.ORG "},
		nil, "test-helo", mockRes, nil, mockLogger, mockMetrics,
	)
	require.NoError(t, err)

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
	ctx := context.Background()
	testKey := loadTestPrivateKey(t)

	dkimConfigs := map[string]DKIMSignerOptions{
		"sign-this.com": {
			Domain:     "sign-this.com",
			Selector:   "test",
			PrivateKey: testKey,
		},
	}

	mockRes := new(mockResolver)
	mockPool := new(mockSmtpClientPool)
	mockMetrics := newMockMetricsRecorder() // Using the factory function for proper initialization
	mockLogger := newMockLogger()

	// Setup mock resolver
	mockRes.mxRecords = map[string][]*net.MX{
		"remote.com": {
			{Host: "mx.remote.com", Pref: 10},
		},
		"other-remote.com": {
			{Host: "mx.other-remote.com", Pref: 10},
		},
	}

	deliverer, err := NewDeliverer(
		[]string{},
		dkimConfigs,
		"test-helo",
		mockRes,
		mockPool,
		mockLogger,
		mockMetrics,
	)
	require.NoError(t, err)

	msg1 := &message.Message{
		ID:   "dkim-sign-1",
		From: "sender@sign-this.com",
		To:   []string{"rcpt@remote.com"},
		Data: []byte("Subject: Sign Me\r\n\r\nBody 1"),
	}

	msg2 := &message.Message{
		ID:   "dkim-nosign-1",
		From: "sender@no-sign.com",
		To:   []string{"rcpt@other-remote.com"},
		Data: []byte("Subject: Do Not Sign Me\r\n\r\nBody 2"),
	}

	err1 := deliverer.Deliver(ctx, msg1)
	assert.NoError(t, err1, "Message 1 delivery should succeed")
	err2 := deliverer.Deliver(ctx, msg2)
	assert.NoError(t, err2, "Message 2 delivery should succeed")

	require.Contains(t, mockPool.clients, "mx.remote.com")
	require.Contains(t, mockPool.clients, "mx.other-remote.com")

	client1 := mockPool.clients["mx.remote.com"][0]
	calls1 := client1.GetSendCalls()
	require.Len(t, calls1, 1, "Expected 1 call for msg1")
	call1 := calls1[0]
	assert.Equal(t, msg1.From, call1.From)
	assert.Contains(t, string(call1.Msg), "DKIM-Signature:", "Message 1 should contain DKIM-Signature header")
	assert.Contains(t, string(call1.Msg), "d=sign-this.com", "DKIM header should have correct domain")
	assert.Contains(t, string(call1.Msg), "s=test", "DKIM header should have correct selector")
	assert.True(t, bytes.HasSuffix(call1.Msg, []byte("\r\nBody 1")), "Signed message should end with original body (check CRLF)")

	client2 := mockPool.clients["mx.other-remote.com"][0]
	calls2 := client2.GetSendCalls()
	require.Len(t, calls2, 1, "Expected 1 call for msg2")
	call2 := calls2[0]
	assert.Equal(t, msg2.From, call2.From)
	assert.NotContains(t, string(call2.Msg), "DKIM-Signature:", "Message 2 should NOT contain DKIM-Signature header")
	assert.True(t, bytes.HasSuffix(call2.Msg, []byte("\r\nBody 2")), "Unsigned message should end with original body (check CRLF)")

	assert.Equal(t, 1, mockMetrics.statuses["delivered_remote.com"])
	assert.Equal(t, 1, mockMetrics.statuses["delivered_other-remote.com"])
}
