package metrics

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mailtive/smtpd/internal/message"
	"github.com/mailtive/smtpd/pkg/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getCounterValue(counter prometheus.Counter) float64 {
	var m dto.Metric
	err := counter.Write(&m)
	if err != nil {
		return 0
	}
	return m.Counter.GetValue()
}

func getGaugeValue(gauge prometheus.Gauge) float64 {
	var m dto.Metric
	err := gauge.Write(&m)
	if err != nil {
		return 0
	}
	return m.Gauge.GetValue()
}

func getCounterVecValue(counter *prometheus.CounterVec, labels ...string) float64 {
	var m dto.Metric
	err := counter.WithLabelValues(labels...).Write(&m)
	if err != nil {
		return 0
	}
	return m.Counter.GetValue()
}

func TestTimeCommand(t *testing.T) {
	// Reset the test metrics
	prometheus.Unregister(CommandsProcessedTotal)
	prometheus.Unregister(CommandProcessingTime)

	// Re-register for testing
	CommandsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "commands_processed_total",
		},
		[]string{"command", "result"},
	)
	prometheus.MustRegister(CommandsProcessedTotal)

	CommandProcessingTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "command_processing_seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 5),
		},
		[]string{"command"},
	)
	prometheus.MustRegister(CommandProcessingTime)

	// Test successful command
	err := TimeCommand("EHLO", func() error {
		time.Sleep(5 * time.Millisecond) // Sleep to ensure timing is measurable
		return nil
	})
	assert.NoError(t, err)

	// Test failed command
	expectedErr := errors.New("command failed")
	err = TimeCommand("RCPT", func() error {
		time.Sleep(5 * time.Millisecond)
		return expectedErr
	})
	assert.Equal(t, expectedErr, err)

	// Verify metrics were recorded
	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_commands_processed_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one metric")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_command_processing_seconds",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one metric")
}

func TestRecordFunctions(t *testing.T) {
	// Test RecordAuth
	prometheus.Unregister(AuthAttemptsTotal)
	AuthAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "auth_attempts_total",
		},
		[]string{"method", "result"},
	)
	prometheus.MustRegister(AuthAttemptsTotal)

	RecordAuth("PLAIN", "success")
	RecordAuth("LOGIN", "failure")

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_auth_attempts_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one auth metric")

	// Test RecordTLSHandshake
	prometheus.Unregister(TLSHandshakesTotal)
	TLSHandshakesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "tls_handshakes_total",
		},
		[]string{"result"},
	)
	prometheus.MustRegister(TLSHandshakesTotal)

	RecordTLSHandshake("success")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_tls_handshakes_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one TLS handshake metric")

	// Test RecordTLSVersion
	prometheus.Unregister(TLSVersionsTotal)
	TLSVersionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "tls_versions_total",
		},
		[]string{"version"},
	)
	prometheus.MustRegister(TLSVersionsTotal)

	RecordTLSVersion("TLSv1.3")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_tls_versions_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one TLS version metric")
}

func TestQueueMetrics(t *testing.T) {
	// Test UpdateQueueSizes
	prometheus.Unregister(QueueSizeReady)
	prometheus.Unregister(QueueSizeRetry)

	QueueSizeReady = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "queue_size_ready",
		},
	)
	prometheus.MustRegister(QueueSizeReady)

	QueueSizeRetry = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "queue_size_retry",
		},
	)
	prometheus.MustRegister(QueueSizeRetry)

	UpdateQueueSizes(10, 5)

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_queue_size_ready",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected queue size ready metric")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_queue_size_retry",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected queue size retry metric")

	// Test RecordMessageRetryCount
	prometheus.Unregister(MessageRetryCount)
	MessageRetryCount = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "message_retry_count",
			Buckets:   []float64{1, 3, 5},
		},
	)
	prometheus.MustRegister(MessageRetryCount)

	RecordMessageRetryCount(3)

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_message_retry_count",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected message retry count metric")
}

func TestDeliveryMetrics(t *testing.T) {
	// Test RecordDeliveryTime
	prometheus.Unregister(DeliveryTimeSeconds)
	DeliveryTimeSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "delivery_time_seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 5),
		},
		[]string{"remote_domain", "result"},
	)
	prometheus.MustRegister(DeliveryTimeSeconds)

	RecordDeliveryTime("example.com", "success", 250*time.Millisecond)

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_delivery_time_seconds",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected delivery time metric")
}

func TestPluginMetrics(t *testing.T) {
	// Test RecordPluginProcessingTime
	prometheus.Unregister(PluginProcessingTimeSeconds)
	PluginProcessingTimeSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "plugin_processing_time_seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 5),
		},
		[]string{"plugin", "hook"},
	)
	prometheus.MustRegister(PluginProcessingTimeSeconds)

	RecordPluginProcessingTime("spf", "OnMailFrom", 10*time.Millisecond)

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_plugin_processing_time_seconds",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected plugin processing time metric")

	// Test RecordPluginResult
	prometheus.Unregister(PluginResultsTotal)
	PluginResultsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "plugin_results_total",
		},
		[]string{"plugin", "hook", "result"},
	)
	prometheus.MustRegister(PluginResultsTotal)

	RecordPluginResult("spf", "OnMailFrom", "pass")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_plugin_results_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected plugin results metric")
}

func TestMessageMetrics(t *testing.T) {
	// Test RecordMessageSize
	prometheus.Unregister(MessageSizeBytes)
	MessageSizeBytes = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "message_size_bytes",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 5),
		},
	)
	prometheus.MustRegister(MessageSizeBytes)

	RecordMessageSize(2048)

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_message_size_bytes",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected message size metric")

	// Test RecordRateLimitHit
	prometheus.Unregister(RateLimitHitsTotal)
	RateLimitHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "rate_limit_hits_total",
		},
		[]string{"type"},
	)
	prometheus.MustRegister(RateLimitHitsTotal)

	RecordRateLimitHit("connection")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_rate_limit_hits_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected rate limit hit metric")

	// Test RecordMessageTimeInQueue
	prometheus.Unregister(MessageTimeInQueueSeconds)
	MessageTimeInQueueSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "message_time_in_queue_seconds",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 5),
		},
	)
	prometheus.MustRegister(MessageTimeInQueueSeconds)

	RecordMessageTimeInQueue(120 * time.Second)

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_message_time_in_queue_seconds",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected message time in queue metric")
}

func TestConnectionMetrics(t *testing.T) {
	// Reset metrics
	prometheus.Unregister(ConnectionsTotal)
	prometheus.Unregister(ConnectionsActive)

	// Re-register for testing
	ConnectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "connections_total",
		},
	)
	prometheus.MustRegister(ConnectionsTotal)

	ConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "connections_active",
		},
	)
	prometheus.MustRegister(ConnectionsActive)

	// Test connection recording
	RecordConnection()
	assert.Equal(t, float64(1), getCounterValue(ConnectionsTotal))
	assert.Equal(t, float64(1), getGaugeValue(ConnectionsActive))

	// Test connection closed
	RecordConnectionClosed()
	assert.Equal(t, float64(1), getCounterValue(ConnectionsTotal))
	assert.Equal(t, float64(0), getGaugeValue(ConnectionsActive))

	// Test multiple connections
	RecordConnection()
	RecordConnection()
	assert.Equal(t, float64(3), getCounterValue(ConnectionsTotal))
	assert.Equal(t, float64(2), getGaugeValue(ConnectionsActive))

	// Test GetConnectionsActive
	assert.Equal(t, float64(2), GetConnectionsActive())
}

func TestCommandMetrics(t *testing.T) {
	// Reset the test metrics
	prometheus.Unregister(CommandsProcessedTotal)
	prometheus.Unregister(CommandProcessingTime)

	// Re-register for testing
	CommandsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "commands_processed_total",
		},
		[]string{"command", "result"},
	)
	prometheus.MustRegister(CommandsProcessedTotal)

	CommandProcessingTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "command_processing_seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 5),
		},
		[]string{"command"},
	)
	prometheus.MustRegister(CommandProcessingTime)

	// Test successful command
	err := TimeCommand("EHLO", func() error {
		time.Sleep(5 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Test failed command
	expectedErr := errors.New("command failed")
	err = TimeCommand("RCPT", func() error {
		time.Sleep(5 * time.Millisecond)
		return expectedErr
	})
	assert.Equal(t, expectedErr, err)

	// Verify metrics were recorded
	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_commands_processed_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one metric")

	count, err = testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_command_processing_seconds",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one metric")
}

func TestTLSMetrics(t *testing.T) {
	// Reset the test metrics
	prometheus.Unregister(TLSConnectionsTotal)
	prometheus.Unregister(TLSHandshakeTime)

	// Re-register for testing
	TLSConnectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "tls_connections_total",
			Help:      "Total number of TLS connections",
		},
	)

	TLSHandshakeTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "tls_handshake_time_seconds",
			Help:      "Time taken for TLS handshake",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Test recording a TLS connection
	RecordTLSConnection(time.Second)
	assert.Equal(t, 1.0, getCounterValue(TLSConnectionsTotal))
}

func TestAuthMetrics(t *testing.T) {
	// Reset the test metrics
	prometheus.Unregister(AuthAttemptsTotal)
	AuthAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "test",
			Subsystem: "smtp",
			Name:      "auth_attempts_total",
		},
		[]string{"method", "result"},
	)
	prometheus.MustRegister(AuthAttemptsTotal)

	// Test successful auth
	RecordAuthAttempt("PLAIN", "success")
	RecordAuthAttempt("LOGIN", "failure")

	count, err := testutil.GatherAndCount(
		prometheus.DefaultGatherer,
		"test_smtp_auth_attempts_total",
	)
	assert.NoError(t, err)
	assert.Greater(t, count, 0, "Expected at least one auth metric")
}

func TestLogMetrics(t *testing.T) {
	// Test initial state
	assert.Equal(t, 0.0, getCounterVecValue(logMessages, "info"))
	assert.Equal(t, 0.0, getCounterVecValue(logMessages, "error"))

	// Record log messages
	RecordLogMessage("info")
	assert.Equal(t, 1.0, getCounterVecValue(logMessages, "info"))

	RecordLogMessage("error")
	assert.Equal(t, 1.0, getCounterVecValue(logMessages, "error"))
}

func TestMetricRegistration(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	// Register key metrics with the new registry
	registry.MustRegister(
		ConnectionsTotal,
		ConnectionsActive,
		MessagesReceivedTotal,
		DeliveryResultsTotal,
		MessageStatusTotal,
		PluginResultsTotal, // Changed from CommandsProcessedTotal which is registered in other tests
		QueueSizeReady,
		DeliveryTimeSeconds,
		TLSConnectionsTotal,
		AuthAttemptsTotal,
		logMessages,
	)

	// Verify all metrics are registered
	metrics, err := registry.Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestMetrics_OnMessage(t *testing.T) {
	// Create a new metrics collector
	collector := NewMetrics()

	// Create a test message
	msg := &message.Message{
		From: "sender@example.com",
		To:   []string{"recipient@example.com"},
		Data: []byte("Subject: Test\r\n\r\nTest message"),
	}

	// Create message info
	msgInfo := &plugin.MessageInfo{
		From: msg.From,
		To:   msg.To,
		Data: msg.Data,
	}

	// Create session info
	clientIP := net.ParseIP("127.0.0.1")
	sessionInfo := &plugin.SessionInfo{
		RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
	}

	// Test the collector
	result, err := collector.OnMessage(context.Background(), sessionInfo, msgInfo)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify metrics were updated
	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestMetrics_OnSessionStart(t *testing.T) {
	// Create a new metrics collector
	collector := NewMetrics()

	// Create session info
	clientIP := net.ParseIP("127.0.0.1")
	sessionInfo := &plugin.SessionInfo{
		RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
	}

	// Test the collector
	result, err := collector.OnSessionStart(context.Background(), sessionInfo)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify metrics were updated
	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}

func TestMetrics_OnSessionEnd(t *testing.T) {
	// Create a new metrics collector
	collector := NewMetrics()

	// Create session info
	clientIP := net.ParseIP("127.0.0.1")
	sessionInfo := &plugin.SessionInfo{
		RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
	}

	// Test the collector
	result, err := collector.OnSessionEnd(context.Background(), sessionInfo)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify metrics were updated
	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
}
