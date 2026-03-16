package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

// Namespace for all metrics.
const namespace = "smtpd"

var (
	// --- Connection Metrics ---
	ConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "server",
		Name:      "connections_total",
		Help:      "Total number of client connections accepted since server start.",
	})
	ConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "server",
		Name:      "connections_active",
		Help:      "Number of currently active client connections.",
	})

	// --- SMTP Command Metrics ---
	CommandsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "commands_processed_total",
			Help:      "Total number of SMTP commands processed",
		},
		[]string{"command", "result"},
	)

	CommandProcessingTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "command_processing_time_seconds",
			Help:      "Time taken to process SMTP commands",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"command"},
	)

	// --- Authentication Metrics ---
	AuthAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "auth",
		Name:      "attempts_total",
		Help:      "Total number of authentication attempts.",
	}, []string{"method", "result"}) // Labeled by auth method (PLAIN, LOGIN) and result (success, failure)

	// --- TLS Metrics ---
	TLSConnectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "tls_connections_total",
			Help:      "Total number of TLS connections",
		},
	)

	TLSHandshakeTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "tls_handshake_time_seconds",
			Help:      "Time taken for TLS handshake",
			Buckets:   prometheus.DefBuckets,
		},
	)

	TLSHandshakesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "tls_handshakes_total",
			Help:      "Total number of TLS handshakes by result",
		},
		[]string{"result"},
	)

	TLSVersionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "server",
			Name:      "tls_versions_total",
			Help:      "Total number of TLS connections by version",
		},
		[]string{"version"},
	)

	// --- Message Reception Metrics ---
	MessagesReceivedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "server",
		Name:      "messages_received_total",
		Help:      "Total number of messages received (after DATA command) and enqueued.",
	})

	MessageSizeBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "server",
		Name:      "message_size_bytes",
		Help:      "Size distribution of received messages in bytes.",
		Buckets:   prometheus.ExponentialBuckets(1024, 2, 10), // From 1KB to ~1MB
	})

	// --- Message Delivery Metrics ---
	DeliveryAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "delivery",
		Name:      "attempts_total",
		Help:      "Total number of delivery attempts per remote domain.",
	}, []string{"remote_domain"}) // Labeled by remote domain

	DeliveryResultsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "delivery",
		Name:      "results_total",
		Help:      "Total count of final delivery results (success, tempfail, permfail) per remote domain.",
	}, []string{"remote_domain", "result"}) // Labeled by remote domain and result (success, tempfail, permfail)

	DeliveryTimeSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "delivery",
		Name:      "time_seconds",
		Help:      "Time taken to deliver messages.",
		Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // From 100ms to ~100s
	}, []string{"remote_domain", "result"}) // Labeled by remote domain and result

	// --- Queue Metrics ---
	QueueSizeReady = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "queue",
		Name:      "size_ready",
		Help:      "Number of messages currently in the ready queue buffer.",
	})
	QueueSizeRetry = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "queue",
		Name:      "size_retry",
		Help:      "Number of messages currently waiting in the retry heap.",
	})
	MessageRetryCount = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "queue",
		Name:      "message_retry_count",
		Help:      "Distribution of retry counts for messages in the queue.",
		Buckets:   []float64{1, 2, 3, 5, 8, 13, 21, 34},
	})
	MessageTimeInQueueSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "queue",
		Name:      "message_time_in_queue_seconds",
		Help:      "Time messages spend in the queue before final delivery or expiry.",
		Buckets:   prometheus.ExponentialBuckets(60, 2, 10), // From 1min to ~17hrs
	})

	// --- Plugin Metrics ---
	PluginProcessingTimeSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "plugin",
		Name:      "processing_time_seconds",
		Help:      "Time taken by plugins to process hooks.",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10), // From 1ms to ~1s
	}, []string{"plugin", "hook"}) // Labeled by plugin name and hook (OnMailFrom, OnRcptTo, etc.)

	PluginResultsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "plugin",
		Name:      "results_total",
		Help:      "Results from plugin processing.",
	}, []string{"plugin", "hook", "result"}) // Labeled by plugin, hook, and result (accept, reject, etc.)

	// --- Rate Limiting Metrics ---
	RateLimitHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "ratelimit",
		Name:      "hits_total",
		Help:      "Total number of rate limit hits by type.",
	}, []string{"type"}) // Labeled by type (connection, message, etc.)

	// --- Message Status Metrics ---
	MessageStatusTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "message",
			Name:      "status_total",
			Help:      "Total number of messages by status (received, delivered, bounced, etc.)",
		},
		[]string{"status"}, // Labeled by status: received, delivered, bounced, rejected, deferred, failed
	)

	MessageStatusByDomain = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "message",
			Name:      "status_by_domain_total",
			Help:      "Total number of messages by status and domain",
		},
		[]string{"status", "domain"},
	)

	MessageStatusBySize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "message",
			Name:      "status_by_size_bytes",
			Help:      "Message size distribution by status",
			Buckets:   prometheus.ExponentialBuckets(1024, 2, 10), // From 1KB to ~1MB
		},
		[]string{"status"},
	)

	MessageStatusByTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "message",
			Name:      "status_by_time_seconds",
			Help:      "Time taken to process messages by status",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // From 100ms to ~100s
		},
		[]string{"status"},
	)

	// --- Bounce Metrics ---
	BounceReasonTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "bounce",
			Name:      "reason_total",
			Help:      "Total number of bounces by reason",
		},
		[]string{"reason"}, // Labeled by reason: user_unknown, mailbox_full, etc.
	)

	BounceTimeToBounce = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "bounce",
			Name:      "time_to_bounce_seconds",
			Help:      "Time taken from message receipt to bounce",
			Buckets:   prometheus.ExponentialBuckets(60, 2, 10), // From 1min to ~17hrs
		},
	)

	// --- Rejection Metrics ---
	RejectionReasonTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "rejection",
			Name:      "reason_total",
			Help:      "Total number of rejections by reason",
		},
		[]string{"reason"}, // Labeled by reason: spam, policy, etc.
	)

	// --- Deferral Metrics ---
	DeferralReasonTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "deferral",
			Name:      "reason_total",
			Help:      "Total number of deferrals by reason",
		},
		[]string{"reason"}, // Labeled by reason: temporary_failure, queue_full, etc.
	)

	DeferralRetryCount = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "deferral",
			Name:      "retry_count",
			Help:      "Number of retry attempts for deferred messages",
			Buckets:   []float64{1, 2, 3, 5, 8, 13, 21, 34},
		},
	)

	// --- Log Message Metrics ---
	logMessages = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "log",
			Name:      "messages_total",
			Help:      "Total number of log messages by level.",
		},
		[]string{"level"},
	)
)

func init() {
	prometheus.MustRegister(
		CommandsProcessedTotal,
		CommandProcessingTime,
		TLSConnectionsTotal,
		TLSHandshakeTime,
	)
}

// TimeCommand times the execution of an SMTP command and records the duration in Prometheus
func TimeCommand(command string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	// Determine the result based on the error
	result := "success"
	if err != nil {
		result = "failure"
	}

	CommandsProcessedTotal.WithLabelValues(command, result).Inc()
	CommandProcessingTime.WithLabelValues(command).Observe(duration.Seconds())

	return err
}

// RecordAuth records an authentication attempt
func RecordAuth(method, result string) {
	AuthAttemptsTotal.WithLabelValues(method, result).Inc()
}

// RecordTLSConnection records a TLS connection event
func RecordTLSConnection(duration time.Duration) {
	TLSConnectionsTotal.Inc()
	TLSHandshakeTime.Observe(duration.Seconds())
}

// RecordMessageSize records the size of a received message
func RecordMessageSize(size int) {
	MessageSizeBytes.Observe(float64(size))
}

// RecordRateLimitHit records a rate limit hit
func RecordRateLimitHit(limitType string) {
	RateLimitHitsTotal.WithLabelValues(limitType).Inc()
}

// RecordMessageTimeInQueue records the time a message spent in the queue
func RecordMessageTimeInQueue(duration time.Duration) {
	MessageTimeInQueueSeconds.Observe(duration.Seconds())
}

// RecordMessageRetryCount records the number of retry attempts for a message
func RecordMessageRetryCount(retries int) {
	MessageRetryCount.Observe(float64(retries))
}

// UpdateQueueSizes updates the queue size metrics
func UpdateQueueSizes(readySize, retrySize int) {
	QueueSizeReady.Set(float64(readySize))
	QueueSizeRetry.Set(float64(retrySize))
}

// RecordMessageStatus records a message status
func RecordMessageStatus(status string, size int, duration time.Duration) {
	MessageStatusTotal.WithLabelValues(status).Inc()
	MessageStatusBySize.WithLabelValues(status).Observe(float64(size))
	MessageStatusByTime.WithLabelValues(status).Observe(duration.Seconds())
}

// RecordMessageStatusByDomain records a message status with domain information
func RecordMessageStatusByDomain(status, domain string) {
	MessageStatusByDomain.WithLabelValues(status, domain).Inc()
}

// RecordBounce records a message bounce
func RecordBounce(reason string, timeToBounce time.Duration) {
	BounceReasonTotal.WithLabelValues(reason).Inc()
	BounceTimeToBounce.Observe(timeToBounce.Seconds())
}

// RecordRejection records a message rejection
func RecordRejection(reason string) {
	RejectionReasonTotal.WithLabelValues(reason).Inc()
}

// RecordDeferral records a message deferral
func RecordDeferral(reason string, retryCount int) {
	DeferralReasonTotal.WithLabelValues(reason).Inc()
	DeferralRetryCount.Observe(float64(retryCount))
}

// RecordLogMessage records a log message with the given level
func RecordLogMessage(level string) {
	logMessages.WithLabelValues(level).Inc()
}

// RecordTLSHandshake records a TLS handshake event
func RecordTLSHandshake(result string) {
	TLSHandshakesTotal.WithLabelValues(result).Inc()
}

// RecordTLSVersion records a TLS version event
func RecordTLSVersion(version string) {
	TLSVersionsTotal.WithLabelValues(version).Inc()
}

// Message status constants
const (
	MessageStatusReceived  = "received"
	MessageStatusDelivered = "delivered"
	MessageStatusBounced   = "bounced"
	MessageStatusRejected  = "rejected"
	MessageStatusDeferred  = "deferred"
	MessageStatusFailed    = "failed"
)

// Bounce reason constants
const (
	BounceReasonUserUnknown       = "user_unknown"
	BounceReasonMailboxFull       = "mailbox_full"
	BounceReasonHostUnreachable   = "host_unreachable"
	BounceReasonConnectionRefused = "connection_refused"
	BounceReasonOther             = "other"
)

// Rejection reason constants
const (
	RejectionReasonSpam           = "spam"
	RejectionReasonPolicy         = "policy"
	RejectionReasonAuthentication = "authentication"
	RejectionReasonSize           = "size"
	RejectionReasonOther          = "other"
)

// Deferral reason constants
const (
	DeferralReasonTemporaryFailure = "temporary_failure"
	DeferralReasonQueueFull        = "queue_full"
	DeferralReasonRateLimit        = "rate_limit"
	DeferralReasonOther            = "other"
)

// GetConnectionsActive returns the current value of the active connections gauge
func GetConnectionsActive() float64 {
	var m dto.Metric
	if err := ConnectionsActive.(prometheus.Metric).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// GetQueueSizeReady returns the current value of the ready queue size gauge
func GetQueueSizeReady() float64 {
	var m dto.Metric
	if err := QueueSizeReady.(prometheus.Metric).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// RecordConnection increments the total connections counter and updates active connections
func RecordConnection() {
	ConnectionsTotal.Inc()
	ConnectionsActive.Inc()
}

// RecordConnectionClosed decrements the active connections gauge
func RecordConnectionClosed() {
	ConnectionsActive.Dec()
}

// RecordDeliveryTime records the time taken to deliver a message
func RecordDeliveryTime(remoteDomain string, result string, duration time.Duration) {
	DeliveryTimeSeconds.WithLabelValues(remoteDomain, result).Observe(duration.Seconds())
}

// RecordPluginProcessingTime records the time taken by a plugin to process a hook
func RecordPluginProcessingTime(pluginName, hook string, duration time.Duration) {
	PluginProcessingTimeSeconds.WithLabelValues(pluginName, hook).Observe(duration.Seconds())
}

// RecordPluginResult records the result of a plugin's processing
func RecordPluginResult(pluginName, hook, result string) {
	PluginResultsTotal.WithLabelValues(pluginName, hook, result).Inc()
}

// RecordCommand records a command execution
func RecordCommand(command string) {
	CommandsProcessedTotal.WithLabelValues(command, "success").Inc()
}

// RecordAuthAttempt records an authentication attempt
func RecordAuthAttempt(method, result string) {
	AuthAttemptsTotal.WithLabelValues(method, result).Inc()
}

// Metrics implements the plugin.Plugin interface for metrics collection
type Metrics struct {
	plugin.BasePlugin // Embed base plugin for default methods
	logger            *slog.Logger
}

// NewMetrics creates a new Metrics plugin instance
func NewMetrics() *Metrics {
	return &Metrics{
		logger: slog.Default().With("plugin", "metrics"),
	}
}

// Name returns the name of the plugin
func (m *Metrics) Name() string {
	return "Metrics Collector"
}

// OnSessionStart is called when a new session starts
func (m *Metrics) OnSessionStart(ctx context.Context, session *plugin.SessionInfo) (context.Context, error) {
	RecordConnection()
	return ctx, nil
}

// OnSessionEnd is called when a session ends
func (m *Metrics) OnSessionEnd(ctx context.Context, session *plugin.SessionInfo) (context.Context, error) {
	RecordConnectionClosed()
	return ctx, nil
}

// OnMessage is called after a message is received
func (m *Metrics) OnMessage(ctx context.Context, session *plugin.SessionInfo, msg *plugin.MessageInfo) (context.Context, error) {
	RecordMessageSize(len(msg.Data))
	return ctx, nil
}
