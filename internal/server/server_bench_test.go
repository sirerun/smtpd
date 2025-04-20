package server

import (
	"net"
	"net/smtp"
	"testing"
	"time"

	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/metrics"
	"github.com/mailtive/smtpd/pkg/plugin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var benchLogger = logging.New(&logging.Config{Level: logging.WarnLevel, Output: "stderr", Format: logging.TextFormat})
var benchPlugins = []plugin.Plugin{}

// Helper to get metric value (counter or gauge)
func getMetricValue(col prometheus.Collector) float64 {
	var metric dto.Metric
	// Handle both Counter and Gauge collectors
	switch c := col.(type) {
	case prometheus.Counter:
		err := c.Write(&metric)
		if err != nil {
			return -1 // Indicate error
		}
		return metric.Counter.GetValue()
	case prometheus.Gauge:
		err := c.Write(&metric)
		if err != nil {
			return -1 // Indicate error
		}
		return metric.Gauge.GetValue()
	default:
		return -2 // Indicate unsupported type
	}
}

// Helper to get metric value from a vector (assumes labels don't matter for total count)
func getVecMetricCount(col prometheus.Collector) float64 {
	// Simplified: Get the first metric's value, assuming we just need a rough count
	// A more robust approach would involve iterating through metrics or using specific labels
	ch := make(chan prometheus.Metric, 1)
	col.Collect(ch)
	close(ch)
	m, ok := <-ch
	if !ok {
		return -1 // No metric found
	}
	var dtoMetric dto.Metric
	if err := m.Write(&dtoMetric); err != nil {
		return -2 // Error writing metric
	}
	if dtoMetric.Counter != nil {
		return dtoMetric.Counter.GetValue()
	} else if dtoMetric.Gauge != nil {
		return dtoMetric.Gauge.GetValue()
	} else if dtoMetric.Histogram != nil {
		return float64(dtoMetric.Histogram.GetSampleCount())
	}
	// Add other types (Summary) if needed
	return -3 // Unsupported metric type in DTO
}

// BenchmarkSMTPConcurrency measures the performance of handling concurrent SMTP sessions.
func BenchmarkSMTPConcurrency(b *testing.B) {
	// Create server with test configuration
	cfg := createTestServerConfig()
	cfg.MaxConnections = 1000

	srv, err := NewServerWithConfig(
		"localhost:0",
		0,
		nil,
		nil,
		benchPlugins,
		benchLogger,
		cfg,
	)
	require.NoError(b, err, "Failed to create server")

	// Start server
	err = srv.Start()
	require.NoError(b, err, "Failed to start server")
	defer srv.Stop()

	// Get server address
	addr := srv.Addr()

	// Run benchmark
	b.ResetTimer()
	b.Run("ConcurrentConnections", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					b.Errorf("Failed to connect: %v", err)
					continue
				}
				// Read greeting to ensure connection is established
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)

				// Send EHLO (optional, but simulates minimal interaction)
				_, _ = conn.Write([]byte("EHLO test\r\n"))
				_, _ = conn.Read(buf) // Read response

				conn.Close()
			}
		})
	})
	b.StopTimer()

	// Print metrics
	b.Logf("Connections processed: %.0f", getMetricValue(metrics.ConnectionsTotal))
	b.Logf("Active connections at end: %.0f", getMetricValue(metrics.ConnectionsActive)) // Active should be low/zero after test
	// Commands processed: Accessing Vec needs specific labels or a different approach
	// b.Logf("Commands processed (approx): %.0f", getVecMetricCount(metrics.CommandsProcessedTotal))
}

func BenchmarkSMTPMessageProcessing(b *testing.B) {
	// Create server with test configuration
	cfg := createTestServerConfig()
	cfg.MaxConnections = 1000

	srv, err := NewServerWithConfig(
		"localhost:0",
		0,
		nil,
		nil,
		benchPlugins,
		benchLogger,
		cfg,
	)
	require.NoError(b, err, "Failed to create server")

	// Start server
	err = srv.Start()
	require.NoError(b, err, "Failed to start server")
	defer srv.Stop()

	// Get server address
	addr := srv.Addr()

	// Run benchmark
	b.ResetTimer()
	b.Run("MessageProcessing", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			// Create a single client per goroutine for reuse
			client, err := smtp.Dial(addr)
			if err != nil {
				b.Fatalf("Failed to dial server: %v", err)
			}
			defer client.Close()

			from := "sender@example.com"
			to := []string{"recipient@example.com"}
			msg := []byte("Subject: Test\r\n\r\nTest message body.")

			for pb.Next() {
				if err := client.Mail(from); err != nil {
					b.Errorf("MAIL FROM failed: %v", err)
					_ = client.Reset() // Try to reset on error
					continue
				}
				for _, rcpt := range to {
					if err := client.Rcpt(rcpt); err != nil {
						b.Errorf("RCPT TO failed: %v", err)
						_ = client.Reset()
						continue
					}
				}
				wc, err := client.Data()
				if err != nil {
					b.Errorf("DATA command failed: %v", err)
					_ = client.Reset()
					continue
				}
				_, err = wc.Write(msg)
				if err != nil {
					_ = wc.Close()
					b.Errorf("Write failed: %v", err)
					_ = client.Reset()
					continue
				}
				if err := wc.Close(); err != nil {
					b.Errorf("DATA close failed: %v", err)
					_ = client.Reset()
					continue
				}
				// Optional: Reset client state if needed between iterations
				if err := client.Reset(); err != nil {
					b.Fatalf("RSET failed: %v", err)
				}
			}
		})
	})
	b.StopTimer()

	// Print metrics
	b.Logf("Messages received: %.0f", getMetricValue(metrics.MessagesReceivedTotal))
	// For histograms, getting a single value isn't very meaningful.
	// Consider logging the count or specific quantiles if needed.
	// b.Logf("Message size distribution count: %.0f", getVecMetricCount(metrics.MessageSizeBytes))
	// b.Logf("Command processing time count: %.0f", getVecMetricCount(metrics.CommandProcessingTime))
}

// Benchmark sending multiple messages through the server.
func BenchmarkServer_HandleMessages(b *testing.B) {
	// Create a server config directly
	serverCfg := DefaultServerConfig() // Use the DefaultServerConfig from server package
	serverCfg.MaxConnections = 100     // Adjust if needed for benchmark

	// Setup logger (already defined as benchLogger)

	// Setup server
	addr := "127.0.0.1:0"                                                                    // Use random port
	srv, err := NewServerWithConfig(addr, 0, nil, nil, benchPlugins, benchLogger, serverCfg) // Pass serverCfg
	require.NoError(b, err)

	go func() {
		if err := srv.Start(); err != nil {
			// Use b.Fatalf in benchmarks
			b.Fatalf("Server failed to start: %v", err)
		}
	}()
	defer srv.Stop()

	// Wait briefly for server to start listening
	time.Sleep(50 * time.Millisecond)

	// Get the actual listening address
	actualAddr := srv.Addr() // Use Addr() method

	// --- Benchmark Client ---
	message := []byte("Subject: Benchmark\r\n\r\nBody.")
	from := "benchmark@localhost"
	to := []string{"recipient@localhost"}

	b.ResetTimer()
	b.SetParallelism(10) // Adjust parallelism

	b.RunParallel(func(pb *testing.PB) {
		// Create a single client per goroutine for reuse
		client, err := smtp.Dial(actualAddr)
		if err != nil {
			b.Fatalf("Failed to dial server: %v", err)
		}
		defer client.Close()

		for pb.Next() {
			if err := client.Mail(from); err != nil {
				b.Errorf("MAIL FROM failed: %v", err)
				_ = client.Reset()
				continue
			}
			for _, recipient := range to {
				if err := client.Rcpt(recipient); err != nil {
					b.Errorf("RCPT TO failed: %v", err)
					_ = client.Reset()
					continue
				}
			}
			wc, err := client.Data()
			if err != nil {
				b.Errorf("DATA failed: %v", err)
				_ = client.Reset()
				continue
			}
			_, err = wc.Write(message)
			if err != nil {
				_ = wc.Close() // Attempt to close even on error
				b.Errorf("Write failed: %v", err)
				_ = client.Reset()
				continue
			}
			if err := wc.Close(); err != nil {
				b.Errorf("DATA close failed: %v", err)
				_ = client.Reset()
				continue
			}
			// Optional: Reset client state if needed between iterations
			if err := client.Reset(); err != nil {
				b.Fatalf("RSET failed: %v", err) // Fatal if reset fails
			}
		}
	})

	b.StopTimer()

	// Optional: Add assertions on metrics after benchmark
	b.Logf("Total Connections: %.0f", getMetricValue(metrics.ConnectionsTotal))
}

// Simplified benchmark focusing only on connection setup/teardown.
func BenchmarkServer_HandleConnections(b *testing.B) {
	serverCfg := DefaultServerConfig()
	// benchLogger already defined
	addr := "127.0.0.1:0"
	srv, err := NewServerWithConfig(addr, 0, nil, nil, benchPlugins, benchLogger, serverCfg)
	require.NoError(b, err)

	go func() {
		if err := srv.Start(); err != nil {
			b.Fatalf("Server failed to start: %v", err)
		}
	}()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)
	actualAddr := srv.Addr()

	b.ResetTimer()
	b.SetParallelism(10)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := net.Dial("tcp", actualAddr)
			if err != nil {
				b.Fatalf("Failed to dial: %v", err)
			}
			// Read greeting (optional but good practice)
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			// Send QUIT
			_, _ = conn.Write([]byte("QUIT\r\n"))
			_ = conn.Close()
		}
	})

	b.StopTimer()

	// Metrics checks
	connections := getMetricValue(metrics.ConnectionsTotal)
	b.Logf("Total Connections Handled: %.0f", connections)
}
