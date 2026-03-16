package server

import (
	"net"
	"net/smtp"
	"testing"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/metrics"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

var benchLogger = logging.New(&logging.Config{Level: logging.WarnLevel, Output: "stderr", Format: logging.TextFormat})
var benchPlugins = []plugin.Plugin{}

// Helper to get metric value (counter or gauge)
func getMetricValue(col prometheus.Collector) float64 {
	var metric dto.Metric
	switch c := col.(type) {
	case prometheus.Counter:
		err := c.Write(&metric)
		if err != nil {
			return -1
		}
		return metric.Counter.GetValue()
	case prometheus.Gauge:
		err := c.Write(&metric)
		if err != nil {
			return -1
		}
		return metric.Gauge.GetValue()
	default:
		return -2
	}
}

// Helper to get metric value from a vector
func getVecMetricCount(col prometheus.Collector) float64 {
	ch := make(chan prometheus.Metric, 1)
	col.Collect(ch)
	close(ch)
	m, ok := <-ch
	if !ok {
		return -1
	}
	var dtoMetric dto.Metric
	if err := m.Write(&dtoMetric); err != nil {
		return -2
	}
	if dtoMetric.Counter != nil {
		return dtoMetric.Counter.GetValue()
	} else if dtoMetric.Gauge != nil {
		return dtoMetric.Gauge.GetValue()
	} else if dtoMetric.Histogram != nil {
		return float64(dtoMetric.Histogram.GetSampleCount())
	}
	return -3
}

// BenchmarkSMTPConcurrency measures the performance of handling concurrent SMTP sessions.
func BenchmarkSMTPConcurrency(b *testing.B) {
	srv, err := newTestServer(b, nil)
	require.NoError(b, err, "Failed to create server")

	err = srv.Start()
	require.NoError(b, err, "Failed to start server")
	defer srv.Stop()

	addr := srv.Addr()

	b.ResetTimer()
	b.Run("ConcurrentConnections", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					b.Errorf("Failed to connect: %v", err)
					continue
				}
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("EHLO test\r\n"))
				_, _ = conn.Read(buf)
				conn.Close()
			}
		})
	})
	b.StopTimer()

	b.Logf("Connections processed: %.0f", getMetricValue(metrics.ConnectionsTotal))
	b.Logf("Active connections at end: %.0f", getMetricValue(metrics.ConnectionsActive))
}

func BenchmarkSMTPMessageProcessing(b *testing.B) {
	srv, err := newTestServer(b, nil)
	require.NoError(b, err, "Failed to create server")

	err = srv.Start()
	require.NoError(b, err, "Failed to start server")
	defer srv.Stop()

	addr := srv.Addr()

	b.ResetTimer()
	b.Run("MessageProcessing", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
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
					_ = client.Reset()
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
				if err := client.Reset(); err != nil {
					b.Fatalf("RSET failed: %v", err)
				}
			}
		})
	})
	b.StopTimer()

	b.Logf("Messages received: %.0f", getMetricValue(metrics.MessagesReceivedTotal))
}

func BenchmarkServer_HandleMessages(b *testing.B) {
	srv, err := newTestServer(b, nil)
	require.NoError(b, err)

	err = srv.Start()
	require.NoError(b, err, "Server failed to start")
	defer srv.Stop()

	actualAddr := srv.Addr()

	message := []byte("Subject: Benchmark\r\n\r\nBody.")
	from := "benchmark@localhost"
	to := []string{"recipient@localhost"}

	b.ResetTimer()
	b.SetParallelism(10)

	b.RunParallel(func(pb *testing.PB) {
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
			if err := client.Reset(); err != nil {
				b.Fatalf("RSET failed: %v", err)
			}
		}
	})

	b.StopTimer()

	b.Logf("Total Connections: %.0f", getMetricValue(metrics.ConnectionsTotal))
}

func BenchmarkServer_HandleConnections(b *testing.B) {
	srv, err := newTestServer(b, nil)
	require.NoError(b, err)

	err = srv.Start()
	require.NoError(b, err, "Server failed to start")
	defer srv.Stop()
	actualAddr := srv.Addr()

	b.ResetTimer()
	b.SetParallelism(10)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := net.Dial("tcp", actualAddr)
			if err != nil {
				b.Fatalf("Failed to dial: %v", err)
			}
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("QUIT\r\n"))
			_ = conn.Close()
		}
	})

	b.StopTimer()

	connections := getMetricValue(metrics.ConnectionsTotal)
	b.Logf("Total Connections Handled: %.0f", connections)
}
