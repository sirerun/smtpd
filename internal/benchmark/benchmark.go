package benchmark

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"sync"
	"time"
)

// BenchmarkConfig holds configuration for the benchmark
type BenchmarkConfig struct {
	ConcurrentClients int           // Number of concurrent clients
	MessagesPerClient int           // Number of messages per client
	MessageSize       int           // Size of each message in bytes
	ServerAddress     string        // SMTP server address
	ServerPort        int           // SMTP server port
	UseTLS            bool          // Whether to use TLS
	Timeout           time.Duration // Connection timeout
}

// DefaultConfig returns default benchmark configuration
func DefaultConfig() *BenchmarkConfig {
	return &BenchmarkConfig{
		ConcurrentClients: 10,
		MessagesPerClient: 100,
		MessageSize:       1024, // 1KB
		ServerAddress:     "localhost",
		ServerPort:        25,
		UseTLS:            false,
		Timeout:           30 * time.Second,
	}
}

// BenchmarkResult holds the results of a benchmark run
type BenchmarkResult struct {
	TotalMessages      int
	SuccessfulMessages int
	FailedMessages     int
	TotalTime          time.Duration
	MessagesPerSecond  float64
	AverageLatency     time.Duration
	MaxLatency         time.Duration
	MinLatency         time.Duration
	ErrorRate          float64
}

// Run executes the benchmark with the given configuration
func Run(ctx context.Context, config *BenchmarkConfig) (*BenchmarkResult, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create a wait group to track all clients
	var wg sync.WaitGroup
	wg.Add(config.ConcurrentClients)

	// Create channels for results
	results := make(chan messageResult, config.ConcurrentClients)
	errors := make(chan error, config.ConcurrentClients)

	// Start all clients
	startTime := time.Now()
	for i := 0; i < config.ConcurrentClients; i++ {
		go func(clientID int) {
			defer wg.Done()
			runClient(ctx, config, results, clientID)
		}(i)
	}

	// Wait for all clients to complete
	wg.Wait()
	close(results)
	close(errors)
	totalTime := time.Since(startTime)

	// Collect results
	var totalMessages, successfulMessages, failedMessages int
	var totalLatency time.Duration
	var maxLatency, minLatency time.Duration

	// Initialize minLatency correctly
	minLatency = time.Duration(1<<63 - 1)

	for result := range results {
		totalMessages++
		if result.err == nil {
			successfulMessages++
			totalLatency += result.latency
			if result.latency > maxLatency {
				maxLatency = result.latency
			}
			if result.latency < minLatency {
				minLatency = result.latency
			}
		} else {
			failedMessages++
		}
	}

	// Check for errors
	var err error
	if failedMessages > 0 {
		err = fmt.Errorf("benchmark completed with %d errors", failedMessages)
	}

	// Calculate metrics
	avgLatency := time.Duration(0)
	if successfulMessages > 0 {
		avgLatency = totalLatency / time.Duration(successfulMessages)
	}

	return &BenchmarkResult{
		TotalMessages:      totalMessages,
		SuccessfulMessages: successfulMessages,
		FailedMessages:     failedMessages,
		TotalTime:          totalTime,
		MessagesPerSecond:  float64(successfulMessages) / totalTime.Seconds(),
		AverageLatency:     avgLatency,
		MaxLatency:         maxLatency,
		MinLatency:         minLatency,
		ErrorRate:          float64(failedMessages) / float64(totalMessages) * 100,
	}, err
}

// messageResult holds the results for a single client
type messageResult struct {
	latency time.Duration
	err     error
}

// runClient simulates a single SMTP client session.
func runClient(ctx context.Context, config *BenchmarkConfig, results chan<- messageResult, clientID int) {
	startTime := time.Now()

	// Dial the server
	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", config.ServerAddress, config.ServerPort))
	if err != nil {
		results <- messageResult{latency: time.Since(startTime), err: fmt.Errorf("dial failed: %w", err)}
		return
	}
	defer conn.Close()

	// Set deadline on the connection
	if err := conn.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
		results <- messageResult{latency: time.Since(startTime), err: fmt.Errorf("SetDeadline failed: %w", err)}
		return
	}

	// Create SMTP client from the connection
	client, err := smtp.NewClient(conn, config.ServerAddress)
	if err != nil {
		results <- messageResult{latency: time.Since(startTime), err: fmt.Errorf("NewClient failed: %w", err)}
		return
	}
	// No need to defer client.Close() as conn.Close() handles it.

	// Optional: Handle TLS if needed
	if config.UseTLS {
		if err := client.StartTLS(&tls.Config{ServerName: config.ServerAddress}); err != nil {
			results <- messageResult{latency: time.Since(startTime), err: fmt.Errorf("StartTLS failed: %w", err)}
			return
		}
	}

	// Send messages
	for i := 0; i < config.MessagesPerClient; i++ {
		select {
		case <-ctx.Done():
			results <- messageResult{latency: time.Since(startTime), err: ctx.Err()} // Report context cancellation
			return
		default:
		}

		msgStartTime := time.Now()
		from := fmt.Sprintf("sender-%d@benchmark.local", i)
		to := []string{fmt.Sprintf("recipient-%d@benchmark.local", i)}
		msg := fmt.Sprintf("Subject: Bench %d\r\n\r\nBody %d\r\nSize: %s", i, i, generateBody(config.MessageSize))

		if err := client.Mail(from); err != nil {
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("mail from failed: %w", err)}
			continue // Try next message
		}
		if err := client.Rcpt(to[0]); err != nil {
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("rcpt to failed: %w", err)}
			continue
		}
		w, err := client.Data()
		if err != nil {
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("data cmd failed: %w", err)}
			continue
		}
		_, err = fmt.Fprint(w, msg)
		if err != nil {
			w.Close() // Attempt close
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("write data failed: %w", err)}
			continue
		}
		if err := w.Close(); err != nil {
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("close data failed: %w", err)}
			continue
		}

		// If loop completes successfully for this message
		results <- messageResult{latency: time.Since(msgStartTime), err: nil}

		// Reset client state for next message (important!)
		if err := client.Reset(); err != nil {
			// If reset fails, the connection state is uncertain, best to stop this client
			results <- messageResult{latency: time.Since(msgStartTime), err: fmt.Errorf("reset failed: %w", err)}
			return
		}
	}

	// Send QUIT after loop finishes
	if err := client.Quit(); err != nil {
		// Log quit error, but don't overwrite successful message results
		fmt.Fprintf(os.Stderr, "client quit failed: %v\n", err)
	}
}

// generateBody generates a random message body of the specified size
func generateBody(size int) string {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 256)
	}
	return string(body)
}
