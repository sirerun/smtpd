// Package main provides an SMTP load testing tool
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"sync"
	"sync/atomic"
	"time"
)

// Configuration options for the load test
type Config struct {
	ServerAddr      string
	Connections     int
	MessagePerConn  int
	MessageSize     int
	Parallel        int
	Duration        time.Duration
	Auth            bool
	Username        string
	Password        string
	UseTLS          bool
	InsecureSkipTLS bool
	Verbose         bool
}

// Statistics collected during the load test
type Stats struct {
	ConnectionsAttempted int64
	ConnectionsSucceeded int64
	ConnectionsFailed    int64
	MessagesAttempted    int64
	MessagesSucceeded    int64
	MessagesFailed       int64
	StartTime            time.Time
	EndTime              time.Time
}

func main() {
	// Parse command-line flags
	cfg := Config{}
	flag.StringVar(&cfg.ServerAddr, "server", "localhost:2525", "SMTP server address")
	flag.IntVar(&cfg.Connections, "connections", 10, "Number of connections to establish")
	flag.IntVar(&cfg.MessagePerConn, "messages", 10, "Messages to send per connection")
	flag.IntVar(&cfg.MessageSize, "size", 1024, "Message size in bytes")
	flag.IntVar(&cfg.Parallel, "parallel", 5, "Number of parallel connections")
	durationStr := flag.String("duration", "30s", "Duration of the test")
	flag.BoolVar(&cfg.Auth, "auth", false, "Use SMTP authentication")
	flag.StringVar(&cfg.Username, "username", "testuser", "Username for SMTP authentication")
	flag.StringVar(&cfg.Password, "password", "password123", "Password for SMTP authentication")
	flag.BoolVar(&cfg.UseTLS, "tls", false, "Use TLS for connections")
	flag.BoolVar(&cfg.InsecureSkipTLS, "insecure", false, "Skip TLS certificate verification")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	// Parse duration
	duration, err := time.ParseDuration(*durationStr)
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}
	cfg.Duration = duration

	// Print test configuration
	fmt.Printf("SMTP Load Test Configuration:\n")
	fmt.Printf("  Server: %s\n", cfg.ServerAddr)
	fmt.Printf("  Connections: %d\n", cfg.Connections)
	fmt.Printf("  Messages per Connection: %d\n", cfg.MessagePerConn)
	fmt.Printf("  Message Size: %d bytes\n", cfg.MessageSize)
	fmt.Printf("  Parallelism: %d\n", cfg.Parallel)
	fmt.Printf("  Duration: %s\n", cfg.Duration)
	fmt.Printf("  Authentication: %v\n", cfg.Auth)
	fmt.Printf("  TLS: %v\n", cfg.UseTLS)
	fmt.Printf("Starting test...\n\n")

	// Run the load test
	stats := runLoadTest(cfg)

	// Print the results
	printResults(stats, cfg)
}

// runLoadTest executes the load test with the given configuration
func runLoadTest(cfg Config) Stats {
	stats := Stats{
		StartTime: time.Now(),
	}

	// Create a semaphore to limit parallelism
	sem := make(chan struct{}, cfg.Parallel)
	var wg sync.WaitGroup

	// Create a context with a timeout
	done := make(chan struct{})
	go func() {
		time.Sleep(cfg.Duration)
		close(done)
	}()

	// Start the worker goroutines
	for i := 0; i < cfg.Connections; i++ {
		select {
		case <-done:
			// Time's up, finish
			break
		case sem <- struct{}{}: // Acquire semaphore slot
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore slot

				// Increment connection attempt counter
				atomic.AddInt64(&stats.ConnectionsAttempted, 1)

				// Create a new connection
				client, err := connectToServer(cfg)
				if err != nil {
					if cfg.Verbose {
						fmt.Printf("Connection %d failed: %v\n", connID, err)
					}
					atomic.AddInt64(&stats.ConnectionsFailed, 1)
					return
				}
				defer client.Close()

				// Connection succeeded
				atomic.AddInt64(&stats.ConnectionsSucceeded, 1)

				// Send messages
				for j := 0; j < cfg.MessagePerConn; j++ {
					select {
					case <-done:
						return // Time's up, finish
					default:
						// Continue sending
					}

					// Increment message attempt counter
					atomic.AddInt64(&stats.MessagesAttempted, 1)

					// Send a message
					err := sendMessage(client, cfg, connID, j)
					if err != nil {
						if cfg.Verbose {
							fmt.Printf("Connection %d, Message %d failed: %v\n", connID, j, err)
						}
						atomic.AddInt64(&stats.MessagesFailed, 1)
						break // Move to next connection
					}

					// Message succeeded
					atomic.AddInt64(&stats.MessagesSucceeded, 1)

					if cfg.Verbose {
						fmt.Printf("Connection %d, Message %d succeeded\n", connID, j)
					}
				}
			}(i)
		}
	}

	// Wait for all connections to complete or timeout
	wg.Wait()
	stats.EndTime = time.Now()
	return stats
}

// connectToServer establishes a connection to the SMTP server
func connectToServer(cfg Config) (*textproto.Conn, error) {
	// Connect to the server
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	if cfg.UseTLS {
		// Use TLS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS,
			MinVersion:         tls.VersionTLS12,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", cfg.ServerAddr, tlsConfig)
	} else {
		// Use plain TCP connection
		conn, err = dialer.Dial("tcp", cfg.ServerAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Create a textproto client
	client := textproto.NewConn(conn)

	// Read the greeting
	_, err = client.ReadLine()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	// Send EHLO
	if err := client.PrintfLine("EHLO loadtest"); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to send EHLO: %w", err)
	}

	// Read EHLO response
	for {
		line, err := client.ReadLine()
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to read EHLO response: %w", err)
		}
		if len(line) < 4 || line[3] != '-' {
			break // End of multiline response
		}
	}

	// If STARTTLS is requested but we didn't connect with TLS initially
	if !cfg.UseTLS && cfg.Auth {
		// Send STARTTLS
		if err := client.PrintfLine("STARTTLS"); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to send STARTTLS: %w", err)
		}

		// Read STARTTLS response
		_, err = client.ReadLine()
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to read STARTTLS response: %w", err)
		}

		// Upgrade connection to TLS
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			client.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		// Replace client with new TLS wrapped client
		client = textproto.NewConn(tlsConn)

		// Send EHLO again after STARTTLS
		if err := client.PrintfLine("EHLO loadtest"); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to send EHLO after STARTTLS: %w", err)
		}

		// Read EHLO response again
		for {
			line, err := client.ReadLine()
			if err != nil {
				client.Close()
				return nil, fmt.Errorf("failed to read EHLO response after STARTTLS: %w", err)
			}
			if len(line) < 4 || line[3] != '-' {
				break // End of multiline response
			}
		}
	}

	// Handle authentication if requested
	if cfg.Auth {
		// Send AUTH PLAIN command with credentials
		auth := fmt.Sprintf("\x00%s\x00%s", cfg.Username, cfg.Password)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(auth)))
		base64.StdEncoding.Encode(encoded, []byte(auth))
		if err := client.PrintfLine("AUTH PLAIN %s", encoded); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to send AUTH: %w", err)
		}

		// Read AUTH response
		_, err = client.ReadLine()
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to read AUTH response: %w", err)
		}
	}

	return client, nil
}

// sendMessage sends a single message through the SMTP connection
func sendMessage(client *textproto.Conn, cfg Config, connID, msgID int) error {
	// Generate a unique message ID
	messageID := fmt.Sprintf("%d.%d.%d@loadtest", time.Now().Unix(), connID, msgID)

	// Send MAIL FROM
	if err := client.PrintfLine("MAIL FROM:<sender@loadtest.example.com>"); err != nil {
		return fmt.Errorf("failed to send MAIL FROM: %w", err)
	}

	// Read MAIL FROM response
	_, err := client.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read MAIL FROM response: %w", err)
	}

	// Send RCPT TO
	if err := client.PrintfLine("RCPT TO:<recipient@loadtest.example.com>"); err != nil {
		return fmt.Errorf("failed to send RCPT TO: %w", err)
	}

	// Read RCPT TO response
	_, err = client.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read RCPT TO response: %w", err)
	}

	// Send DATA
	if err := client.PrintfLine("DATA"); err != nil {
		return fmt.Errorf("failed to send DATA: %w", err)
	}

	// Read DATA response
	_, err = client.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read DATA response: %w", err)
	}

	// Send message headers
	if err := client.PrintfLine("From: Sender <sender@loadtest.example.com>"); err != nil {
		return fmt.Errorf("failed to send message headers: %w", err)
	}
	if err := client.PrintfLine("To: Recipient <recipient@loadtest.example.com>"); err != nil {
		return fmt.Errorf("failed to send message headers: %w", err)
	}
	if err := client.PrintfLine("Subject: Load Test Message %d.%d", connID, msgID); err != nil {
		return fmt.Errorf("failed to send message headers: %w", err)
	}
	if err := client.PrintfLine("Message-ID: <%s>", messageID); err != nil {
		return fmt.Errorf("failed to send message headers: %w", err)
	}
	if err := client.PrintfLine("Date: %s", time.Now().Format(time.RFC1123Z)); err != nil {
		return fmt.Errorf("failed to send message headers: %w", err)
	}
	if err := client.PrintfLine(""); err != nil { // Empty line between headers and body
		return fmt.Errorf("failed to send message headers: %w", err)
	}

	// Send message body
	body := generateMessageBody(cfg.MessageSize, connID, msgID)
	if err := client.PrintfLine(body); err != nil {
		return fmt.Errorf("failed to send message body: %w", err)
	}

	// Send end of data
	if err := client.PrintfLine("."); err != nil {
		return fmt.Errorf("failed to send end of data: %w", err)
	}

	// Read end of data response
	_, err = client.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read end of data response: %w", err)
	}

	return nil
}

// generateMessageBody generates a message body of the specified size
func generateMessageBody(size, connID, msgID int) string {
	body := fmt.Sprintf("This is a load test message %d.%d.\r\n\r\n", connID, msgID)

	// Generate padding to reach the target size
	padding := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
	paddingLen := size - len(body)
	if paddingLen > 0 {
		repeats := paddingLen / len(padding)
		remainder := paddingLen % len(padding)
		for i := 0; i < repeats; i++ {
			body += padding
		}
		body += padding[:remainder]
	}

	return body
}

// printResults displays the load test results
func printResults(stats Stats, cfg Config) {
	duration := stats.EndTime.Sub(stats.StartTime)
	fmt.Printf("\nSMTP Load Test Results:\n")
	fmt.Printf("  Test Duration: %s\n", duration)
	fmt.Printf("  Connections Attempted: %d\n", stats.ConnectionsAttempted)
	fmt.Printf("  Connections Succeeded: %d (%.2f%%)\n", stats.ConnectionsSucceeded, float64(stats.ConnectionsSucceeded)/float64(stats.ConnectionsAttempted)*100)
	fmt.Printf("  Connections Failed: %d (%.2f%%)\n", stats.ConnectionsFailed, float64(stats.ConnectionsFailed)/float64(stats.ConnectionsAttempted)*100)
	fmt.Printf("  Messages Attempted: %d\n", stats.MessagesAttempted)
	fmt.Printf("  Messages Succeeded: %d (%.2f%%)\n", stats.MessagesSucceeded, float64(stats.MessagesSucceeded)/float64(stats.MessagesAttempted)*100)
	fmt.Printf("  Messages Failed: %d (%.2f%%)\n", stats.MessagesFailed, float64(stats.MessagesFailed)/float64(stats.MessagesAttempted)*100)

	// Calculate performance metrics
	messageRate := float64(stats.MessagesSucceeded) / duration.Seconds()
	bytesTransmitted := int64(stats.MessagesSucceeded) * int64(cfg.MessageSize)
	throughput := float64(bytesTransmitted) / 1024 / 1024 / duration.Seconds() // MB/s

	fmt.Printf("\nPerformance Metrics:\n")
	fmt.Printf("  Message Rate: %.2f msgs/sec\n", messageRate)
	fmt.Printf("  Throughput: %.2f MB/s\n", throughput)
	fmt.Printf("  Average Response Time: %.2f ms\n", (duration.Seconds()*1000)/float64(stats.MessagesSucceeded))

	// Provide guidance on results
	fmt.Printf("\nRecommendations:\n")
	if stats.ConnectionsFailed > 0 {
		fmt.Printf("  - Some connections failed. Consider reducing parallelism or checking server capacity.\n")
	}
	if stats.MessagesFailed > 0 {
		fmt.Printf("  - Some messages failed. Examine server logs for specific error details.\n")
	}
	if messageRate < 10 {
		fmt.Printf("  - Message rate is relatively low. Consider optimizing server performance.\n")
	} else if messageRate > 1000 {
		fmt.Printf("  - Excellent message rate! Server is handling high throughput well.\n")
	}
}
