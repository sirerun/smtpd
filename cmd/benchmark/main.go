package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mailtive/smtpd/internal/benchmark"
)

func main() {
	// Parse command line flags
	concurrentClients := flag.Int("clients", 10, "Number of concurrent clients")
	messagesPerClient := flag.Int("messages", 100, "Number of messages per client")
	messageSize := flag.Int("size", 1024, "Size of each message in bytes")
	serverAddress := flag.String("server", "localhost", "SMTP server address")
	serverPort := flag.Int("port", 25, "SMTP server port")
	useTLS := flag.Bool("tls", false, "Use TLS")
	timeout := flag.Duration("timeout", 30*time.Second, "Connection timeout")
	flag.Parse()

	// Create benchmark configuration
	config := &benchmark.BenchmarkConfig{
		ConcurrentClients: *concurrentClients,
		MessagesPerClient: *messagesPerClient,
		MessageSize:       *messageSize,
		ServerAddress:     *serverAddress,
		ServerPort:        *serverPort,
		UseTLS:            *useTLS,
		Timeout:           *timeout,
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Print configuration
	fmt.Printf("Starting benchmark with configuration:\n")
	fmt.Printf("  Concurrent Clients: %d\n", config.ConcurrentClients)
	fmt.Printf("  Messages per Client: %d\n", config.MessagesPerClient)
	fmt.Printf("  Message Size: %d bytes\n", config.MessageSize)
	fmt.Printf("  Server: %s:%d\n", config.ServerAddress, config.ServerPort)
	fmt.Printf("  TLS: %v\n", config.UseTLS)
	fmt.Printf("  Timeout: %v\n", config.Timeout)
	fmt.Println()

	// Run benchmark
	fmt.Println("Running benchmark...")
	result, err := benchmark.Run(ctx, config)
	if err != nil {
		fmt.Printf("Benchmark failed: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("\nBenchmark Results:\n")
	fmt.Printf("  Total Messages: %d\n", result.TotalMessages)
	fmt.Printf("  Successful Messages: %d\n", result.SuccessfulMessages)
	fmt.Printf("  Failed Messages: %d\n", result.FailedMessages)
	fmt.Printf("  Total Time: %v\n", result.TotalTime)
	fmt.Printf("  Messages per Second: %.2f\n", result.MessagesPerSecond)
	fmt.Printf("  Average Latency: %v\n", result.AverageLatency)
	fmt.Printf("  Min Latency: %v\n", result.MinLatency)
	fmt.Printf("  Max Latency: %v\n", result.MaxLatency)
	fmt.Printf("  Error Rate: %.2f%%\n", result.ErrorRate)
}
