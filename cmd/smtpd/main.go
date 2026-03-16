package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Include pprof for diagnostics
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sirerun/smtpd/internal/config"
	"github.com/sirerun/smtpd/internal/health"
	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/queue"
	"github.com/sirerun/smtpd/internal/server"
	"github.com/sirerun/smtpd/pkg/plugin"
)

const appVersion = "1.0.0" // Define app version constant

func main() {
	// Setup context that cancels on interrupt signals
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the application and handle potential errors
	if err := run(ctx, os.Args); err != nil {
		// Logger might not be initialized if run() failed early.
		// Attempt to get the default logger, but fall back to stderr.
		logger := logging.Default() // Get default logger (might be nil initially)
		if logger != nil {
			logger.Error("Application run failed", "error", err)
		} else {
			fmt.Fprintf(os.Stderr, "ERROR: Application run failed before logger initialization: %v\n", err)
		}
		stop() // Ensure context cancellation triggers potential cleanup
		os.Exit(1)
	}

	// Get logger after run() has successfully initialized it
	logger := logging.Default()
	if logger != nil { // Check if logger was initialized (it should be if run succeeded)
		logger.Info("Application exited successfully")
	}
}

// run initializes and runs the SMTP server application.
func run(ctx context.Context, args []string) error {
	// --- Configuration and Flag Parsing ---
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configFile := fs.String("config", "", "Path to configuration file (YAML)")
	debugLogging := fs.Bool("debug", false, "Enable debug logging override")
	// Add other flags here, using fs.String, fs.Int, etc.

	// Parse initial flags (config path and debug)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // Exit cleanly if help was requested
		}
		// Log directly to stderr if flags fail very early before logger setup
		fmt.Fprintf(os.Stderr, "ERROR: Failed to parse initial flags: %v\n", err)
		return fmt.Errorf("failed to parse initial flags: %w", err)
	}

	// Load configuration from file first
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		// Log directly to stderr if config load fails before logger setup
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load configuration from %q: %v\n", *configFile, err)
		return fmt.Errorf("failed to load configuration from %q: %w", *configFile, err)
	}

	// Define the rest of the flags, using config values as defaults
	// Server flags
	listenAddr := fs.String("listen-addr", cfg.Server.ListenAddr, "Address to listen on")
	port := fs.Int("port", cfg.Server.Port, "SMTP port")
	submissionPort := fs.Int("submission-port", cfg.Server.SubmissionPort, "Submission port")
	maxConnections := fs.Int("max-connections", cfg.Server.MaxConnections, "Maximum number of concurrent connections")
	maxMessageSize := fs.Int64("max-message-size", cfg.Server.MaxMessageSize, "Maximum message size in bytes")
	readTimeout := fs.Duration("read-timeout", cfg.Server.ReadTimeout, "Read timeout")
	writeTimeout := fs.Duration("write-timeout", cfg.Server.WriteTimeout, "Write timeout")
	idleTimeout := fs.Duration("idle-timeout", cfg.Server.IdleTimeout, "Idle timeout")
	shutdownTimeout := fs.Duration("shutdown-timeout", cfg.Server.ShutdownTimeout, "Graceful shutdown timeout")

	// Auth flags
	authEnabled := fs.Bool("auth-enabled", cfg.Auth.Enabled, "Enable authentication")
	authUsersFile := fs.String("auth-users-file", cfg.Auth.UsersFile, "Path to users file")

	// Security flags
	tlsEnabled := fs.Bool("tls-enabled", cfg.Security.TLSEnabled, "Enable TLS")
	tlsCertFile := fs.String("tls-cert-file", cfg.Security.TLSCertFile, "TLS certificate file")
	tlsKeyFile := fs.String("tls-key-file", cfg.Security.TLSKeyFile, "TLS key file")
	rateLimit := fs.Int("rate-limit", cfg.Security.RateLimit, "Rate limit per minute")

	// Metrics flags
	metricsEnabled := fs.Bool("metrics-enabled", cfg.Metrics.Enabled, "Enable metrics server")
	metricsAddr := fs.String("metrics-addr", cfg.Metrics.ListenAddr, "Address for metrics server")
	metricsPath := fs.String("metrics-path", cfg.Metrics.MetricsPath, "Path for metrics endpoint")

	// Re-parse flags to capture overrides
	if err := fs.Parse(args[1:]); err != nil {
		// Log directly to stderr as logger isn't set up yet
		fmt.Fprintf(os.Stderr, "ERROR: Failed to parse override flags: %v\n", err)
		return fmt.Errorf("failed to parse override flags: %w", err)
	}

	// --- Apply Flag Overrides to Config (before logger setup) ---
	cfg.Server.ListenAddr = *listenAddr
	cfg.Server.Port = *port
	cfg.Server.SubmissionPort = *submissionPort
	cfg.Server.MaxConnections = *maxConnections
	cfg.Server.MaxMessageSize = *maxMessageSize
	cfg.Server.ReadTimeout = *readTimeout
	cfg.Server.WriteTimeout = *writeTimeout
	cfg.Server.IdleTimeout = *idleTimeout
	cfg.Server.ShutdownTimeout = *shutdownTimeout

	cfg.Auth.Enabled = *authEnabled
	cfg.Auth.UsersFile = *authUsersFile

	cfg.Security.TLSEnabled = *tlsEnabled
	cfg.Security.TLSCertFile = *tlsCertFile
	cfg.Security.TLSKeyFile = *tlsKeyFile
	cfg.Security.RateLimit = *rateLimit

	cfg.Metrics.Enabled = *metricsEnabled
	cfg.Metrics.ListenAddr = *metricsAddr
	cfg.Metrics.MetricsPath = *metricsPath

	// Apply debug logging flag override to config *before* initializing logger
	if *debugLogging {
		cfg.Logging.Level = string(logging.DebugLevel) // Use logging package constant
	}

	// --- Logger Setup ---
	// Use logging.Config which should be part of the main config.Config struct
	logCfg := &logging.Config{
		Level:       logging.LogLevel(cfg.Logging.Level), // Cast from string
		Format:      logging.Format(cfg.Logging.Format),  // Cast from string
		Output:      cfg.Logging.Output,
		ServiceName: "smtpd", // Consider making this configurable
		Environment: "dev",   // Consider making this configurable
		AddSource:   cfg.Logging.AddSource,
		TimeFormat:  time.RFC3339Nano, // Consider making this configurable
	}

	// If debug flag was set, ensure level is debug
	if *debugLogging {
		logCfg.Level = logging.DebugLevel
	}

	logger := logging.New(logCfg) // Create logger using internal package

	if *debugLogging {
		logger.Debug("Debug logging explicitly enabled via flag.")
	}

	logger.Info("Starting smtpd...",
		"version", appVersion,
		"go_version", runtime.Version(),
		"num_cpu", runtime.NumCPU(),
	)

	// --- Validate Final Configuration (after logger setup) ---
	if err := cfg.Validate(); err != nil {
		logger.Error("Invalid configuration", "error", err) // Use the initialized logger
		return fmt.Errorf("invalid configuration: %w", err)
	}
	logger.Info("Configuration loaded and validated successfully")

	// --- Component Initialization ---
	healthChecker := health.NewHealthChecker() // TODO: Pass logger to healthChecker?

	if cfg.Security.TLSEnabled {
		logger.Info("TLS enabled")
	}

	// Validate TLS configuration for submission port
	if cfg.Server.SubmissionPort > 0 {
		submissionAddr := fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.SubmissionPort)
		if !cfg.Security.TLSEnabled || cfg.Security.TLSCertFile == "" || cfg.Security.TLSKeyFile == "" {
			logger.Error("TLS configuration is required for submission port",
				"submission_port", cfg.Server.SubmissionPort,
				"tls_enabled", cfg.Security.TLSEnabled,
				"cert_file", cfg.Security.TLSCertFile,
				"key_file", cfg.Security.TLSKeyFile,
			)
			return fmt.Errorf("TLS configuration (enabled, cert, key) is required for submission port %d",
				cfg.Server.SubmissionPort)
		}
		logger.Info("Validated TLS configuration for submission port", "address", submissionAddr)
	}

	// Create queue for message processing
	q := queue.NewQueue(cfg.Server.ConnectionBacklog, logger)

	// Create plugin manager
	pm := plugin.NewManager()

	// Create main server
	mainServerLogger := logger.WithComponent("server.main")
	mainCfg := *cfg
	mainCfg.Server.ListenAddr = fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.Port)
	mainServer, err := server.NewServerWithOptions(server.ServerOptions{
		Config:        &mainCfg,
		Logger:        mainServerLogger,
		Queue:         q,
		PluginManager: pm,
	})
	if err != nil {
		logger.Error("Failed to create main server", "error", err)
		return fmt.Errorf("failed to create main server: %w", err)
	}

	// Create submission server
	submissionServerLogger := logger.WithComponent("server.submission")
	subCfg := *cfg
	subCfg.Server.ListenAddr = fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.SubmissionPort)
	subCfg.Server.Port = cfg.Server.SubmissionPort
	submissionServer, err := server.NewServerWithOptions(server.ServerOptions{
		Config:        &subCfg,
		Logger:        submissionServerLogger,
		Queue:         q,
		PluginManager: pm,
	})
	if err != nil {
		logger.Error("Failed to create submission server", "error", err)
		return fmt.Errorf("failed to create submission server: %w", err)
	}

	// --- Server Startup and Shutdown Management ---
	var eg errgroup.Group
	var metricsServer *http.Server

	// Start Metrics Server (if enabled)
	if cfg.Metrics.Enabled {
		metricsLogger := logger.WithComponent("server.metrics")
		mux := http.NewServeMux()
		mux.Handle(cfg.Metrics.MetricsPath, promhttp.Handler())
		mux.Handle("/health", health.Handler()) // Assuming health.Handler() is okay without logger
		mux.HandleFunc("/debug/pprof/", http.DefaultServeMux.ServeHTTP)

		metricsServer = &http.Server{
			Addr:         cfg.Metrics.ListenAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
			ErrorLog:     logging.NewSlogAdapter(metricsLogger), // Use the defined adapter
		}

		eg.Go(func() error {
			metricsLogger.Info("Starting metrics and health server", "address", cfg.Metrics.ListenAddr)
			if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				healthChecker.SetLastError(fmt.Sprintf("metrics server failed: %v", err)) // Keep using SetLastError for now
				metricsLogger.Error("Metrics server failed", "error", err)
				return fmt.Errorf("metrics server failed: %w", err)
			}
			metricsLogger.Info("Metrics server stopped listening")
			return nil
		})
	}

	// Start Main SMTP Server
	eg.Go(func() error {
		mainServerLogger.Info("Starting main SMTP server", "address", mainServer.Addr())
		if err := mainServer.Start(); err != nil {
			// Start should ideally handle context cancellation internally and return nil/specific error
			// Assuming Start() blocks until stopped or fatal error
			mainServerLogger.Error("Main SMTP server failed", "error", err)
			return fmt.Errorf("main SMTP server failed: %w", err)
		}
		mainServerLogger.Info("Main SMTP server stopped")
		return nil
	})

	// Start Submission SMTP Server
	eg.Go(func() error {
		submissionServerLogger.Info("Starting submission server", "address", submissionServer.Addr())
		if err := submissionServer.Start(); err != nil {
			submissionServerLogger.Error("Submission server failed", "error", err)
			return fmt.Errorf("submission server failed: %w", err)
		}
		submissionServerLogger.Info("Submission server stopped")
		return nil
	})

	logger.Info("Application servers started",
		"main_port", cfg.Server.Port,
		"submission_port", cfg.Server.SubmissionPort,
		"tls_enabled", cfg.Security.TLSEnabled,
		"auth_enabled", cfg.Auth.Enabled,
		"metrics_enabled", cfg.Metrics.Enabled,
	)

	// --- Graceful Shutdown Handling ---
	<-ctx.Done()
	logger.Info("Shutdown signal received, initiating graceful shutdown...")
	stopErr := ctx.Err()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancelShutdown()

	var shutdownWg sync.WaitGroup

	if metricsServer != nil {
		metricsLogger := logger.WithComponent("server.metrics")
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			metricsLogger.Info("Shutting down metrics server...")
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				metricsLogger.Error("Metrics server shutdown error", "error", err)
			} else {
				metricsLogger.Info("Metrics server shutdown complete")
			}
		}()
	}

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		mainServerLogger.Info("Shutting down main server...")
		if err := mainServer.Stop(); err != nil { // Assuming Stop() handles context cancellation implicitly
			mainServerLogger.Error("Main server shutdown error", "error", err)
		} else {
			mainServerLogger.Info("Main server shutdown complete")
		}
	}()

	shutdownWg.Add(1)
	go func() {
		defer shutdownWg.Done()
		submissionServerLogger.Info("Shutting down submission server...")
		if err := submissionServer.Stop(); err != nil { // Assuming Stop() handles context cancellation implicitly
			submissionServerLogger.Error("Submission server shutdown error", "error", err)
		} else {
			submissionServerLogger.Info("Submission server shutdown complete")
		}
	}()

	shutdownWg.Wait()
	logger.Info("Graceful shutdown finished.")

	// Wait for the main errgroup to finish (capture any startup errors)
	if runErr := eg.Wait(); runErr != nil {
		logger.Error("Server runtime error detected after shutdown signal", "error", runErr)
		// Decide which error to return. Prioritize runtime error if shutdown was 'clean' (canceled).
		if errors.Is(stopErr, context.Canceled) {
			return runErr // Return the server runtime error
		}
	}

	// Return error if shutdown timed out
	if errors.Is(stopErr, context.DeadlineExceeded) {
		err := fmt.Errorf("graceful shutdown timed out after %v", cfg.Server.ShutdownTimeout)
		logger.Error(err.Error())
		return err
	}

	// Return nil if shutdown was triggered by signal and no other errors occurred
	if errors.Is(stopErr, context.Canceled) {
		return nil // Indicate successful shutdown following signal
	}

	// If stopErr is something else (shouldn't happen with signal.NotifyContext), return it.
	if stopErr != nil {
		return stopErr
	}

	// Should not be reached if eg.Wait() returned nil and stopErr was nil or Canceled.
	return nil
}
