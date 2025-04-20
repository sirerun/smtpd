package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mailtive/smtpd/internal/auth"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/metrics"
	"github.com/mailtive/smtpd/internal/outbound"
	"github.com/mailtive/smtpd/internal/processor"
	"github.com/mailtive/smtpd/internal/queue"
	"github.com/mailtive/smtpd/pkg/plugin"
)

// ServerConfig represents the configuration for the SMTP server
type ServerConfig struct {
	// Connection configuration
	MaxConnections    int           // Maximum number of concurrent connections
	ReadBufferSize    int           // Size of the read buffer for each connection
	WriteBufferSize   int           // Size of the write buffer for each connection
	ReadTimeout       time.Duration // Timeout for read operations
	WriteTimeout      time.Duration // Timeout for write operations
	IdleTimeout       time.Duration // Timeout for idle connections
	ShutdownTimeout   time.Duration // Timeout for graceful shutdown
	MaxMessageSize    int64         // Maximum message size in bytes
	WorkerPoolSize    int           // Size of the worker pool for connection handling
	ConnectionBacklog int           // Size of the connection queue backlog
}

// DefaultServerConfig returns the default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		MaxConnections:    1000,
		ReadBufferSize:    16 * 1024, // 16KB read buffer
		WriteBufferSize:   16 * 1024, // 16KB write buffer
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       10 * time.Minute,
		ShutdownTimeout:   30 * time.Second,
		MaxMessageSize:    32 * 1024 * 1024, // 32MB max message size
		WorkerPoolSize:    runtime.NumCPU() * 2,
		ConnectionBacklog: 128,
	}
}

// Server represents an SMTP server instance
type Server struct {
	addr      string
	listener  net.Listener
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	queue     *queue.Queue
	processor *processor.QueueProcessor
	pool      *sync.Pool
	tlsConfig *TLSConfig
	forceTLS  bool
	authStore auth.AuthStore
	plugins   []plugin.Plugin
	logger    *logging.Logger
	config    *ServerConfig

	// Connection handling
	connChan      chan net.Conn
	maxConns      int
	activeConns   int32
	connSemaphore chan struct{}
}

// NewServer creates a new SMTP server instance
// Deprecated: Use NewServerWithConfig for better control.
func NewServer(addr string, intendedPort int, tlsConfig *TLSConfig, userStore *auth.Store, plugins []plugin.Plugin, logger *logging.Logger) (*Server, error) {
	// Provide a default logger if nil is passed, though it's better practice for caller to provide one.
	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
		logger.Warn("NewServer called with nil logger, using default.")
	}
	// Pass userStore directly, as *auth.Store should implement auth.AuthStore
	return NewServerWithConfig(addr, intendedPort, tlsConfig, userStore, plugins, logger, DefaultServerConfig())
}

// NewServerWithConfig creates a new SMTP server instance with the given configuration
func NewServerWithConfig(addr string, intendedPort int, tlsConfig *TLSConfig, authStore auth.AuthStore, plugins []plugin.Plugin, logger *logging.Logger, config *ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if logger == nil {
		// Fallback, but strongly recommend providing a configured logger
		logger = logging.New(logging.DefaultConfig())
		logger.Warn("NewServerWithConfig called with nil logger, using default.")
	}

	if config == nil {
		logger.Warn("NewServerWithConfig called with nil config, using default.")
		config = DefaultServerConfig()
	}

	// Initialize the queue (pass logger)
	q := queue.NewQueue(1000, logger.WithComponent("queue"))

	// Initialize the deliverer (pass logger)
	// TODO: Make these configurable
	dkimSigners := map[string]outbound.DKIMSignerOptions{}
	heloName := "localhost"               // Should be configurable
	localDomains := []string{"localhost"} // Should be configurable
	deliverer := outbound.NewDeliverer(localDomains, dkimSigners, heloName, logger.WithComponent("outbound.deliverer"))

	// Initialize the queue processor (pass logger)
	proc := processor.NewQueueProcessor(q, deliverer, runtime.NumCPU(), logger.WithComponent("processor"))

	// Determine if TLS should be forced (port 587)
	forceTLS := false
	actualPort := 0
	if strings.Contains(addr, ":") {
		parts := strings.Split(addr, ":")
		if portStr := parts[len(parts)-1]; portStr != "0" {
			p, err := strconv.Atoi(portStr)
			if err == nil {
				actualPort = p
			}
		}
	}

	portToCheck := intendedPort
	if portToCheck == 0 {
		portToCheck = actualPort
	}

	if portToCheck == 587 {
		forceTLS = true
		if tlsConfig == nil {
			err := fmt.Errorf("TLS configuration is required for port 587")
			logger.Error("Server configuration error", "error", err)
			cancel() // Ensure context is cancelled on error path
			return nil, err
		}
		logger.Info("Port 587 detected, forcing TLS.")
	}

	srv := &Server{
		addr:          addr,
		ctx:           ctx,
		cancel:        cancel,
		queue:         q,
		processor:     proc,
		tlsConfig:     tlsConfig,
		forceTLS:      forceTLS,
		authStore:     authStore,
		plugins:       plugins,
		logger:        logger.WithComponent("server"),
		config:        config,
		connChan:      make(chan net.Conn, config.ConnectionBacklog),
		connSemaphore: make(chan struct{}, config.MaxConnections),
		// Session pool using internal logger
		pool: &sync.Pool{
			New: func() interface{} {
				// Create the session logger inside New, ensuring it's based on the current server logger config
				sessionBaseLogger := logger.WithComponent("session")
				return &Session{
					to:      make([]string, 0, 10), // Pre-allocate typical recipient count
					plugins: plugins,
					logger:  sessionBaseLogger, // Assign the component logger
					// serverConfig needed? or pass specific values?
				}
			},
		},
	}

	logger.Info("Server instance created", "addr", addr, "intendedPort", intendedPort, "forceTLS", forceTLS)
	return srv, nil
}

// Start begins listening for SMTP connections
func (s *Server) Start() error {
	var err error
	s.logger.Info("Attempting to start server...")

	// Create TLS config if needed
	var actualTLSConfig *tls.Config
	if s.forceTLS || s.tlsConfig != nil {
		if s.tlsConfig == nil {
			return fmt.Errorf("cannot start TLS: tlsConfig is nil, but TLS is required (forceTLS=%v)", s.forceTLS)
		}
		actualTLSConfig, err = s.tlsConfig.CreateTLSConfig()
		if err != nil {
			s.logger.Error("Failed to create TLS config", "error", err)
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		// Ensure minimum TLS version for compatibility & security
		actualTLSConfig.MinVersion = tls.VersionTLS12
		s.logger.Info("TLS configuration prepared")
	}

	// Start listener
	if s.forceTLS {
		s.logger.Info("Starting TLS listener directly", "address", s.addr)
		s.listener, err = tls.Listen("tcp", s.addr, actualTLSConfig)
	} else {
		s.logger.Info("Starting standard TCP listener", "address", s.addr)
		s.listener, err = net.Listen("tcp", s.addr)
	}

	if err != nil {
		s.logger.Error("Failed to start listener", "address", s.addr, "error", err)
		return fmt.Errorf("failed to start listener on %s: %w", s.addr, err)
	}
	if s.listener == nil {
		// This case should theoretically not happen if Listen returns nil error
		s.logger.Error("Listener is nil after successful Listen call", "address", s.addr)
		return fmt.Errorf("listener creation failed unexpectedly on %s", s.addr)
	}

	// Update address if port was 0
	s.addr = s.listener.Addr().String()
	s.logger.Info("Server listening",
		"address", s.addr,
		"forceTLS", s.forceTLS,
		"worker_pool_size", s.config.WorkerPoolSize,
		"max_connections", s.config.MaxConnections,
	)

	// Start the queue processor
	s.processor.Start() // Assuming Start doesn't block

	// Start the worker pool
	for i := 0; i < s.config.WorkerPoolSize; i++ {
		s.wg.Add(1)
		go s.connectionWorker(i)
	}

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections()

	s.logger.Info("Server startup sequence complete")
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.logger.Info("Stopping server...")
	s.cancel() // 1. Signal context cancellation to all routines

	listenerErr := "none"
	// 2. Stop accepting new connections immediately
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Error("Error closing listener", "error", err)
			listenerErr = err.Error()
		} else {
			s.logger.Info("Listener closed")
		}
	} else {
		s.logger.Warn("Stop called but listener was nil")
	}

	// 3. Signal workers to stop processing new connections from channel
	// Check if connChan is already closed to prevent panic
	// This requires a mutex or a select with a flag
	// TODO: Add safe closing mechanism for connChan if acceptConnections might exit early
	// For now, assume acceptConnections closes it or Stop is called once.
	// close(s.connChan)
	s.logger.Info("Connection channel closing initiated (or already closed)")

	// 4. Wait for workers and accept loop to finish with timeout
	s.logger.Info("Waiting for active connections and workers to finish...", "timeout", s.config.ShutdownTimeout)
	ctx, cancelTimeout := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancelTimeout()

	waitCh := make(chan struct{})
	go func() {
		s.wg.Wait() // Wait for accept loop and all connection handlers (via connectionWorker)
		close(waitCh)
	}()

	select {
	case <-waitCh:
		s.logger.Info("All connection handlers and workers finished cleanly.")
	case <-ctx.Done():
		s.logger.Warn("Shutdown timeout reached, server stopping possibly uncleanly.")
		// Consider logging active connection count here if tracked precisely
	}

	// 5. Stop the queue processor (waits for its workers)
	s.logger.Info("Stopping queue processor...")
	s.processor.Stop() // This should block until done
	s.logger.Info("Queue processor stopped.")

	// 6. Stop the queue itself (optional, might be handled by processor stop)
	// s.queue.Close() // Assuming Close waits if needed

	s.logger.Info("Server stopped", "listener_close_error", listenerErr)
	// TODO: Collect and return specific errors if needed
	return nil
}

// acceptConnections handles incoming connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()
	defer func() {
		// Ensure channel is closed when accept loop exits
		// Use a lock or sync.Once if Stop() might also close it
		// For simplicity now, assume this is the primary closer.
		close(s.connChan)
		s.logger.Info("Connection channel closed by accept loop exit.")
	}()
	s.logger.Info("Accept loop starting...")

	for {
		// Check for context cancellation first
		select {
		case <-s.ctx.Done():
			s.logger.Info("Accept loop stopping due to context cancellation.")
			return
		default:
			// Continue if context is not done
		}

		if s.listener == nil {
			s.logger.Error("Listener is nil, accept loop exiting.")
			return // Should not happen if Start succeeded
		}

		// Set accept deadline to allow periodic checks for context cancellation
		// Use a shorter deadline for more responsive shutdown
		deadline := time.Now().Add(500 * time.Millisecond)
		// SetDeadline might not be available on all listener types (e.g., mock listeners in tests)
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(deadline); err != nil {
				// Log warning but continue - non-critical
				s.logger.Warn("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout error, which is expected
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Normal timeout, check context and loop again
			}

			// Check if the error is because the listener was closed (part of shutdown)
			select {
			case <-s.ctx.Done():
				s.logger.Info("Accept loop detected listener closed during shutdown.")
				return // Graceful exit
			default:
				// Unexpected error
				s.logger.Error("Failed to accept connection", "error", err)
				// Consider adding a small delay for temporary errors to prevent tight loops
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					time.Sleep(50 * time.Millisecond)
				}
				continue // Try accepting again
			}
		}

		// Got a connection
		remoteAddr := conn.RemoteAddr().String()

		// Try to acquire a connection slot using the semaphore
		select {
		case s.connSemaphore <- struct{}{}:
			// Acquired slot, increment active connections metric
			metrics.ConnectionsTotal.Inc()
			metrics.ConnectionsActive.Inc()
			s.logger.Debug("Connection slot acquired", "remote_addr", remoteAddr)

			// Send the connection to the worker pool channel
			select {
			case s.connChan <- conn:
				s.logger.Debug("Connection passed to worker pool", "remote_addr", remoteAddr)
			case <-s.ctx.Done():
				// Server is shutting down while trying to queue
				s.logger.Info("Server shutting down, closing accepted connection before queuing", "remote_addr", remoteAddr)
				<-s.connSemaphore // Release semaphore
				conn.Close()
				metrics.ConnectionsActive.Dec() // Decrement active metric
			default:
				// Worker channel buffer is full (should be rare)
				<-s.connSemaphore // Release semaphore
				s.logger.Warn("Connection worker queue full, rejecting connection", "remote_addr", remoteAddr)
				conn.Close()
				metrics.ConnectionsActive.Dec() // Decrement active metric
			}
		default:
			// Max connections reached, could not acquire slot immediately
			s.logger.Warn("Max connections reached, rejecting connection",
				"remote_addr", remoteAddr,
				"max_connections", s.config.MaxConnections,
				// Consider adding current active count if available safely
			)
			conn.Close()
			// Note: Do not increment/decrement metrics here as the connection was never fully active
		}
	}
}

// connectionWorker handles connections from the connection pool
func (s *Server) connectionWorker(workerID int) {
	defer s.wg.Done()

	workerLogger := s.logger.With("worker_id", workerID)
	workerLogger.Info("Connection worker started")

	for conn := range s.connChan { // Loop exits when connChan is closed
		workerLogger.Debug("Received connection from channel")
		// Handle connection error recovery using a closure
		func(c net.Conn) {
			panicked := true // Assume panic until proven otherwise
			defer func() {
				// This defer runs after the session handling completes or panics

				// Close connection if not already closed
				// Note: session.Handle might close it on QUIT
				if err := c.Close(); err != nil {
					// Log error only if it's not related to already being closed
					if !strings.Contains(err.Error(), "use of closed network connection") {
						workerLogger.Error("Error closing connection in worker defer", "error", err)
					}
				}

				// Decrement active connection count
				metrics.ConnectionsActive.Dec()
				// Release the connection slot from the semaphore
				<-s.connSemaphore
				workerLogger.Debug("Connection slot released")

				// Recover from panic
				if r := recover(); r != nil {
					workerLogger.Error("Panic recovered in connection handler",
						"error", r,
						"stack", string(debug.Stack()),
						"remote_addr", c.RemoteAddr().String(), // Log remote addr if possible
					)
				} else {
					// No panic occurred
					panicked = false
				}

				if !panicked {
					workerLogger.Debug("Connection handling finished normally.")
				}

			}()

			remoteAddr := c.RemoteAddr().String()
			sessionID := uuid.NewString()
			// Create a logger specific to this session
			sessionLogger := s.logger.With("remote_addr", remoteAddr, "session_id", sessionID)

			// Get a session struct from the pool
			session := s.pool.Get().(*Session)

			// Reset the session state and pass dependencies
			session.Reset(c, s.queue, s.tlsConfig, s.authStore, s.plugins, sessionLogger, sessionID)
			session.forceTLS = s.forceTLS // Pass server's forceTLS setting

			// Configure session parameters from server config
			session.readTimeout = s.config.ReadTimeout
			session.writeTimeout = s.config.WriteTimeout
			session.idleTimeout = s.config.IdleTimeout
			session.maxMessageSize = s.config.MaxMessageSize

			sessionLogger.Info("Handling new session")
			// Handle the SMTP session (blocking call)
			if err := session.Handle(); err != nil {
				// Log session errors, differentiating between normal close and actual errors
				// Handle EOF or specific "connection closed" errors as Info/Debug maybe?
				if strings.Contains(err.Error(), "timeout") {
					sessionLogger.Warn("Session ended due to timeout", "error", err)
				} else if strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "forcibly closed") {
					sessionLogger.Info("Session ended due to connection closure", "error", err)
				} else {
					sessionLogger.Error("Session ended with error", "error", err)
				}
			} else {
				sessionLogger.Info("Session ended normally (QUIT received)")
			}

			// Return the session struct to the pool *before* the defer runs
			s.pool.Put(session)
			sessionLogger.Debug("Session returned to pool")

		}(conn) // Pass conn to the closure
	}

	workerLogger.Info("Connection worker stopped")
}

// Addr returns the listener address. Useful for testing with port 0.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr // Return original addr if listener not ready
}
