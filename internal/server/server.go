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
	"github.com/sirerun/smtpd/internal/auth"
	"github.com/sirerun/smtpd/internal/config"
	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/metrics"
	"github.com/sirerun/smtpd/pkg/outbound"
	"github.com/sirerun/smtpd/internal/processor"
	"github.com/sirerun/smtpd/internal/queue"
	"github.com/sirerun/smtpd/pkg/plugin"
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

// defaultNetResolver wraps net.DefaultResolver to satisfy the outbound.Resolver interface.
type defaultNetResolver struct{}

// LookupMX performs a DNS MX lookup using the default resolver.
func (r *defaultNetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

// noopMetricsRecorder implements outbound.MetricsRecorderInterface for testing/default use.
type noopMetricsRecorder struct{}

// RecordMessageStatusByDomain is a no-op.
func (m *noopMetricsRecorder) RecordMessageStatusByDomain(status string, domain string) {}

// RecordDeliveryTime is a no-op.
func (m *noopMetricsRecorder) RecordDeliveryTime(duration time.Duration, domain string) {}

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
	authStore    auth.AuthStore
	jwtValidator auth.JWTValidator
	plugins      []plugin.Plugin
	logger    *logging.Logger
	config    *config.ServerConfig

	// Connection handling
	connChan      chan net.Conn
	maxConns      int
	activeConns   int32
	connSemaphore chan struct{}
}

// ServerOptions holds all dependencies for creating a server
type ServerOptions struct {
	Config           *config.Config
	Logger           *logging.Logger
	Queue            *queue.Queue
	PluginManager    *plugin.Manager
	Resolver         outbound.Resolver
	Dialer           outbound.Dialer
	MetricsRecorder  outbound.MetricsRecorderInterface
	DelivererFactory func(
		localDomains []string,
		dkimOptions map[string]outbound.DKIMSignerOptions,
		heloName string,
		resolver outbound.Resolver,
		clientPool outbound.SMTPClientPoolInterface,
		logger outbound.LoggerInterface,
		metricsRecorder outbound.MetricsRecorderInterface,
	) (*outbound.Deliverer, error)
	SMTPClientPoolFactory func(
		cfg interface{},
		dialer outbound.Dialer,
		logger outbound.LoggerInterface,
	) outbound.SMTPClientPoolInterface
}

// NewServerWithOptions creates a server with customizable dependencies for testing
func NewServerWithOptions(opts ServerOptions) (*Server, error) {
	// Set defaults for nil dependencies
	var logger *logging.Logger
	if opts.Logger == nil {
		logger = logging.New(logging.DefaultConfig())
		logger.Warn("NewServerWithOptions called with nil logger, using default.")
	} else {
		logger = opts.Logger
	}

	if opts.Config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if opts.Queue == nil {
		return nil, fmt.Errorf("queue cannot be nil")
	}

	if opts.PluginManager == nil {
		return nil, fmt.Errorf("plugin manager cannot be nil")
	}

	// --- Outbound Setup ---
	logger.Info("Setting up outbound components")

	// 1. Create Logger Adapter
	loggerAdapter := outbound.NewLoggerAdapter(logger.WithComponent("outbound"))

	// 2. Create or use provided Metrics Adapter
	var metricsAdapter outbound.MetricsRecorderInterface
	if opts.MetricsRecorder == nil {
		metricsAdapter = &noopMetricsRecorder{}
		logger.Info("Using no-op metrics recorder for outbound")
	} else {
		metricsAdapter = opts.MetricsRecorder
		logger.Info("Using provided metrics recorder for outbound")
	}

	// 3. Create or use provided Dialer
	var dialer outbound.Dialer
	if opts.Dialer == nil {
		dialer = &net.Dialer{
			Timeout: opts.Config.Outbound.SMTPClient.ConnectTimeout,
		}
		logger.Info("Created default dialer", "timeout", opts.Config.Outbound.SMTPClient.ConnectTimeout)
	} else {
		dialer = opts.Dialer
		logger.Info("Using provided dialer")
	}

	// 4. Create SMTP Client Pool
	var clientPool outbound.SMTPClientPoolInterface
	if opts.SMTPClientPoolFactory == nil {
		// Convert config.SMTPClientConfig to outbound.SMTPClientConfig
		outboundClientConfig := convertSMTPClientConfig(opts.Config.Outbound.SMTPClient)
		clientPool = outbound.NewSMTPClientPool(outboundClientConfig, dialer, loggerAdapter)
	} else {
		// For custom factory, still pass the converted config
		outboundClientConfig := convertSMTPClientConfig(opts.Config.Outbound.SMTPClient)
		clientPool = opts.SMTPClientPoolFactory(outboundClientConfig, dialer, loggerAdapter)
	}
	logger.Info("SMTP client pool configured", "max_conns", opts.Config.Outbound.SMTPClient.MaxConnections)

	// 5. Create or use provided Resolver
	var resolver outbound.Resolver
	if opts.Resolver == nil {
		resolver = &defaultNetResolver{}
		logger.Info("Using default DNS resolver")
	} else {
		resolver = opts.Resolver
		logger.Info("Using provided DNS resolver")
	}

	// 6. Prepare DKIM Signer Options
	dkimSignerOptions := make(map[string]outbound.DKIMSignerOptions)
	for domain, dkimCfg := range opts.Config.Outbound.DKIM {
		logger.Info("Loading DKIM key", "domain", domain, "selector", dkimCfg.Selector)
		pk, err := config.LoadPrivateKey(dkimCfg.PrivateKeyPath)
		if err != nil {
			logger.Error("Failed to load DKIM private key", "domain", domain, "path", dkimCfg.PrivateKeyPath, "error", err)
			continue
		}
		dkimSignerOptions[domain] = outbound.DKIMSignerOptions{
			Domain:     domain,
			Selector:   dkimCfg.Selector,
			PrivateKey: pk,
			Signer:     &outbound.DefaultDKIMSigner{},
		}
	}

	// 7. Create Deliverer
	var deliverer *outbound.Deliverer
	var err error
	if opts.DelivererFactory == nil {
		deliverer, err = outbound.NewDeliverer(
			opts.Config.Server.LocalDomains,
			dkimSignerOptions,
			opts.Config.Server.Hostname,
			resolver,
			clientPool,
			loggerAdapter,
			metricsAdapter,
		)
	} else {
		deliverer, err = opts.DelivererFactory(
			opts.Config.Server.LocalDomains,
			dkimSignerOptions,
			opts.Config.Server.Hostname,
			resolver,
			clientPool,
			loggerAdapter,
			metricsAdapter,
		)
	}

	if err != nil {
		logger.Error("Failed to create outbound deliverer", "error", err)
		return nil, fmt.Errorf("failed to initialize outbound deliverer: %w", err)
	}
	logger.Info("Outbound deliverer created successfully")

	// Initialize the queue processor
	m := metrics.NewMetrics()
	proc := processor.NewQueueProcessor(opts.Queue, deliverer, runtime.NumCPU(), logger.WithComponent("processor"), m)

	// Determine if TLS should be forced
	forceTLS := false
	listenAddr := opts.Config.Server.ListenAddr
	portToCheck := opts.Config.Server.Port

	// Logic to determine actual port and check against SubmissionPort
	if strings.Contains(listenAddr, ":") {
		parts := strings.Split(listenAddr, ":")
		if portStr := parts[len(parts)-1]; portStr != "0" {
			p, err := strconv.Atoi(portStr)
			if err == nil {
				// If port in address is set, it overrides the main Port config for checking 587
				if portToCheck == 0 || portToCheck == 25 { // Only override if main port is default/unset
					portToCheck = p
				}
			}
		}
	} else {
		// If no port in ListenAddr, construct full address with Port
		listenAddr = net.JoinHostPort(listenAddr, strconv.Itoa(portToCheck))
	}

	if portToCheck == opts.Config.Server.SubmissionPort && portToCheck != 0 {
		forceTLS = true
		if !opts.Config.Security.TLSEnabled || opts.Config.Security.TLSCertFile == "" || opts.Config.Security.TLSKeyFile == "" {
			err := fmt.Errorf("TLS configuration (enabled, cert, key) is required for submission port %d", opts.Config.Server.SubmissionPort)
			logger.Error("Server configuration error", "error", err)
			return nil, err
		}
		logger.Info("Submission port detected, forcing TLS.", "port", portToCheck)
	}

	// Create TLSConfig
	var tlsCfg *TLSConfig
	if opts.Config.Security.TLSEnabled {
		tlsCfg, err = NewTLSConfig(opts.Config.Security.TLSCertFile, opts.Config.Security.TLSKeyFile, "")
		if err != nil {
			logger.Error("Failed to create TLS config from security settings", "error", err)
			return nil, fmt.Errorf("failed to load TLS cert/key: %w", err)
		}
		logger.Info("TLS configuration loaded from security settings")
	}

	// Create AuthStore
	authStore, err := opts.Config.CreateAuthStore(logger)
	if err != nil {
		logger.Error("Failed to create auth store", "error", err)
		return nil, fmt.Errorf("failed to create auth store: %w", err)
	}
	if authStore != nil {
		logger.Info("Auth store created")
	}

	// Create Server instance
	srv := &Server{
		addr:          listenAddr,
		queue:         opts.Queue,
		processor:     proc,
		tlsConfig:     tlsCfg,
		forceTLS:      forceTLS,
		authStore:     authStore,
		plugins:       opts.PluginManager.Plugins(), // Use the accessor method
		logger:        logger.WithComponent("server"),
		config:        &opts.Config.Server,
		connChan:      make(chan net.Conn, opts.Config.Server.ConnectionBacklog),
		connSemaphore: make(chan struct{}, opts.Config.Server.MaxConnections),
		pool: &sync.Pool{
			New: func() interface{} {
				sessionBaseLogger := logger.WithComponent("session")
				return &Session{
					to:      make([]string, 0, 10),
					plugins: opts.PluginManager.Plugins(), // Use the accessor method
					logger:  sessionBaseLogger,
				}
			},
		},
	}

	srv.ctx, srv.cancel = context.WithCancel(context.Background())

	logger.Info("Server instance created", "addr", srv.addr, "forceTLS", srv.forceTLS)
	return srv, nil
}

// NewServer creates a new SMTP server instance using the standard configuration.
func NewServer(cfg *config.Config, logger *logging.Logger, pm *plugin.Manager, q *queue.Queue) (*Server, error) {
	return NewServerWithOptions(ServerOptions{
		Config:        cfg,
		Logger:        logger,
		Queue:         q,
		PluginManager: pm,
	})
}

// Start begins listening for SMTP connections
func (s *Server) Start() error {
	var err error
	s.logger.Info("Attempting to start server...")

	// Create actual *tls.Config if needed (using s.tlsConfig which is *server.TLSConfig)
	var actualTLSConfig *tls.Config
	if s.forceTLS || s.tlsConfig != nil {
		if s.tlsConfig == nil {
			// This case should be prevented by NewServer checks if forceTLS is true
			return fmt.Errorf("cannot start TLS: server.tlsConfig is nil, but TLS is required (forceTLS=%v)", s.forceTLS)
		}
		actualTLSConfig, err = s.tlsConfig.CreateTLSConfig()
		if err != nil {
			s.logger.Error("Failed to create *tls.Config", "error", err)
			return fmt.Errorf("failed to create *tls.Config: %w", err)
		}
		actualTLSConfig.MinVersion = tls.VersionTLS12 // Enforce minimum TLS version
		s.logger.Info("Actual *tls.Config prepared for listener")
	}

	// Start listener
	if s.forceTLS {
		if actualTLSConfig == nil {
			// Should not happen due to checks above and in NewServer
			return fmt.Errorf("internal error: forceTLS is true but actualTLSConfig is nil")
		}
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
		s.logger.Error("Listener is nil after successful Listen call", "address", s.addr)
		return fmt.Errorf("listener creation failed unexpectedly on %s", s.addr)
	}

	s.addr = s.listener.Addr().String()
	s.logger.Info("Server listening",
		"address", s.addr,
		"forceTLS", s.forceTLS,
		"worker_pool_size", s.config.WorkerPoolSize,
		"max_connections", s.config.MaxConnections,
	)

	s.processor.Start()

	for i := 0; i < s.config.WorkerPoolSize; i++ {
		s.wg.Add(1)
		go s.connectionWorker(i)
	}

	s.wg.Add(1)
	go s.acceptConnections()

	s.logger.Info("Server startup sequence complete")
	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	s.logger.Info("Stopping server...")
	s.cancel()

	listenerErr := "none"
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

	s.logger.Info("Connection channel closing initiated (or already closed)")

	s.logger.Info("Waiting for active connections and workers to finish...", "timeout", s.config.ShutdownTimeout)
	ctx, cancelTimeout := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancelTimeout()

	waitCh := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		s.logger.Info("All connection handlers and workers finished cleanly.")
	case <-ctx.Done():
		s.logger.Warn("Shutdown timeout reached, server stopping possibly uncleanly.")
	}

	s.logger.Info("Stopping queue processor...")
	s.processor.Stop()
	s.logger.Info("Queue processor stopped.")

	s.logger.Info("Server stopped", "listener_close_error", listenerErr)
	return nil
}

// acceptConnections handles incoming connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()
	defer func() {
		close(s.connChan)
		s.logger.Info("Connection channel closed by accept loop exit.")
	}()
	s.logger.Info("Accept loop starting...")

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("Accept loop stopping due to context cancellation.")
			return
		default:
		}

		if s.listener == nil {
			s.logger.Error("Listener is nil, accept loop exiting.")
			return
		}

		deadline := time.Now().Add(500 * time.Millisecond)
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			if err := tcpListener.SetDeadline(deadline); err != nil {
				s.logger.Warn("Failed to set accept deadline", "error", err)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-s.ctx.Done():
				s.logger.Info("Accept loop detected listener closed during shutdown.")
				return
			default:
				s.logger.Error("Failed to accept connection", "error", err)
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					time.Sleep(50 * time.Millisecond)
				}
				continue
			}
		}

		remoteAddr := conn.RemoteAddr().String()

		select {
		case s.connSemaphore <- struct{}{}:
			metrics.ConnectionsTotal.Inc()
			metrics.ConnectionsActive.Inc()
			s.logger.Debug("Connection slot acquired", "remote_addr", remoteAddr)

			select {
			case s.connChan <- conn:
				s.logger.Debug("Connection passed to worker pool", "remote_addr", remoteAddr)
			case <-s.ctx.Done():
				s.logger.Info("Server shutting down, closing accepted connection before queuing", "remote_addr", remoteAddr)
				<-s.connSemaphore
				conn.Close()
				metrics.ConnectionsActive.Dec()
			default:
				<-s.connSemaphore
				s.logger.Warn("Connection worker queue full, rejecting connection", "remote_addr", remoteAddr)
				conn.Close()
				metrics.ConnectionsActive.Dec()
			}
		default:
			s.logger.Warn("Max connections reached, rejecting connection",
				"remote_addr", remoteAddr,
				"max_connections", s.config.MaxConnections,
			)
			conn.Close()
		}
	}
}

// connectionWorker handles connections from the connection pool
func (s *Server) connectionWorker(workerID int) {
	defer s.wg.Done()

	workerLogger := s.logger.With("worker_id", workerID)
	workerLogger.Info("Connection worker started")

	for conn := range s.connChan {
		workerLogger.Debug("Received connection from channel")
		func(c net.Conn) {
			panicked := true
			defer func() {
				if err := c.Close(); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						workerLogger.Error("Error closing connection in worker defer", "error", err)
					}
				}

				metrics.ConnectionsActive.Dec()
				<-s.connSemaphore
				workerLogger.Debug("Connection slot released")

				if r := recover(); r != nil {
					workerLogger.Error("Panic recovered in connection handler",
						"error", r,
						"stack", string(debug.Stack()),
						"remote_addr", c.RemoteAddr().String(),
					)
				} else {
					panicked = false
				}

				if !panicked {
					workerLogger.Debug("Connection handling finished normally.")
				}

			}()

			remoteAddr := c.RemoteAddr().String()
			sessionID := uuid.NewString()
			sessionLogger := s.logger.WithFields(map[string]interface{}{
				"remote_addr": remoteAddr,
				"session_id":  sessionID,
			})

			session := s.pool.Get().(*Session)

			session.Reset(c, s.queue, s.tlsConfig, s.authStore, s.jwtValidator, s.plugins, sessionLogger, sessionID)
			session.forceTLS = s.forceTLS

			// Use values from s.config (which is *config.ServerConfig)
			session.readTimeout = s.config.ReadTimeout
			session.writeTimeout = s.config.WriteTimeout
			session.idleTimeout = s.config.IdleTimeout
			session.maxMessageSize = s.config.MaxMessageSize

			sessionLogger.Info("Handling new session")
			if err := session.Handle(); err != nil {
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

			s.pool.Put(session)
			sessionLogger.Debug("Session returned to pool")

		}(conn)
	}

	workerLogger.Info("Connection worker stopped")
}

// Addr returns the listener address. Useful for testing with port 0.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// convertSMTPClientConfig converts from config.SMTPClientConfig to outbound.SMTPClientConfig
func convertSMTPClientConfig(cfg config.SMTPClientConfig) outbound.SMTPClientConfig {
	// Create a default config first to ensure all fields are set
	outboundConfig := outbound.DefaultSMTPClientConfig()

	// Override with values from config
	outboundConfig.ConnectTimeout = cfg.ConnectTimeout
	outboundConfig.MaxConnections = cfg.MaxConnections
	outboundConfig.IdleTimeout = cfg.IdleTimeout

	return outboundConfig
}
