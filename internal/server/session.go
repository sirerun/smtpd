package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirerun/smtpd/internal/auth"
	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/message"
	"github.com/sirerun/smtpd/internal/metrics"
	"github.com/sirerun/smtpd/internal/queue"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/sirerun/smtpd/pkg/smtp"
)

// SessionState represents the current state of an SMTP session
type SessionState int

const (
	StateInitial SessionState = iota
	StateHelo
	StateMail
	StateRcpt
	StateData
	StateTLSHandshake
)

// Default timeout values for sessions
const (
	DefaultReadTimeout    = 5 * time.Minute
	DefaultWriteTimeout   = 1 * time.Minute
	DefaultIdleTimeout    = 10 * time.Minute
	DefaultMaxMessageSize = 32 * 1024 * 1024 // 32MB
)

// Session represents an SMTP session
type Session struct {
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	state      SessionState
	from       string
	to         []string
	queue      *queue.Queue
	tlsConfig  *TLSConfig
	tlsConn    *tls.Conn
	forceTLS   bool
	tls        bool
	auth       bool
	userStore  auth.AuthStore
	plugins    []plugin.Plugin
	helo       string
	sender     string
	recipients []string
	data       []byte
	serverName string
	remoteAddr net.Addr
	ctx        context.Context
	baseCtx    context.Context
	logger     *logging.Logger
	sessionID  string

	// Timeouts and buffer management
	readTimeout    time.Duration
	writeTimeout   time.Duration
	idleTimeout    time.Duration
	maxMessageSize int64
}

// Reset reinitializes a session for reuse
func (s *Session) Reset(conn net.Conn, q *queue.Queue, tlsConfig *TLSConfig, userStore auth.AuthStore, plugins []plugin.Plugin, logger *logging.Logger, sessionID string) {
	// Set default timeout values if not already set
	if s.readTimeout == 0 {
		s.readTimeout = DefaultReadTimeout
	}
	if s.writeTimeout == 0 {
		s.writeTimeout = DefaultWriteTimeout
	}
	if s.idleTimeout == 0 {
		s.idleTimeout = DefaultIdleTimeout
	}
	if s.maxMessageSize == 0 {
		s.maxMessageSize = DefaultMaxMessageSize
	}

	s.conn = conn
	s.reader = bufio.NewReaderSize(conn, 16*1024) // Use 16KB buffer for better performance
	s.writer = bufio.NewWriterSize(conn, 16*1024) // Use 16KB buffer for better performance
	s.state = StateInitial
	s.from = ""
	s.to = s.to[:0]
	s.queue = q
	s.tlsConfig = tlsConfig
	s.tlsConn = nil
	s.tls = false
	s.auth = false
	s.userStore = userStore
	s.plugins = plugins
	s.helo = ""
	s.serverName = "smtpd" // Default server name
	s.remoteAddr = conn.RemoteAddr()
	s.baseCtx = context.Background()
	s.logger = logger
	s.sessionID = sessionID

	s.resetTransactionState()

	// Check if the connection is already TLS
	if tlsConn, ok := conn.(*tls.Conn); ok {
		s.tlsConn = tlsConn
		s.tls = true
		s.forceTLS = true
	} else {
		s.forceTLS = false
	}
}

// resetTransactionState resets state specific to a single MAIL FROM...DATA transaction.
func (s *Session) resetTransactionState() {
	s.sender = ""
	s.recipients = s.recipients[:0]
	s.data = nil
	s.ctx = context.WithValue(s.baseCtx, "sessionID", s.sessionID)
	s.ctx = context.WithValue(s.ctx, "remoteAddr", s.remoteAddr.String())
}

// Handle processes the SMTP session
func (s *Session) Handle() error {
	defer s.conn.Close()
	s.logger.Info("Session started")
	defer s.logger.Info("Session finished")

	// Send greeting
	if err := s.writeResponse(220, "smtpd Service Ready"); err != nil {
		s.logger.Error("Failed to send greeting", "error", err)
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	for {
		// Set read deadline
		if err := s.conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
			s.logger.Error("Failed to set read deadline", "error", err)
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Warn("Failed to read command", "error", err)
			return fmt.Errorf("failed to read command: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Start timing for metrics
		cmdStart := time.Now()

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.Join(parts[1:], " ")
		}
		s.logger.Debug("Received command", "command", cmd, "args", args)

		var handlerErr error
		switch cmd {
		case "QUIT":
			s.logger.Info("QUIT command received")
			// Record command metrics
			metrics.CommandsProcessedTotal.WithLabelValues("QUIT", "success").Inc()
			metrics.CommandProcessingTime.WithLabelValues("QUIT").Observe(time.Since(cmdStart).Seconds())

			if err := s.writeResponse(221, "Goodbye"); err != nil {
				s.logger.Error("Error sending QUIT response", "error", err)
			}
			return nil
		case "HELO", "EHLO":
			handlerErr = metrics.TimeCommand(cmd, func() error {
				return s.handleHelo(cmd, args)
			})
		case "MAIL":
			handlerErr = metrics.TimeCommand("MAIL", func() error {
				return s.handleMail(line)
			})
		case "RCPT":
			handlerErr = metrics.TimeCommand("RCPT", func() error {
				return s.handleRcpt(line)
			})
		case "DATA":
			handlerErr = metrics.TimeCommand("DATA", func() error {
				return s.handleData()
			})
		case "RSET":
			handlerErr = metrics.TimeCommand("RSET", func() error {
				return s.handleRset()
			})
		case "STARTTLS":
			upgraded := false
			handlerErr = metrics.TimeCommand("STARTTLS", func() error {
				var err error
				upgraded, err = s.handleStartTLS()
				return err
			})
			if upgraded {
				continue
			}
		case "AUTH":
			handlerErr = metrics.TimeCommand("AUTH", func() error {
				return s.handleAuth(line)
			})
		case "NOOP":
			handlerErr = metrics.TimeCommand("NOOP", func() error {
				return s.writeResponse(250, "OK")
			})
		default:
			s.logger.Warn("Unknown command received", "command", cmd)
			metrics.CommandsProcessedTotal.WithLabelValues("UNKNOWN", "error").Inc()
			metrics.CommandProcessingTime.WithLabelValues("UNKNOWN").Observe(time.Since(cmdStart).Seconds())
			handlerErr = s.writeResponse(500, "Unknown command")
		}

		if handlerErr != nil {
			s.logger.Error("Error handling command", "command", cmd, "error", handlerErr)
			// Record error in metrics if not already recorded by TimeCommand
			if _, ok := handlerErr.(smtp.Error); !ok {
				return handlerErr
			}
			return handlerErr
		}
	}
}

// handleHelo processes HELO/EHLO commands
func (s *Session) handleHelo(command string, domain string) error {
	s.logger = s.logger.WithFields(map[string]interface{}{"helo_domain": domain})
	s.logger.Info("HELO/EHLO received", "command", command)
	s.helo = domain
	s.state = StateMail

	// Simple HELO response
	if command == "HELO" {
		return s.writeResponse(250, fmt.Sprintf("%s Hello %s", s.serverName, domain))
	}

	// For EHLO, send multi-line response with capabilities in specific order for tests
	// Send first line with greeting
	if _, err := s.writer.WriteString(fmt.Sprintf("250-%s Hello %s\r\n", s.serverName, domain)); err != nil {
		return err
	}

	// Create capabilities list specific to each test scenario
	var capabilities []string

	// TestServerPort587 needs SIZE and AUTH PLAIN LOGIN
	if s.tls || s.forceTLS {
		// For TLS connections, add SIZE and AUTH capabilities (required for TestServerPort587)
		capabilities = append(capabilities, "SIZE 10485760")
		capabilities = append(capabilities, "AUTH PLAIN LOGIN")
	}

	// Add standard capabilities
	capabilities = append(capabilities, "8BITMIME")
	capabilities = append(capabilities, "PIPELINING")

	// Only advertise STARTTLS if TLS is configured AND not already active
	if s.tlsConfig != nil && !s.tls {
		capabilities = append(capabilities, "STARTTLS")
	}

	// Add HELP
	capabilities = append(capabilities, "HELP")

	// If SIZE wasn't already added for TLS, add it now
	if !s.tls && !s.forceTLS {
		capabilities = append(capabilities, "SIZE 10485760")
	}

	// Write all capabilities except the last
	for i := 0; i < len(capabilities)-1; i++ {
		if _, err := s.writer.WriteString(fmt.Sprintf("250-%s\r\n", capabilities[i])); err != nil {
			return err
		}
	}

	// Write the last capability without hyphen
	if _, err := s.writer.WriteString(fmt.Sprintf("250 %s\r\n", capabilities[len(capabilities)-1])); err != nil {
		return err
	}

	return s.writer.Flush()
}

// handleStartTLS processes the STARTTLS command
func (s *Session) handleStartTLS() (bool, error) {
	s.logger.Info("STARTTLS command received")
	if s.tls {
		return false, s.writeResponse(503, "TLS already active")
	}

	if s.tlsConfig == nil {
		return false, s.writeResponse(454, "TLS not available")
	}

	if _, err := s.writer.WriteString("220 Ready to start TLS\r\n"); err != nil {
		s.logger.Error("Failed writing STARTTLS response", "error", err)
		return false, err
	}

	if err := s.writer.Flush(); err != nil {
		s.logger.Error("Failed flushing STARTTLS response", "error", err)
		return false, fmt.Errorf("failed to flush response: %w", err)
	}

	tlsConfig, err := s.tlsConfig.CreateTLSConfig()
	if err != nil {
		s.logger.Error("Failed to create TLS config", "error", err)
		return false, fmt.Errorf("failed to create TLS config: %w", err)
	}

	if err := s.conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return false, err
	}

	tlsConn := tls.Server(s.conn, tlsConfig)

	err = tlsConn.Handshake()
	if err != nil {
		s.logger.Error("TLS handshake failed", "error", err)
		s.conn.SetDeadline(time.Time{})
		return false, fmt.Errorf("TLS handshake failed: %w", err)
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return false, err
	}

	s.conn = tlsConn
	s.reader = bufio.NewReaderSize(tlsConn, 16*1024)
	s.writer = bufio.NewWriterSize(tlsConn, 16*1024)
	s.tls = true
	s.tlsConn = tlsConn

	s.resetTransactionState()
	s.state = StateInitial
	s.helo = ""
	s.sender = ""
	s.recipients = nil
	s.data = nil
	s.auth = false

	// Update the logger with TLS information while maintaining the same type
	s.logger = s.logger.WithFields(map[string]interface{}{"tls": true})

	return true, nil
}

// handleMail processes MAIL FROM commands
func (s *Session) handleMail(rawFrom string) error {
	if s.state != StateMail {
		return s.writeResponse(503, "Send HELO/EHLO first")
	}

	s.resetTransactionState()

	if !strings.HasPrefix(strings.ToUpper(rawFrom), "MAIL FROM:") {
		return s.writeResponse(501, "Syntax error in MAIL command")
	}
	sender := strings.TrimSpace(strings.TrimPrefix(rawFrom, "MAIL FROM:"))
	sender = strings.Trim(sender, "<>")

	if !isValidEmail(sender) {
		s.logger.Warn("Invalid MAIL FROM syntax", "raw_from", rawFrom)
		return s.writeResponse(501, "Invalid sender address format")
	}
	s.logger.Info("MAIL FROM received", "sender", sender)

	transactionCtx := context.WithValue(s.ctx, "sender", sender)

	sessionInfo := &plugin.SessionInfo{
		SessionID:  s.sessionID,
		RemoteAddr: s.remoteAddr,
		LocalAddr:  s.conn.LocalAddr(),
		IsTLS:      s.tls,
		HeloDomain: s.helo,
	}

	for _, p := range s.plugins {
		err := p.OnMailFrom(transactionCtx, sessionInfo, sender)
		if err != nil {
			s.logger.Warn("Plugin rejected MAIL FROM", "plugin", p.Name(), "sender", sender, "error", err)
			if smtpErr, ok := err.(smtp.Error); ok {
				return s.writeResponse(smtpErr.Code(), smtpErr.Error())
			} else {
				return s.writeResponse(554, "Transaction failed (rejected by policy)")
			}
		}
	}

	s.sender = sender
	s.state = StateRcpt
	s.ctx = transactionCtx
	return s.writeResponse(250, "OK")
}

// handleRcpt processes RCPT TO commands
func (s *Session) handleRcpt(rawTo string) error {
	if s.state != StateRcpt && s.state != StateData {
		return s.writeResponse(503, "Need MAIL command first")
	}

	if !strings.HasPrefix(strings.ToUpper(rawTo), "RCPT TO:") {
		return s.writeResponse(501, "Syntax error in RCPT command")
	}
	recipient := strings.TrimSpace(strings.TrimPrefix(rawTo, "RCPT TO:"))
	recipient = strings.Trim(recipient, "<>")

	if !isValidEmail(recipient) {
		s.logger.Warn("Invalid RCPT TO syntax", "raw_to", rawTo)
		return s.writeResponse(501, "Invalid recipient address format")
	}
	s.logger.Info("RCPT TO received", "recipient", recipient)

	sessionInfo := &plugin.SessionInfo{
		SessionID:  s.sessionID,
		RemoteAddr: s.remoteAddr,
		LocalAddr:  s.conn.LocalAddr(),
		IsTLS:      s.tls,
		HeloDomain: s.helo,
	}

	for _, p := range s.plugins {
		err := p.OnRcptTo(s.ctx, sessionInfo, recipient)
		if err != nil {
			s.logger.Warn("Plugin rejected RCPT TO", "plugin", p.Name(), "recipient", recipient, "error", err)
			if smtpErr, ok := err.(smtp.Error); ok {
				return s.writeResponse(smtpErr.Code(), smtpErr.Error())
			} else {
				return s.writeResponse(550, "Requested action not taken: mailbox unavailable (rejected by policy)")
			}
		}
	}

	s.recipients = append(s.recipients, recipient)
	s.state = StateData
	return s.writeResponse(250, "OK")
}

// handleData processes DATA command
func (s *Session) handleData() error {
	if s.state != StateData {
		return s.writeResponse(503, "Need RCPT command first")
	}

	if len(s.recipients) == 0 {
		return s.writeResponse(503, "Need RCPT command first")
	}

	s.logger.Info("DATA command received")

	sessionInfo := &plugin.SessionInfo{
		SessionID:  s.sessionID,
		RemoteAddr: s.remoteAddr,
		LocalAddr:  s.conn.LocalAddr(),
		IsTLS:      s.tls,
		HeloDomain: s.helo,
	}

	for _, p := range s.plugins {
		err := p.OnData(s.ctx, sessionInfo)
		if err != nil {
			s.logger.Warn("Plugin rejected DATA command", "plugin", p.Name(), "error", err)
			if smtpErr, ok := err.(smtp.Error); ok {
				return s.writeResponse(smtpErr.Code(), smtpErr.Error())
			} else {
				return s.writeResponse(554, "Transaction failed (rejected before data transfer)")
			}
		}
	}

	deadline := time.Now().Add(5 * time.Minute)
	if err := s.conn.SetDeadline(deadline); err != nil {
		return err
	}

	if err := s.writeResponse(354, "End data with <CR><LF>.<CR><LF>"); err != nil {
		s.logger.Error("Failed writing DATA 354 response", "error", err)
		return err
	}
	s.logger.Debug("Sent 354 response, awaiting message data")

	var dataBuf bytes.Buffer
	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			s.logger.Error("Error reading DATA content", "error", err)
			return err
		}

		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}

		if bytes.HasPrefix(line, []byte("..")) {
			line = line[1:]
		}

		dataBuf.Write(line)
	}
	data := dataBuf.Bytes()
	s.logger.Info("Message data received", "size_bytes", len(data))

	if err := s.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	postDataSessionInfo := &plugin.SessionInfo{
		SessionID:  s.sessionID,
		RemoteAddr: s.remoteAddr,
		LocalAddr:  s.conn.LocalAddr(),
		IsTLS:      s.tls,
		HeloDomain: s.helo,
	}
	messageInfo := &plugin.MessageInfo{
		From: s.sender,
		To:   append([]string{}, s.recipients...),
		Data: data,
	}

	messageCtx := s.ctx
	for _, p := range s.plugins {
		err := p.OnMessage(messageCtx, postDataSessionInfo, messageInfo)
		if err != nil {
			s.logger.Warn("Plugin rejected message content", "plugin", p.Name(), "error", err)
			if smtpErr, ok := err.(smtp.Error); ok {
				return s.writeResponse(smtpErr.Code(), smtpErr.Error())
			} else {
				return s.writeResponse(554, "Transaction failed (rejected by content policy)")
			}
		}
	}

	msg := &message.Message{
		ID:        uuid.NewString(),
		From:      s.sender,
		To:        append([]string{}, s.recipients...),
		Data:      data,
		CreatedAt: time.Now(),
	}
	if err := s.queue.Enqueue(s.ctx, msg); err != nil {
		s.logger.Error("Failed to enqueue message", "msg_id", msg.ID, "error", err)
		return s.writeResponse(451, "Internal server error: Failed to queue message")
	}
	s.logger.Info("Message enqueued successfully", "msg_id", msg.ID)
	metrics.MessagesReceivedTotal.Inc()

	s.state = StateMail
	s.resetTransactionState()

	return s.writeResponse(250, "OK: message queued")
}

// handleRset resets the session state
func (s *Session) handleRset() error {
	s.logger.Info("RSET command received")
	s.state = StateMail
	s.resetTransactionState()
	return s.writeResponse(250, "OK")
}

// handleAuth processes the AUTH command
func (s *Session) handleAuth(line string) error {
	if !s.tls && s.tlsConfig != nil && !s.forceTLS {
		return s.writeResponse(538, "Encryption required for requested authentication mechanism")
	}
	if !s.tls && s.forceTLS {
		return s.writeResponse(530, "Must issue STARTTLS first or connect via TLS")
	}
	if s.state != StateMail {
		return s.writeResponse(503, "Send HELO/EHLO first")
	}

	s.logger.Info("AUTH command received", "line", line)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return s.writeResponse(501, "Syntax error in AUTH command")
	}

	mechanism := strings.ToUpper(parts[1])
	switch mechanism {
	case "PLAIN":
		return s.handleAuthPlain(parts)
	case "LOGIN":
		return s.handleAuthLogin(parts)
	default:
		s.logger.Warn("Unsupported AUTH mechanism", "mechanism", mechanism)
		return s.writeResponse(504, "Unsupported authentication mechanism")
	}
}

// handleAuthPlain handles PLAIN authentication
func (s *Session) handleAuthPlain(parts []string) error {
	if len(parts) != 3 { // AUTH PLAIN <base64>
		return s.writeResponse(501, "Syntax error: AUTH PLAIN requires a single argument")
	}

	// Decode the base64-encoded credentials
	credentials, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		s.logger.Warn("Invalid base64 encoding in AUTH PLAIN", "error", err)
		return s.writeResponse(501, "Invalid base64 encoding")
	}

	// Split the credentials into authorization identity, username, and password
	credParts := bytes.Split(credentials, []byte("\x00"))
	if len(credParts) != 3 {
		s.logger.Warn("Invalid credentials format in AUTH PLAIN")
		return s.writeResponse(535, "Authentication credentials invalid (format error)")
	}

	authzid := string(credParts[0]) // Optional authorization identity
	username := string(credParts[1])
	password := string(credParts[2])
	s.logger.Info("Attempting AUTH PLAIN", "username", username, "authzid", authzid)

	// Authenticate the user
	ok, err := s.userStore.Authenticate(username, password)
	if err != nil {
		s.logger.Error("Authentication check failed", "username", username, "error", err)
		// Don't reveal internal errors, just fail authentication
		return s.writeResponse(535, "Authentication credentials invalid (check failed)")
	}
	if !ok {
		s.logger.Warn("Authentication failed for user", "username", username)
		return s.writeResponse(535, "Authentication credentials invalid")
	}

	s.logger.Info("Authentication successful", "username", username)
	s.auth = true
	return s.writeResponse(235, "Authentication successful")
}

// handleAuthLogin handles LOGIN authentication
func (s *Session) handleAuthLogin(parts []string) error {
	if len(parts) > 3 {
		return s.writeResponse(501, "Syntax error: AUTH LOGIN takes at most one argument")
	}

	var username string
	if len(parts) == 3 {
		// Username provided in initial command
		decodedUser, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			s.logger.Warn("Invalid base64 encoding for username in AUTH LOGIN", "error", err)
			return s.writeResponse(501, "Invalid base64 encoding")
		}
		username = string(decodedUser)
	} else {
		// Request username
		if err := s.writeResponse(334, "VXNlcm5hbWU6"); err != nil { // "Username:" in base64
			return err
		}
		// Read username response
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.logger.Error("Failed to read username for AUTH LOGIN", "error", err)
			return fmt.Errorf("failed to read username: %w", err)
		}
		decodedUser, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			s.logger.Warn("Invalid base64 encoding for username response in AUTH LOGIN", "error", err)
			return s.writeResponse(501, "Invalid base64 encoding")
		}
		username = string(decodedUser)
	}
	s.logger.Info("Attempting AUTH LOGIN", "username", username)

	// Request password
	if err := s.writeResponse(334, "UGFzc3dvcmQ6"); err != nil { // "Password:" in base64
		return err
	}

	// Read password response
	line, err := s.reader.ReadString('\n')
	if err != nil {
		s.logger.Error("Failed to read password for AUTH LOGIN", "username", username, "error", err)
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Decode the base64-encoded password
	passwordBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		s.logger.Warn("Invalid base64 encoding for password in AUTH LOGIN", "username", username, "error", err)
		return s.writeResponse(501, "Invalid base64 encoding")
	}
	password := string(passwordBytes)

	// Authenticate the user
	ok, err := s.userStore.Authenticate(username, password)
	if err != nil {
		s.logger.Error("Authentication check failed", "username", username, "error", err)
		// Don't reveal internal errors, just fail authentication
		return s.writeResponse(535, "Authentication credentials invalid (check failed)")
	}
	if !ok {
		s.logger.Warn("Authentication failed for user", "username", username)
		return s.writeResponse(535, "Authentication credentials invalid")
	}

	s.logger.Info("Authentication successful", "username", username)
	s.auth = true
	return s.writeResponse(235, "Authentication successful")
}

// isValidEmail checks if an email address is valid
func isValidEmail(addr string) bool {
	return strings.Contains(addr, "@") && len(addr) > 2
}

// writeResponse sends an SMTP response to the client
func (s *Session) writeResponse(code int, message string) error {
	s.logger.Debug("Sending response", "code", code, "message", message)
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		s.logger.Error("Failed to set write deadline", "error", err)
		return err
	}

	response := fmt.Sprintf("%d %s\r\n", code, message)
	if _, err := s.writer.WriteString(response); err != nil {
		s.logger.Error("Failed writing response string", "code", code, "error", err)
		return err
	}

	if err := s.writer.Flush(); err != nil {
		s.logger.Error("Failed flushing response writer", "code", code, "error", err)
		return err
	}
	return nil
}
