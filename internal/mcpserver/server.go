// Package mcpserver exposes the SMTP submission capability through MCP.
package mcpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxFieldBytes = 64 << 10

// Config contains owner-controlled SMTP settings. None are supplied by tool callers.
type Config struct {
	Host           string
	From           string
	Username       string
	Password       string
	EnableSend     bool
	AllowPlaintext bool
	Timeout        time.Duration
	TLSCAFile      string
	TLSServerName  string
	TLSMode        string
}

// Sender submits one message to the configured relay.
type Sender interface {
	Send(context.Context, Email) (string, error)
}

// Email is a single-recipient message with plain-text content.
type Email struct {
	To      string
	Subject string
	Text    string
	ReplyTo string
}

type server struct {
	cfg    Config
	sender Sender
}

// NewServer constructs a transport-independent server. Pass a nil Sender to use
// the configured SMTP adapter; tests and future integrations may inject another.
func NewServer(cfg Config, sender Sender) (*mcp.Server, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "starttls"
	}
	if cfg.EnableSend {
		if _, err := parseAddress(cfg.From); err != nil {
			return nil, fmt.Errorf("invalid configured from address: %w", err)
		}
		if cfg.Host == "" {
			return nil, errors.New("SMTP host is required when sending is enabled")
		}
		if sender == nil {
			var err error
			sender, err = NewSMTPSender(cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	s := &server{cfg: cfg, sender: sender}
	m := mcp.NewServer(&mcp.Implementation{Name: "smtpd", Version: "0.1.0"}, nil)
	falseHint, trueHint := false, true
	mcp.AddTool(m, &mcp.Tool{Name: "smtpd_preview_email", Description: "Validate and preview a single-recipient plain-text email without network activity.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &falseHint}}, s.preview)
	mcp.AddTool(m, &mcp.Tool{Name: "smtpd_send_email", Description: "Submit one email to the owner-configured SMTP relay. SMTP acceptance is not proof of delivery.", Annotations: &mcp.ToolAnnotations{DestructiveHint: &trueHint, OpenWorldHint: &trueHint}}, s.send)
	mcp.AddTool(m, &mcp.Tool{Name: "smtpd_status", Description: "Report MCP SMTP configuration status without exposing credentials.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &falseHint}}, s.status)
	return m, nil
}

type emailInput struct {
	To      string `json:"to" jsonschema:"recipient email address"`
	Subject string `json:"subject" jsonschema:"email subject"`
	Text    string `json:"text" jsonschema:"plain-text email body"`
	ReplyTo string `json:"reply_to,omitempty" jsonschema:"optional reply-to address"`
}

type emailOutput struct {
	Status  string `json:"status"`
	To      string `json:"to"`
	From    string `json:"from,omitempty"`
	Subject string `json:"subject,omitempty"`
	ReplyTo string `json:"reply_to,omitempty"`
	Message string `json:"message"`
}

func (s *server) preview(_ context.Context, _ *mcp.CallToolRequest, in emailInput) (*mcp.CallToolResult, emailOutput, error) {
	if err := validateEmail(in); err != nil {
		return nil, emailOutput{}, err
	}
	return nil, emailOutput{Status: "preview_only", To: in.To, From: s.cfg.From, Subject: in.Subject, ReplyTo: in.ReplyTo, Message: in.Text}, nil
}

func (s *server) send(ctx context.Context, _ *mcp.CallToolRequest, in emailInput) (*mcp.CallToolResult, emailOutput, error) {
	if err := validateEmail(in); err != nil {
		return nil, emailOutput{}, err
	}
	if !s.cfg.EnableSend || s.sender == nil {
		return nil, emailOutput{}, errors.New("sending is disabled; restart with --enable-send after configuring SMTP")
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	result, err := s.sender.Send(ctx, Email(in))
	if err != nil {
		return nil, emailOutput{}, err
	}
	return nil, emailOutput{Status: "accepted_by_smtp", To: in.To, From: s.cfg.From, Subject: in.Subject, Message: result}, nil
}

func (s *server) status(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
	return nil, map[string]any{"sending_enabled": s.cfg.EnableSend, "smtp_host_configured": s.cfg.Host != "", "tls_required": !s.cfg.AllowPlaintext, "from_configured": s.cfg.From != ""}, nil
}

func validateEmail(in emailInput) error {
	if _, err := parseAddress(in.To); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}
	if in.ReplyTo != "" {
		if _, err := parseAddress(in.ReplyTo); err != nil {
			return fmt.Errorf("invalid reply-to address: %w", err)
		}
	}
	if in.Subject == "" || hasControl(in.Subject) {
		return errors.New("subject is required and must not contain control characters")
	}
	if in.Text == "" || len(in.Text) > maxFieldBytes {
		return errors.New("text body is required and must be at most 64 KiB")
	}
	if len(in.To)+len(in.Subject)+len(in.Text)+len(in.ReplyTo) > 128<<10 {
		return errors.New("email payload exceeds 128 KiB")
	}
	if len(encodeHeader(in.Subject)) > 989 {
		return errors.New("encoded subject exceeds the RFC 5322 line limit")
	}
	return nil
}

func hasControl(v string) bool {
	for _, r := range v {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func parseAddress(v string) (string, error) {
	if strings.TrimSpace(v) != v || hasControl(v) {
		return "", errors.New("address contains whitespace padding or control characters")
	}
	if len(v) > 254 {
		return "", errors.New("address exceeds 254 bytes")
	}
	for _, r := range v {
		if r > 127 {
			return "", errors.New("internationalized addresses are not supported")
		}
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || strings.ContainsAny(a.Address, "\r\n") {
		return "", errors.New("expected a bare email address")
	}
	return a.Address, nil
}

// SMTPSender performs one SMTP transaction per call.
type SMTPSender struct {
	cfg       Config
	tlsConfig *tls.Config
}

func NewSMTPSender(cfg Config) (*SMTPSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("SMTP host is required")
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "starttls"
	}
	if cfg.TLSMode != "starttls" && cfg.TLSMode != "implicit" {
		return nil, errors.New("SMTP TLS mode must be starttls or implicit")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.AllowPlaintext && cfg.TLSMode == "implicit" {
		return nil, errors.New("plaintext opt-in cannot be combined with implicit TLS mode")
	}
	name := cfg.TLSServerName
	if name == "" {
		name, _, _ = net.SplitHostPort(cfg.Host)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("TLS CA file contains no usable certificates")
		}
		tc.RootCAs = pool
	}
	if cfg.Password != "" && cfg.Username == "" {
		return nil, errors.New("SMTP username is required when a password is configured")
	}
	host, port, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("SMTP host must be host:port: %w", err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("SMTP host port must be between 1 and 65535")
	}
	if cfg.AllowPlaintext {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("plaintext opt-in requires smtp-host to use a literal loopback IP address")
		}
	}
	return &SMTPSender{cfg: cfg, tlsConfig: tc}, nil
}

func (s *SMTPSender) Send(ctx context.Context, mail Email) (string, error) {
	from, err := parseAddress(s.cfg.From)
	if err != nil {
		return "", fmt.Errorf("invalid configured from address: %w", err)
	}
	to, err := parseAddress(mail.To)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}
	if err := validateEmail(emailInput(mail)); err != nil {
		return "", err
	}
	message, err := encodeMessage(from, mail)
	if err != nil {
		return "", fmt.Errorf("encode email: %w", err)
	}
	relayHost, _, _ := net.SplitHostPort(s.cfg.Host)
	plainIP := net.ParseIP(relayHost)
	plainLoopback := plainIP != nil && plainIP.IsLoopback()
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.cfg.Host)
	if err != nil {
		return "", fmt.Errorf("connect to SMTP relay: %w", err)
	}
	rawConn := conn
	stopClose := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopClose()
	defer func() { _ = rawConn.Close() }()
	if s.cfg.AllowPlaintext && !securedRemoteMatches(rawConn, plainIP) {
		return "", errors.New("SMTP connection did not reach the configured loopback IP")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	}
	secured := false
	if s.cfg.TLSMode == "implicit" {
		tlsConn := tls.Client(conn, s.tlsConfig.Clone())
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return "", fmt.Errorf("establish implicit TLS to SMTP relay: %w", err)
		}
		conn = tlsConn
		secured = true
	}
	client, err := smtp.NewClient(conn, relayHost)
	if err != nil {
		return "", fmt.Errorf("start SMTP session: %w", err)
	}
	if !secured {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(s.tlsConfig.Clone()); err != nil {
				return "", fmt.Errorf("start TLS to SMTP relay: %w", err)
			}
			secured = true
		}
	}
	if !secured && (!s.cfg.AllowPlaintext || !plainLoopback) {
		return "", errors.New("SMTP relay did not offer STARTTLS; plaintext is allowed only with explicit opt-in to a loopback IP")
	}
	if s.cfg.Username != "" {
		if !secured {
			return "", errors.New("refusing SMTP authentication without TLS")
		}
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, relayHost)
		if err := client.Auth(auth); err != nil {
			return "", fmt.Errorf("authenticate to SMTP relay: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return "", fmt.Errorf("SMTP sender rejected: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return "", fmt.Errorf("SMTP recipient rejected: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return "", fmt.Errorf("SMTP DATA was not accepted: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return "", fmt.Errorf("SMTP outcome unknown: message write failed after DATA began: %w", err)
	}
	if err := w.Close(); err != nil {
		var proto *textproto.Error
		if errors.As(err, &proto) {
			return "", fmt.Errorf("SMTP relay rejected message after DATA with code %d: %s", proto.Code, proto.Msg)
		}
		return "", fmt.Errorf("SMTP outcome unknown: final DATA response was not received: %w", err)
	}
	_ = client.Quit() // Final DATA response already confirmed acceptance.
	return "message accepted by configured SMTP relay", nil
}

func encodeMessage(from string, in Email) ([]byte, error) {
	if err := validateEmail(emailInput(in)); err != nil {
		return nil, err
	}
	to, err := parseAddress(in.To)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	_, domain, ok := strings.Cut(from, "@")
	if !ok || domain == "" {
		return nil, errors.New("configured sender must include a domain")
	}
	date := time.Now().Format(time.RFC1123Z)
	messageID := "<" + uuid.NewString() + "@" + domain + ">"
	b.WriteString("Date: ")
	b.WriteString(date)
	b.WriteString("\r\nMessage-ID: ")
	b.WriteString(messageID)
	b.WriteString("\r\n")
	b.WriteString("From: ")
	b.WriteString(from)
	b.WriteString("\r\nTo: ")
	b.WriteString(to)
	b.WriteString("\r\nSubject: ")
	b.WriteString(encodeHeader(in.Subject))
	b.WriteString("\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n")
	if in.ReplyTo != "" {
		r, e := parseAddress(in.ReplyTo)
		if e != nil {
			return nil, e
		}
		b.WriteString("Reply-To: ")
		b.WriteString(r)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(in.Text))
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return []byte(b.String()), nil
}

func encodeHeader(v string) string {
	if isASCII(v) {
		return v
	}
	var words []string
	chunk := make([]byte, 0, 42)
	flush := func() {
		if len(chunk) > 0 {
			words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString(chunk)+"?=")
			chunk = make([]byte, 0, 42)
		}
	}
	for _, r := range v {
		encoded := []byte(string(r))
		if len(chunk)+len(encoded) > 42 {
			flush()
		}
		chunk = append(chunk, encoded...)
	}
	flush()
	return strings.Join(words, "\r\n ")
}
func isASCII(v string) bool {
	for _, r := range v {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func securedRemoteMatches(conn net.Conn, expected net.IP) bool {
	if expected == nil {
		return false
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	return ok && remote.IP.Equal(expected)
}
