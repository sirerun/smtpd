package plugin

import (
	"context"
	"net"
)

// SessionInfo holds information about the client session.
type SessionInfo struct {
	SessionID  string      // Unique identifier for the session
	RemoteAddr net.Addr    // Network address of the client
	LocalAddr  net.Addr    // Network address the server accepted the connection on
	IsTLS      bool        // True if the connection is using TLS
	HeloDomain string      // Domain provided in HELO/EHLO
	Username   string      // Authenticated username, if available
	Data       interface{} // Plugin-specific data storage (use with care)
}

// MessageInfo holds information about the received message.
// This might be populated *after* the DATA command.
type MessageInfo struct {
	From string   // Envelope sender (from MAIL FROM)
	To   []string // Envelope recipients (from RCPT TO)
	Data []byte   // Raw message content (headers + body)
}

// Plugin defines the interface for SMTP server plugins.
// Plugins can hook into various stages of the SMTP transaction.
type Plugin interface {
	// Name returns a descriptive name for the plugin.
	Name() string

	// OnConnect is called when a new client connection is accepted,
	// before the SMTP banner is sent.
	OnConnect(ctx context.Context, session *SessionInfo) error

	// OnHelo is called after a HELO or EHLO command is received.
	OnHelo(ctx context.Context, session *SessionInfo, heloDomain string) error

	// OnMailFrom is called after a MAIL FROM command is received and parsed.
	// Returning an error rejects the command or indicates a temporary failure.
	// Returning nil accepts the command.
	OnMailFrom(ctx context.Context, session *SessionInfo, from string) error

	// OnRcptTo is called after a RCPT TO command is received and parsed.
	// Returning an error rejects the command or indicates a temporary failure.
	// Returning nil accepts the command.
	OnRcptTo(ctx context.Context, session *SessionInfo, rcptTo string) error

	// OnData is called after the DATA command is received, before the client
	// starts sending the message content.
	// Returning an error rejects the command or indicates a temporary failure.
	// Returning nil accepts the command.
	OnData(ctx context.Context, session *SessionInfo) error

	// OnMessage is called after the entire message content has been received
	// (after the final "." line).
	// Returning an error rejects the message or indicates a temporary failure.
	// Returning nil accepts the message.
	OnMessage(ctx context.Context, session *SessionInfo, msg *MessageInfo) error

	// OnDisconnect is called when the client connection is closed.
	OnDisconnect(ctx context.Context, session *SessionInfo)
}

// BasePlugin provides a default implementation of Plugin that accepts all commands.
// Plugins can embed this and override only the methods they need.
type BasePlugin struct{}

func (p *BasePlugin) Name() string {
	return "BasePlugin" // Provide a default name
}

func (p *BasePlugin) OnConnect(ctx context.Context, session *SessionInfo) error {
	return nil
}

func (p *BasePlugin) OnHelo(ctx context.Context, session *SessionInfo, heloDomain string) error {
	return nil
}

// Default implementation accepts the command by returning nil.
func (p *BasePlugin) OnMailFrom(ctx context.Context, session *SessionInfo, from string) error {
	return nil
}

// Default implementation accepts the command by returning nil.
func (p *BasePlugin) OnRcptTo(ctx context.Context, session *SessionInfo, rcptTo string) error {
	return nil
}

// Default implementation accepts the command by returning nil.
func (p *BasePlugin) OnData(ctx context.Context, session *SessionInfo) error {
	return nil
}

// Default implementation accepts the message by returning nil.
func (p *BasePlugin) OnMessage(ctx context.Context, session *SessionInfo, msg *MessageInfo) error {
	return nil
}

func (p *BasePlugin) OnDisconnect(ctx context.Context, session *SessionInfo) {
	// No default action needed
}

// Ensure BasePlugin implements Plugin
var _ Plugin = (*BasePlugin)(nil)
