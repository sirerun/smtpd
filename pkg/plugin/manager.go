package plugin

import (
	"context"
	// "net" // Unused
	"sync"
)

// Manager handles the registration and execution of multiple plugins.
type Manager struct {
	plugins []Plugin
	mu      sync.RWMutex
}

// NewManager creates a new plugin manager.
func NewManager() *Manager {
	return &Manager{
		plugins: make([]Plugin, 0),
	}
}

// Register adds a new plugin to the manager.
func (m *Manager) Register(p Plugin) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plugins = append(m.plugins, p)
}

// Plugins returns a copy of the current plugins list.
// This provides thread-safe read-only access to the plugins.
func (m *Manager) Plugins() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]Plugin, len(m.plugins))
	copy(result, m.plugins)
	return result
}

// ExecuteOnMailFrom executes the OnMailFrom hook for all registered plugins.
// It stops and returns the first error encountered.
func (m *Manager) ExecuteOnMailFrom(ctx context.Context, session *SessionInfo, from string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnMailFrom(ctx, session, from); err != nil {
			// TODO: Log which plugin returned the error?
			return err // Return the first error
		}
	}
	return nil // All plugins accepted
}

// ExecuteOnRcptTo executes the OnRcptTo hook for all registered plugins.
// It stops and returns the first error encountered.
func (m *Manager) ExecuteOnRcptTo(ctx context.Context, session *SessionInfo, rcptTo string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnRcptTo(ctx, session, rcptTo); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteOnData executes the OnData hook for all registered plugins.
// It stops and returns the first error encountered.
func (m *Manager) ExecuteOnData(ctx context.Context, session *SessionInfo) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnData(ctx, session); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteOnMessage executes the OnMessage hook for all registered plugins.
// It stops and returns the first error encountered.
func (m *Manager) ExecuteOnMessage(ctx context.Context, session *SessionInfo, msg *MessageInfo) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnMessage(ctx, session, msg); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteOnDisconnect executes the OnDisconnect hook for all registered plugins.
func (m *Manager) ExecuteOnDisconnect(ctx context.Context, session *SessionInfo) {
	m.mu.RLock()
	plugins := make([]Plugin, len(m.plugins))
	copy(plugins, m.plugins)
	m.mu.RUnlock()

	for _, p := range plugins {
		// Consider adding panic recovery around plugin calls
		p.OnDisconnect(ctx, session)
	}
}

// ExecuteOnConnect executes the OnConnect hook for all registered plugins.
func (m *Manager) ExecuteOnConnect(ctx context.Context, session *SessionInfo) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnConnect(ctx, session); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteOnHelo executes the OnHelo hook for all registered plugins.
func (m *Manager) ExecuteOnHelo(ctx context.Context, session *SessionInfo, heloDomain string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.plugins {
		if err := p.OnHelo(ctx, session, heloDomain); err != nil {
			return err
		}
	}
	return nil
}
