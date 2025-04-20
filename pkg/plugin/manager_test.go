package plugin

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockPlugin for manager tests
type mockPlugin struct {
	BasePlugin
	name string
	// Store results/errors for hooks
	mailFromErr error
	rcptToErr   error
	dataErr     error
	messageErr  error
	connectErr  error
	heloErr     error
}

func (p *mockPlugin) Name() string {
	if p.name == "" {
		return "MockPlugin"
	}
	return p.name
}

// Implement hooks to return configured errors
func (p *mockPlugin) OnMailFrom(ctx context.Context, session *SessionInfo, from string) error {
	return p.mailFromErr
}

func (p *mockPlugin) OnRcptTo(ctx context.Context, session *SessionInfo, rcptTo string) error {
	return p.rcptToErr
}

func (p *mockPlugin) OnData(ctx context.Context, session *SessionInfo) error {
	return p.dataErr
}

func (p *mockPlugin) OnMessage(ctx context.Context, session *SessionInfo, msg *MessageInfo) error {
	return p.messageErr
}

func (p *mockPlugin) OnConnect(ctx context.Context, session *SessionInfo) error {
	return p.connectErr
}

func (p *mockPlugin) OnHelo(ctx context.Context, session *SessionInfo, heloDomain string) error {
	return p.heloErr
}

// --- Test Manager ---

func TestManager_Registration(t *testing.T) {
	manager := NewManager()
	assert.Len(t, manager.plugins, 0)

	p1 := &mockPlugin{name: "P1"}
	manager.Register(p1)
	assert.Len(t, manager.plugins, 1)
	assert.Equal(t, p1, manager.plugins[0])

	p2 := &mockPlugin{name: "P2"}
	manager.Register(p2)
	assert.Len(t, manager.plugins, 2)
	assert.Equal(t, p2, manager.plugins[1])
}

func TestManager_ExecutionOrderAndErrorHandling(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	session := &SessionInfo{RemoteAddr: addr}
	msgInfo := &MessageInfo{From: "a@b.c"}

	errPluginReturns := fmt.Errorf("plugin error")

	tests := []struct {
		name         string
		plugins      []Plugin
		hookCallFunc func(m *Manager) error // Function to call specific hook
		expectError  error
	}{
		{
			name:    "OnMailFrom - No Plugins",
			plugins: []Plugin{},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnMailFrom(ctx, session, "test@example.com")
			},
			expectError: nil,
		},
		{
			name: "OnMailFrom - One Plugin OK",
			plugins: []Plugin{
				&mockPlugin{mailFromErr: nil},
			},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnMailFrom(ctx, session, "test@example.com")
			},
			expectError: nil,
		},
		{
			name: "OnMailFrom - One Plugin Error",
			plugins: []Plugin{
				&mockPlugin{mailFromErr: errPluginReturns},
			},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnMailFrom(ctx, session, "test@example.com")
			},
			expectError: errPluginReturns,
		},
		{
			name: "OnMailFrom - Second Plugin Error",
			plugins: []Plugin{
				&mockPlugin{mailFromErr: nil},              // First OK
				&mockPlugin{mailFromErr: errPluginReturns}, // Second Errors
				&mockPlugin{mailFromErr: nil},              // Third not called
			},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnMailFrom(ctx, session, "test@example.com")
			},
			expectError: errPluginReturns,
		},
		// Add similar tests for ExecuteOnRcptTo, ExecuteOnData, ExecuteOnMessage, ExecuteOnConnect, ExecuteOnHelo
		{
			name:    "OnRcptTo - No Plugins",
			plugins: []Plugin{},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnRcptTo(ctx, session, "rcpt@example.com")
			},
			expectError: nil,
		},
		{
			name: "OnRcptTo - First Plugin Error",
			plugins: []Plugin{
				&mockPlugin{rcptToErr: errPluginReturns},
				&mockPlugin{rcptToErr: nil},
			},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnRcptTo(ctx, session, "rcpt@example.com")
			},
			expectError: errPluginReturns,
		},
		{
			name:    "OnMessage - OK",
			plugins: []Plugin{&mockPlugin{messageErr: nil}},
			hookCallFunc: func(m *Manager) error {
				return m.ExecuteOnMessage(ctx, session, msgInfo)
			},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager()
			for _, p := range tt.plugins {
				manager.Register(p)
			}

			err := tt.hookCallFunc(manager)

			if tt.expectError == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectError)
			}
		})
	}
}
