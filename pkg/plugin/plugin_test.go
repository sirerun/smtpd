package plugin

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testPlugin for BasePlugin tests
type testPlugin struct {
	BasePlugin // Embed BasePlugin
	// Track calls
	connectCalled    bool
	heloCalled       bool
	mailFromCalled   bool
	rcptToCalled     bool
	dataCalled       bool
	messageCalled    bool
	disconnectCalled bool
}

// Override methods to track calls
func (p *testPlugin) OnConnect(ctx context.Context, session *SessionInfo) error {
	p.connectCalled = true
	return p.BasePlugin.OnConnect(ctx, session) // Call embedded method
}
func (p *testPlugin) OnHelo(ctx context.Context, session *SessionInfo, heloDomain string) error {
	p.heloCalled = true
	return p.BasePlugin.OnHelo(ctx, session, heloDomain)
}
func (p *testPlugin) OnMailFrom(ctx context.Context, session *SessionInfo, from string) error {
	p.mailFromCalled = true
	return p.BasePlugin.OnMailFrom(ctx, session, from)
}
func (p *testPlugin) OnRcptTo(ctx context.Context, session *SessionInfo, rcptTo string) error {
	p.rcptToCalled = true
	return p.BasePlugin.OnRcptTo(ctx, session, rcptTo)
}
func (p *testPlugin) OnData(ctx context.Context, session *SessionInfo) error {
	p.dataCalled = true
	return p.BasePlugin.OnData(ctx, session)
}
func (p *testPlugin) OnMessage(ctx context.Context, session *SessionInfo, msg *MessageInfo) error {
	p.messageCalled = true
	return p.BasePlugin.OnMessage(ctx, session, msg)
}
func (p *testPlugin) OnDisconnect(ctx context.Context, session *SessionInfo) {
	p.disconnectCalled = true
	p.BasePlugin.OnDisconnect(ctx, session)
}

func TestBasePlugin(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	session := &SessionInfo{RemoteAddr: addr}
	msgInfo := &MessageInfo{Data: []byte("test")}

	base := &BasePlugin{}

	// Test default implementations return nil error
	assert.NoError(t, base.OnConnect(ctx, session))
	assert.NoError(t, base.OnHelo(ctx, session, "helo.com"))
	assert.NoError(t, base.OnMailFrom(ctx, session, "from@example.com"))
	assert.NoError(t, base.OnRcptTo(ctx, session, "to@example.com"))
	assert.NoError(t, base.OnData(ctx, session))
	assert.NoError(t, base.OnMessage(ctx, session, msgInfo))
	// OnDisconnect has no return
}

func TestCustomPluginEmbeddingBase(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	session := &SessionInfo{RemoteAddr: addr}
	msgInfo := &MessageInfo{Data: []byte("test")}
	plugin := &testPlugin{}

	// Call methods and check they were called via the tracker
	err := plugin.OnConnect(ctx, session)
	assert.NoError(t, err)
	assert.True(t, plugin.connectCalled, "OnConnect should have been called")

	err = plugin.OnHelo(ctx, session, "helo.com")
	assert.NoError(t, err)
	assert.True(t, plugin.heloCalled, "OnHelo should have been called")

	err = plugin.OnMailFrom(ctx, session, "from@example.com")
	assert.NoError(t, err)
	assert.True(t, plugin.mailFromCalled, "OnMailFrom should have been called")

	err = plugin.OnRcptTo(ctx, session, "to@example.com")
	assert.NoError(t, err)
	assert.True(t, plugin.rcptToCalled, "OnRcptTo should have been called")

	err = plugin.OnData(ctx, session)
	assert.NoError(t, err)
	assert.True(t, plugin.dataCalled, "OnData should have been called")

	err = plugin.OnMessage(ctx, session, msgInfo)
	assert.NoError(t, err)
	assert.True(t, plugin.messageCalled, "OnMessage should have been called")

	plugin.OnDisconnect(ctx, session)
	assert.True(t, plugin.disconnectCalled, "OnDisconnect should have been called")
}
