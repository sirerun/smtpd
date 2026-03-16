package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations moved to mocks_test.go

// --- Tests ---

func TestNewSMTPClientPool(t *testing.T) {
	cfg := DefaultSMTPClientConfig()
	mockD := &mockDialer{}
	mockL := newMockLogger()

	pool := NewSMTPClientPool(cfg, mockD, mockL)
	require.NotNil(t, pool)
	assert.Equal(t, cfg, pool.config)
	assert.Equal(t, mockD, pool.dialer)
	assert.NotNil(t, pool.logger)
	assert.NotNil(t, pool.pools)
	assert.Equal(t, cfg.MaxConnections, pool.maxConnsPerHost)
	assert.Equal(t, cfg.IdleTimeout, pool.idleTimeout)

	// Test with nil logger
	poolWithNilLogger := NewSMTPClientPool(cfg, mockD, nil)
	require.NotNil(t, poolWithNilLogger)
	assert.NotNil(t, poolWithNilLogger.logger)
	
	// Test with nil dialer
	poolWithNilDialer := NewSMTPClientPool(cfg, nil, mockL)
	require.NotNil(t, poolWithNilDialer)
	assert.NotNil(t, poolWithNilDialer.dialer)
}

func TestSMTPClientPool_GetRelease(t *testing.T) {
	cfg := DefaultSMTPClientConfig()
	cfg.MaxConnections = 1
	cfg.IdleTimeout = 10 * time.Millisecond
	mockD := &mockDialer{}
	mockL := newMockLogger()
	pool := NewSMTPClientPool(cfg, mockD, mockL)

	dialCount := int32(0)
	mockD.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dialCount, 1)
		return &mockConn{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host := "mx.example.com"

	// Get first client
	client1, err := pool.GetClient(ctx, host)
	require.NoError(t, err)
	require.NotNil(t, client1)
	assert.EqualValues(t, 1, atomic.LoadInt32(&dialCount))

	// Pool doesn't enforce max connections; a second get creates a new client
	client2, err := pool.GetClient(ctx, host)
	require.NoError(t, err)
	require.NotNil(t, client2)
	assert.EqualValues(t, 2, atomic.LoadInt32(&dialCount))

	// Release first client
	pool.ReleaseClient(client1)
	pool.ReleaseClient(client2)

	// Getting again should reuse from pool (no new dial)
	client3, err := pool.GetClient(ctx, host)
	require.NoError(t, err)
	require.NotNil(t, client3)
	assert.EqualValues(t, 2, atomic.LoadInt32(&dialCount))

	pool.ReleaseClient(client3)
}

func TestSMTPClientPool_GetClient_DialError(t *testing.T) {
	cfg := DefaultSMTPClientConfig()
	mockD := &mockDialer{dialError: errors.New("connection refused")}
	mockL := newMockLogger()
	pool := NewSMTPClientPool(cfg, mockD, mockL)

	ctx := context.Background()
	_, err := pool.GetClient(ctx, "mx.example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.Contains(t, err.Error(), "failed to dial")
}

func TestSMTPClientPool_CloseAll(t *testing.T) {
	cfg := DefaultSMTPClientConfig()
	cfg.MaxConnections = 2
	mockD := &mockDialer{}
	mockL := newMockLogger()
	pool := NewSMTPClientPool(cfg, mockD, mockL)

	dialedConns := make([]*mockConn, 0)
	dialMu := sync.Mutex{}
	mockD.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn := &mockConn{}
		dialMu.Lock()
		dialedConns = append(dialedConns, conn)
		dialMu.Unlock()
		return conn, nil
	}

	ctx := context.Background()
	host1 := "mx1.example.com"
	host2 := "mx2.example.com"

	c1, _ := pool.GetClient(ctx, host1)
	c2, _ := pool.GetClient(ctx, host1)
	c3, _ := pool.GetClient(ctx, host2)

	require.NotNil(t, c1)
	require.NotNil(t, c2)
	require.NotNil(t, c3)

	pool.ReleaseClient(c1)
	pool.ReleaseClient(c2)
	pool.ReleaseClient(c3)

	time.Sleep(50 * time.Millisecond)

	pool.mu.RLock()
	poolLen := len(pool.pools)
	pool.mu.RUnlock()
	assert.Equal(t, 2, poolLen)

	pool.CloseAll()

	pool.mu.RLock()
	poolLenAfterClose := len(pool.pools)
	pool.mu.RUnlock()
	assert.Equal(t, 0, poolLenAfterClose)

	dialMu.Lock()
	allClosed := true
	closedCount := 0
	for _, conn := range dialedConns {
		if conn.IsClosed() {
			closedCount++
		} else {
			allClosed = false
		}
	}
	dialMu.Unlock()
	assert.True(t, allClosed)
	assert.Equal(t, 3, closedCount)

	dialCountBefore := len(dialedConns)
	c4, err := pool.GetClient(ctx, host1)
	require.NoError(t, err)
	require.NotNil(t, c4)
	dialMu.Lock()
	dialCountAfter := len(dialedConns)
	dialMu.Unlock()
	assert.Equal(t, dialCountBefore+1, dialCountAfter)

	mockConn4 := c4.(*SMTPClient).conn.(*mockConn)
	assert.False(t, mockConn4.IsClosed())

	pool.ReleaseClient(c4)
}
