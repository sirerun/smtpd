package security

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10, 5) // 10 tokens per minute, burst of 5
	assert.NotNil(t, limiter)

	// Test initial burst
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(), "should allow initial burst")
	}

	// Test rate limiting
	assert.False(t, limiter.Allow(), "should not allow after burst")

	// Test token replenishment
	time.Sleep(6 * time.Second) // 0.1 minutes
	assert.True(t, limiter.Allow(), "should allow after token replenishment")
}

func TestConnectionFilter(t *testing.T) {
	filter, err := NewConnectionFilter(
		[]string{"10.0.0.0/8", "192.168.0.0/16"},
		[]string{"1.2.3.4/32"},
		[]string{"example.com", "example.org"},
		[]string{"spam.com", "malware.org"},
	)
	assert.NoError(t, err)
	assert.NotNil(t, filter)

	// Test allowed IPs
	tests := []struct {
		name    string
		addr    string
		domain  string
		allowed bool
	}{
		{
			name:    "allowed IP",
			addr:    "10.0.0.1:1234",
			allowed: true,
		},
		{
			name:    "blocked IP",
			addr:    "1.2.3.4:1234",
			allowed: false,
		},
		{
			name:    "unlisted IP",
			addr:    "2.3.4.5:1234",
			allowed: false, // Should be blocked when allowed_ips is specified
		},
		{
			name:    "allowed domain",
			domain:  "example.com",
			allowed: true,
		},
		{
			name:    "blocked domain",
			domain:  "spam.com",
			allowed: false,
		},
		{
			name:    "unlisted domain",
			domain:  "other.com",
			allowed: false, // Should be blocked when allowed_domains is specified
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.addr != "" {
				addr, err := net.ResolveTCPAddr("tcp", tt.addr)
				assert.NoError(t, err)
				assert.Equal(t, tt.allowed, filter.AllowConnection(addr))
			}
			if tt.domain != "" {
				assert.Equal(t, tt.allowed, filter.AllowDomain(tt.domain))
			}
		})
	}
}

func TestUpdateFilters(t *testing.T) {
	filter, err := NewConnectionFilter(
		[]string{"10.0.0.0/8"},
		[]string{"1.2.3.4/32"},
		[]string{"example.com"},
		[]string{"spam.com"},
	)
	assert.NoError(t, err)

	// Test updating with valid IPs
	err = filter.UpdateFilters(
		[]string{"192.168.0.0/16"},
		[]string{"2.3.4.5/32"},
		[]string{"example.org"},
		[]string{"malware.org"},
	)
	assert.NoError(t, err)

	// Test updating with invalid IP
	err = filter.UpdateFilters(
		[]string{"invalid-ip"},
		[]string{},
		[]string{},
		[]string{},
	)
	assert.Error(t, err)
}

func TestMin(t *testing.T) {
	assert.Equal(t, 1, min(1, 2))
	assert.Equal(t, 1, min(2, 1))
	assert.Equal(t, 0, min(0, 1))
	assert.Equal(t, -1, min(-1, 0))
}
