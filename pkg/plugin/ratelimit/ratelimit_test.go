package ratelimit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirerun/smtpd/pkg/plugin"
)

func TestRateLimiter(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25}
	sender := "test@example.com"
	session := &plugin.SessionInfo{
		SessionID:  "test-session",
		RemoteAddr: addr,
	}

	// Create a rate limiter with a limit of 2 emails per hour
	limiter := NewRateLimiter(2, time.Hour)

	// First email should be accepted
	err := limiter.OnMailFrom(ctx, session, sender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Second email should be accepted
	err = limiter.OnMailFrom(ctx, session, sender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Third email should be rejected
	err = limiter.OnMailFrom(ctx, session, sender)
	if err == nil {
		t.Error("Third email should be rejected")
	}

	// Test different sender
	otherSender := "other@example.com"
	err = limiter.OnMailFrom(ctx, session, otherSender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Test window expiration
	limiter = NewRateLimiter(1, time.Millisecond)
	err = limiter.OnMailFrom(ctx, session, sender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Wait for window to expire
	time.Sleep(2 * time.Millisecond)

	// Should be accepted after window expiration
	err = limiter.OnMailFrom(ctx, session, sender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25}
	sender := "test@example.com"
	session := &plugin.SessionInfo{
		SessionID:  "test-session",
		RemoteAddr: addr,
	}

	// Create a rate limiter with a short window
	limiter := NewRateLimiter(1, time.Millisecond)

	// Send an email
	err := limiter.OnMailFrom(ctx, session, sender)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Verify sender is in the map
	if len(limiter.counts) != 1 {
		t.Error("Sender count should be tracked")
	}

	// Wait for cleanup
	time.Sleep(2 * time.Millisecond)

	// Send another email to trigger cleanup
	err = limiter.OnMailFrom(ctx, session, "other@example.com")
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}

	// Verify old sender was cleaned up
	if _, exists := limiter.counts[sender]; exists {
		t.Error("Old sender should have been cleaned up")
	}
}
