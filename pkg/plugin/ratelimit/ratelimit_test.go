package ratelimit

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25}
	sender := "test@example.com"

	// Create a rate limiter with a limit of 2 emails per hour
	limiter := NewRateLimiter(2, time.Hour)

	// First email should be accepted
	accepted, err := limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("First email should be accepted")
	}

	// Second email should be accepted
	accepted, err = limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("Second email should be accepted")
	}

	// Third email should be rejected
	accepted, err = limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if accepted {
		t.Error("Third email should be rejected")
	}

	// Test different sender
	otherSender := "other@example.com"
	accepted, err = limiter.OnMailFrom(ctx, otherSender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("First email from different sender should be accepted")
	}

	// Test window expiration
	limiter = NewRateLimiter(1, time.Millisecond)
	accepted, err = limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("First email should be accepted")
	}

	// Wait for window to expire
	time.Sleep(2 * time.Millisecond)

	// Should be accepted after window expiration
	accepted, err = limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("Email should be accepted after window expiration")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25}
	sender := "test@example.com"

	// Create a rate limiter with a short window
	limiter := NewRateLimiter(1, time.Millisecond)

	// Send an email
	accepted, err := limiter.OnMailFrom(ctx, sender, addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("First email should be accepted")
	}

	// Verify sender is in the map
	if len(limiter.counts) != 1 {
		t.Error("Sender count should be tracked")
	}

	// Wait for cleanup
	time.Sleep(2 * time.Millisecond)

	// Send another email to trigger cleanup
	accepted, err = limiter.OnMailFrom(ctx, "other@example.com", addr)
	if err != nil {
		t.Errorf("OnMailFrom returned error: %v", err)
	}
	if !accepted {
		t.Error("Email should be accepted")
	}

	// Verify old sender was cleaned up
	if _, exists := limiter.counts[sender]; exists {
		t.Error("Old sender should have been cleaned up")
	}
}
