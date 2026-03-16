package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/sirerun/smtpd/pkg/smtp"
)

// RateLimiter is a plugin that limits the number of emails a sender can send within a time window.
type RateLimiter struct {
	plugin.BasePlugin
	limit     int           // Maximum number of emails allowed
	window    time.Duration // Time window for the limit
	counts    map[string]*senderCount
	mu        sync.RWMutex
	cleanupAt time.Time
}

type senderCount struct {
	count     int
	startTime time.Time
}

// NewRateLimiter creates a new rate limiting plugin.
// limit: maximum number of emails allowed per sender
// window: time window for the limit (e.g., 1 hour)
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:     limit,
		window:    window,
		counts:    make(map[string]*senderCount),
		cleanupAt: time.Now().Add(window),
	}
}

// cleanup removes expired sender counts
func (r *RateLimiter) cleanup(now time.Time) {
	if now.Before(r.cleanupAt) {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for sender, count := range r.counts {
		if now.Sub(count.startTime) > r.window {
			delete(r.counts, sender)
		}
	}

	r.cleanupAt = now.Add(r.window)
}

// OnMailFrom implements the Plugin interface.
func (r *RateLimiter) OnMailFrom(ctx context.Context, session *plugin.SessionInfo, from string) error {
	now := time.Now()
	r.cleanup(now)

	r.mu.Lock()
	defer r.mu.Unlock()

	count, exists := r.counts[from]
	if !exists {
		r.counts[from] = &senderCount{
			count:     1,
			startTime: now,
		}
		return nil
	}

	if now.Sub(count.startTime) > r.window {
		count.count = 1
		count.startTime = now
		return nil
	}

	if count.count >= r.limit {
		return smtp.NewError(450, "4.7.1", "Rate limit exceeded")
	}

	count.count++
	return nil
}
