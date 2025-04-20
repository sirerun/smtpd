package security

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mailtive/smtpd/internal/metrics"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	rate       int        // tokens per minute
	burst      int        // maximum burst size
	tokens     int        // current token count
	lastUpdate time.Time  // last token update time
	mu         sync.Mutex // protects token count
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.rate))

	if tokensToAdd > 0 {
		rl.tokens = min(rl.tokens+tokensToAdd, rl.burst)
		rl.lastUpdate = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	metrics.RateLimitHitsTotal.WithLabelValues("request").Inc()
	return false
}

// ConnectionFilter implements IP-based connection filtering
type ConnectionFilter struct {
	allowedIPs     []*net.IPNet
	blockedIPs     []*net.IPNet
	allowedDomains []string
	blockedDomains []string
	mu             sync.RWMutex
}

// NewConnectionFilter creates a new connection filter
func NewConnectionFilter(allowedIPs, blockedIPs []string, allowedDomains, blockedDomains []string) (*ConnectionFilter, error) {
	filter := &ConnectionFilter{}

	// Parse allowed IPs
	for _, ipStr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed IP: %w", err)
		}
		filter.allowedIPs = append(filter.allowedIPs, ipNet)
	}

	// Parse blocked IPs
	for _, ipStr := range blockedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked IP: %w", err)
		}
		filter.blockedIPs = append(filter.blockedIPs, ipNet)
	}

	filter.allowedDomains = allowedDomains
	filter.blockedDomains = blockedDomains

	return filter, nil
}

// AllowConnection checks if a connection should be allowed
func (f *ConnectionFilter) AllowConnection(addr net.Addr) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Extract IP from address
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check blocked IPs first
	for _, blocked := range f.blockedIPs {
		if blocked.Contains(ip) {
			return false
		}
	}

	// If allowed IPs are specified, only allow those
	if len(f.allowedIPs) > 0 {
		for _, allowed := range f.allowedIPs {
			if allowed.Contains(ip) {
				return true
			}
		}
		return false
	}

	return true
}

// AllowDomain checks if a domain should be allowed
func (f *ConnectionFilter) AllowDomain(domain string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check blocked domains first
	for _, blocked := range f.blockedDomains {
		if blocked == domain {
			return false
		}
	}

	// If allowed domains are specified, only allow those
	if len(f.allowedDomains) > 0 {
		for _, allowed := range f.allowedDomains {
			if allowed == domain {
				return true
			}
		}
		return false
	}

	return true
}

// UpdateFilters updates the filter lists
func (f *ConnectionFilter) UpdateFilters(allowedIPs, blockedIPs []string, allowedDomains, blockedDomains []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Parse new allowed IPs
	var newAllowedIPs []*net.IPNet
	for _, ipStr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid allowed IP: %w", err)
		}
		newAllowedIPs = append(newAllowedIPs, ipNet)
	}

	// Parse new blocked IPs
	var newBlockedIPs []*net.IPNet
	for _, ipStr := range blockedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid blocked IP: %w", err)
		}
		newBlockedIPs = append(newBlockedIPs, ipNet)
	}

	// Update the filters
	f.allowedIPs = newAllowedIPs
	f.blockedIPs = newBlockedIPs
	f.allowedDomains = allowedDomains
	f.blockedDomains = blockedDomains

	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
