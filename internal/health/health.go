package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/sirerun/smtpd/internal/metrics"
)

// HealthStatus represents the server's health status
type HealthStatus struct {
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	Uptime      string    `json:"uptime"`
	Connections int       `json:"connections"`
	QueueSize   int       `json:"queue_size"`
	LastError   string    `json:"last_error,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// HealthChecker manages health checks
type HealthChecker struct {
	startTime time.Time
	mu        sync.RWMutex
	lastError string
}

// NewHealthChecker creates a new health checker
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		startTime: time.Now(),
	}
}

// SetLastError records the last error that occurred
func (h *HealthChecker) SetLastError(err string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastError = err
}

// GetStatus returns the current health status
func (h *HealthChecker) GetStatus() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := "healthy"
	if h.lastError != "" {
		status = "degraded"
	}

	return HealthStatus{
		Status:      status,
		Version:     "1.0.0", // TODO: Get from build info
		Uptime:      time.Since(h.startTime).String(),
		Connections: int(metrics.GetConnectionsActive()),
		QueueSize:   int(metrics.GetQueueSizeReady()),
		LastError:   h.lastError,
		Timestamp:   time.Now(),
	}
}

// Status represents the health check response
type Status struct {
	Status            string  `json:"status"`
	ActiveConnections float64 `json:"active_connections"`
	QueueSize         float64 `json:"queue_size"`
	Timestamp         string  `json:"timestamp"`
}

// Handler returns an HTTP handler for health checks
func (h *HealthChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := h.GetStatus()

		// Send response
		w.Header().Set("Content-Type", "application/json")
		if status.Status == "degraded" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	}
}

// Handler returns an HTTP handler for health checks
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get current metrics
		activeConns := metrics.GetConnectionsActive()
		queueSize := metrics.GetQueueSizeReady()

		// Determine status
		status := "healthy"
		if activeConns > 1000 || queueSize > 10000 {
			status = "degraded"
		}

		// Create response
		resp := Status{
			Status:            status,
			ActiveConnections: activeConns,
			QueueSize:         queueSize,
			Timestamp:         time.Now().UTC().Format(time.RFC3339),
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		if status == "degraded" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(resp)
	}
}
