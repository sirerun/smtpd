package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHealthChecker(t *testing.T) {
	checker := NewHealthChecker()
	assert.NotNil(t, checker)

	// Test initial status
	status := checker.GetStatus()
	assert.Equal(t, "healthy", status.Status)
	assert.Equal(t, "1.0.0", status.Version)
	assert.Equal(t, 0, status.Connections)
	assert.Equal(t, 0, status.QueueSize)
	assert.Empty(t, status.LastError)

	// Test setting error
	checker.SetLastError("test error")
	status = checker.GetStatus()
	assert.Equal(t, "degraded", status.Status)
	assert.Equal(t, "test error", status.LastError)

	// Test HTTP handler
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	checker.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var responseStatus HealthStatus
	err := json.NewDecoder(w.Body).Decode(&responseStatus)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", responseStatus.Status)
	assert.Equal(t, "test error", responseStatus.LastError)
}

func TestHealthStatusJSON(t *testing.T) {
	status := HealthStatus{
		Status:      "healthy",
		Version:     "1.0.0",
		Uptime:      "1h23m45s",
		Connections: 10,
		QueueSize:   5,
		Timestamp:   time.Now(),
	}

	data, err := json.Marshal(status)
	assert.NoError(t, err)

	var decoded HealthStatus
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, status.Status, decoded.Status)
	assert.Equal(t, status.Version, decoded.Version)
	assert.Equal(t, status.Uptime, decoded.Uptime)
	assert.Equal(t, status.Connections, decoded.Connections)
	assert.Equal(t, status.QueueSize, decoded.QueueSize)
}
