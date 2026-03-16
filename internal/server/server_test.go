package server

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use internal logger for tests
var testLogger = logging.New(&logging.Config{Level: logging.DebugLevel, Output: "stderr", Format: logging.TextFormat, AddSource: true})
var testPlugins = []plugin.Plugin{} // Empty plugin list for basic tests

// Helper function to create a test server config
func createTestServerConfig() *ServerConfig {
	return DefaultServerConfig() // Start with defaults
}

func TestServerStartStop(t *testing.T) {
	srv, err := newTestServer(t, nil)
	require.NoError(t, err)

	// Start server
	err = srv.Start()
	require.NoError(t, err, "Server.Start failed")

	// Check listener address
	require.NotNil(t, srv.listener, "Server listener is nil after Start")
	listenerAddr := srv.listener.Addr().String()
	t.Logf("Server listening on %s", listenerAddr)

	// Minimal check: Try to connect
	conn, err := net.DialTimeout("tcp", listenerAddr, 1*time.Second)
	require.NoError(t, err, "Failed to connect to server")
	conn.Close()

	// Stop server
	err = srv.Stop()
	require.NoError(t, err, "Server.Stop failed")
}

func TestServerGracefulShutdown(t *testing.T) {
	srv, err := newTestServer(t, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		// Attempt stop again in cleanup just in case, log errors
		if err := srv.Stop(); err != nil {
			t.Logf("Error stopping server in cleanup: %v", err)
		}
	})

	err = srv.Start()
	require.NoError(t, err)

	// Create a connection that we'll keep open
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	require.NoError(t, err, "Failed to connect to server")
	defer conn.Close()

	// Read the initial greeting
	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	require.NoError(t, err, "Failed to read greeting")

	// Start a goroutine to stop the server after a short delay
	stopErrCh := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		stopErrCh <- srv.Stop()
	}()

	// The connection should be closed by the server during Stop()
	_, err = reader.ReadByte()
	require.Error(t, err, "Expected connection to be closed by server, read succeeded")
	t.Logf("Got expected error after server stop: %v", err)

	// Check the error from the Stop() call itself
	stopErr := <-stopErrCh
	require.NoError(t, stopErr, "srv.Stop() returned an error")
}

func TestServerMessageDelivery(t *testing.T) {
	srv, err := newTestServer(t, nil)
	require.NoError(t, err)
	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	serverAddr := srv.listener.Addr().String()

	// Simulate client sending a message
	conn, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	readExpected(t, reader, "220") // Read initial greeting
	writeCmd(t, conn, "EHLO client.test")
	readEHLO(t, reader) // Read full EHLO response
	writeCmd(t, conn, "MAIL FROM:<test@from.com>")
	readExpected(t, reader, "250")
	writeCmd(t, conn, "RCPT TO:<test@to.com>")
	readExpected(t, reader, "250")
	writeCmd(t, conn, "DATA")
	readExpected(t, reader, "354")

	msgBody := []byte("Subject: Test\r\n\r\nHello, world!\r\n.\r\n")
	_, err = conn.Write(msgBody)
	require.NoError(t, err)
	readExpected(t, reader, "250") // Read OK after DATA
	writeCmd(t, conn, "QUIT")
	readExpected(t, reader, "221")

	t.Log("Message delivery test passed basic checks (enqueue not verified)")
}

func TestServerPort587_Integration(t *testing.T) {
	tlsCfg := &TLSConfig{CertFile: "../testdata/cert.pem", KeyFile: "../testdata/key.pem"}
	srv, err := newTestServerWithPort(t, tlsCfg, 587)
	require.NoError(t, err, "NewServer failed for port 587")

	err = srv.Start()
	require.NoError(t, err, "Server.Start failed for port 587")
	defer srv.Stop()

	// Connect using TLS directly
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // Required for test certs
	}
	serverAddr := srv.listener.Addr().String()
	t.Logf("Attempting tls.Dial to %s...", serverAddr)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", serverAddr, clientTLSConfig)
	require.NoError(t, err, "Failed to connect to server using TLS")
	t.Logf("tls.Dial to %s successful.", serverAddr)
	defer conn.Close()

	// Set deadlines
	err = conn.SetDeadline(time.Now().Add(10 * time.Second))
	require.NoError(t, err)

	// Read greeting
	t.Logf("Attempting to read greeting from %s...", serverAddr)
	reader := bufio.NewReader(conn)
	readExpected(t, reader, "220")

	// Send EHLO
	writeCmd(t, conn, "EHLO test.com")

	// Read EHLO response - Port 587 server might not advertise STARTTLS if already TLS
	requiredCapabilities := map[string]bool{
		"AUTH PLAIN LOGIN": true, // Expect AUTH since TLS is established
		"SIZE":             true, // Expect SIZE
	}
	capabilitiesFound := readEHLO(t, reader)

	for capName := range requiredCapabilities {
		assert.True(t, capabilitiesFound[capName], "Missing required capability: %s", capName)
	}
	assert.False(t, capabilitiesFound["STARTTLS"], "STARTTLS should NOT be advertised when connected via TLS")

	// Send QUIT
	writeCmd(t, conn, "QUIT")
	readExpected(t, reader, "221")
}

func TestTLSConfig_CreateTLSConfig(t *testing.T) {
	// Test valid config
	cfg := &TLSConfig{CertFile: "../testdata/cert.pem", KeyFile: "../testdata/key.pem"}
	tlsCfg, err := cfg.CreateTLSConfig()
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.NotEmpty(t, tlsCfg.Certificates)
}

// Helper functions moved to test_helpers_test.go
