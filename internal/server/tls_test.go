package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTLSConfig(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "tls-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Read test certificate and key files
	certData, err := os.ReadFile("testdata/cert.pem")
	require.NoError(t, err)
	keyData, err := os.ReadFile("testdata/key.pem")
	require.NoError(t, err)
	caData, err := os.ReadFile("testdata/ca.pem")
	require.NoError(t, err)

	// Write test files to temp directory
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	caFile := filepath.Join(tempDir, "ca.pem")

	err = os.WriteFile(certFile, certData, 0644)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, keyData, 0644)
	require.NoError(t, err)
	err = os.WriteFile(caFile, caData, 0644)
	require.NoError(t, err)

	// Test creating TLS config
	config, err := NewTLSConfig(certFile, keyFile, caFile)
	require.NoError(t, err, "Failed to create TLS config")

	// Test creating tls.Config
	tlsConfig, err := config.CreateTLSConfig()
	require.NoError(t, err, "Failed to create tls.Config")

	// Verify TLS version settings
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion, "MinVersion mismatch")
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MaxVersion, "MaxVersion mismatch")

	// Verify cipher suites
	expectedSuites := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	require.Equal(t, expectedSuites, tlsConfig.CipherSuites, "CipherSuites mismatch")

	// Verify client authentication settings
	require.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth, "ClientAuth mismatch")

	// Verify CA pool
	require.NotNil(t, tlsConfig.ClientCAs, "ClientCAs should not be nil")
}

func TestSTARTTLS(t *testing.T) {
	tlsCfg := &TLSConfig{CertFile: "testdata/cert.pem", KeyFile: "testdata/key.pem"}
	srv, err := newTestServer(t, tlsCfg)
	require.NoError(t, err, "Failed to create server")

	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Logf("Error stopping server in cleanup: %v", err)
		}
	})
	err = srv.Start()
	require.NoError(t, err, "Failed to start server")

	// Connect to the server
	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	require.NoError(t, err, "Failed to connect to server")
	defer conn.Close()

	// Read greeting
	reader := bufio.NewReader(conn)
	readExpected(t, reader, "220")

	// Send EHLO
	writeCmd(t, conn, "EHLO test.com")

	// Read EHLO response
	capabilities := readEHLO(t, reader)
	require.True(t, capabilities["STARTTLS"], "STARTTLS should be advertised before TLS negotiation")
	require.False(t, capabilities["AUTH PLAIN LOGIN"], "AUTH should not be advertised before TLS negotiation")

	// Send STARTTLS
	writeCmd(t, conn, "STARTTLS")
	readExpected(t, reader, "220") // Read STARTTLS response

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // For testing only
	})

	// Handshake with context/timeout
	hshakeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = tlsConn.HandshakeContext(hshakeCtx)
	require.NoError(t, err, "TLS handshake failed")
	defer tlsConn.Close()

	// Verify the connection is encrypted
	state := tlsConn.ConnectionState()
	require.True(t, state.HandshakeComplete, "Expected handshake to be complete")
	require.GreaterOrEqual(t, state.Version, uint16(tls.VersionTLS12), "Expected TLS 1.2 or higher")

	// Send EHLO again over TLS
	tlsReader := bufio.NewReader(tlsConn)
	writeCmd(t, tlsConn, "EHLO test.com")
	tlsCapabilities := readEHLO(t, tlsReader)

	// Verify capabilities after STARTTLS
	require.False(t, tlsCapabilities["STARTTLS"], "STARTTLS should NOT be advertised after TLS negotiation")
	require.True(t, tlsCapabilities["AUTH PLAIN LOGIN"], "AUTH should be advertised after TLS negotiation")

}

func TestSubmissionPort(t *testing.T) {
	tlsCfg := &TLSConfig{CertFile: "testdata/cert.pem", KeyFile: "testdata/key.pem"}
	srv, err := newTestServerWithPort(t, tlsCfg, 587)
	require.NoError(t, err, "Failed to create server for submission port")

	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Logf("Error stopping server in cleanup: %v", err)
		}
	})
	err = srv.Start()
	require.NoError(t, err, "Failed to start server for submission port")

	// Connect to the server with TLS directly (as required by port 587)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", srv.listener.Addr().String(), clientTLSConfig)
	require.NoError(t, err, "Failed to connect with TLS to submission port")
	defer tlsConn.Close()

	// Read greeting
	reader := bufio.NewReader(tlsConn)
	readExpected(t, reader, "220")

	// Send EHLO
	writeCmd(t, tlsConn, "EHLO test.com")

	// Read EHLO response and check capabilities (STARTTLS should NOT be present)
	capabilities := readEHLO(t, reader)
	require.False(t, capabilities["STARTTLS"], "STARTTLS should not be advertised on submission port (already TLS)")
	require.True(t, capabilities["AUTH PLAIN LOGIN"], "AUTH should be advertised on submission port")

	// Send MAIL FROM
	writeCmd(t, tlsConn, "MAIL FROM:<sender@example.com>")
	readExpected(t, reader, "250")

	// Send QUIT
	writeCmd(t, tlsConn, "QUIT")
	readExpected(t, reader, "221")
}
