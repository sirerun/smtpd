package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mailtive/smtpd/internal/auth"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/queue"
	"github.com/mailtive/smtpd/pkg/plugin"
	"github.com/stretchr/testify/require"
)

// Shared test variables
var testSessionLogger = logging.New(logging.DefaultConfig()).WithComponent("session")
var testUserStore = auth.NewStore()
var testQueue = queue.NewQueue(10, testSessionLogger)

// Mock connection implementation
type mockConn struct {
	net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func newMockConn() (*mockConn, *mockConn) {
	client, server := net.Pipe()
	clientConn := &mockConn{
		Conn:   client,
		reader: bufio.NewReader(client),
		writer: bufio.NewWriter(client),
	}
	serverConn := &mockConn{
		Conn:   server,
		reader: bufio.NewReader(server),
		writer: bufio.NewWriter(server),
	}
	testTimeout := 5 * time.Second // Shorter timeout for tests
	client.SetDeadline(time.Now().Add(testTimeout))
	server.SetDeadline(time.Now().Add(testTimeout))
	return clientConn, serverConn
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.reader.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	n, err = m.writer.Write(b)
	if err != nil {
		return n, err
	}
	return n, m.writer.Flush()
}

func (m *mockConn) Close() error {
	return m.Conn.Close()
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return m.Conn.SetDeadline(t)
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return m.Conn.SetReadDeadline(t)
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return m.Conn.SetWriteDeadline(t)
}

// Mock Plugin Implementation
type mockPlugin struct {
	plugin.BasePlugin
	rejectMailFrom bool
	rejectRcptTo   bool
	rejectData     bool
	mailFromErr    error
	rcptToErr      error
	dataErr        error
	mailFromCalled bool
	rcptToCalled   bool
	dataCalled     bool
}

func (p *mockPlugin) OnMailFrom(ctx context.Context, from string, remoteAddr net.Addr) (bool, error) {
	p.mailFromCalled = true
	if p.mailFromErr != nil {
		return false, p.mailFromErr
	}
	return !p.rejectMailFrom, nil
}

func (p *mockPlugin) OnRcptTo(ctx context.Context, to string, remoteAddr net.Addr) (bool, error) {
	p.rcptToCalled = true
	if p.rcptToErr != nil {
		return false, p.rcptToErr
	}
	return !p.rejectRcptTo, nil
}

func (p *mockPlugin) OnData(ctx context.Context, data []byte, remoteAddr net.Addr) (bool, error) {
	p.dataCalled = true
	if p.dataErr != nil {
		return false, p.dataErr
	}
	return !p.rejectData, nil
}

// Helper to run session tests
func runSessionTest(t *testing.T, testFunc func(clientConn *mockConn, serverSession *Session)) {
	clientConn, serverConn := newMockConn()
	defer clientConn.Close()

	errChan := make(chan error, 1)
	session := &Session{}
	session.Reset(serverConn, testQueue, nil, testUserStore, nil, testSessionLogger, "test-session-"+t.Name())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("session handler panicked: %v", r)
			}
			close(errChan)
		}()
		if err := session.Handle(); err != nil {
			errChan <- err
		}
	}()

	testFunc(clientConn, session)

	// Check for session handler errors
	select {
	case err := <-errChan:
		if err != nil {
			// Ignore "use of closed network connection" as it's expected when client quits
			if !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "failed to read command: EOF") {
				t.Errorf("Session handler returned unexpected error: %v", err)
			}
		}
	case <-time.After(2 * time.Second): // Shorter timeout
		t.Error("Session handler did not complete within timeout")
	}
}

// Helper to write command
func writeCmd(t *testing.T, conn net.Conn, cmd string) {
	_, err := conn.Write([]byte(cmd + "\r\n"))
	require.NoError(t, err, "Failed to write command: %s", cmd)
}

// Helper to read response and check prefix
func readExpected(t *testing.T, r *bufio.Reader, prefix string) string {
	lineBytes, err := r.ReadBytes('\n')
	require.NoError(t, err, "Failed to read response, expected prefix: %s", prefix)
	line := string(lineBytes)
	require.True(t, strings.HasPrefix(line, prefix), "Expected response prefix '%s', got: %s", prefix, line)
	return line
}

// Helper to read multi-line EHLO response
func readEHLO(t *testing.T, r *bufio.Reader) map[string]bool {
	capabilities := make(map[string]bool)
	for i := 0; i < 10; i++ {
		line := readExpected(t, r, "250")
		if strings.HasPrefix(line, "250 ") { // Space indicates last line
			capabilities[strings.TrimSpace(line[4:])] = true
			break
		}
		capabilities[strings.TrimSpace(line[4:])] = true
	}
	return capabilities
}
