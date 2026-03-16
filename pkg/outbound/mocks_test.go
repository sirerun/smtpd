// filepath: /Users/dndungu/Code/mailnative/smtpd/internal/outbound/mocks_test.go
package outbound

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/stretchr/testify/require"
)

// --- Mock Resolver ---
type mockResolver struct {
	mxRecords map[string][]*net.MX
	lookupErr map[string]error
}

func (r *mockResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err, exists := r.lookupErr[name]; exists {
		return nil, err
	}
	if records, exists := r.mxRecords[name]; exists {
		recordsCopy := make([]*net.MX, len(records))
		copy(recordsCopy, records)
		return recordsCopy, nil
	}
	return []*net.MX{}, nil
}

// --- Mock SMTP Client ---
type mockSmtpClient struct {
	host        string
	sendFunc    func(from string, to []string, msg []byte) error
	closeFunc   func() error
	mu          sync.Mutex
	sendCalls   []SendCall
	closeCalled bool
	resetCalled bool
	shouldFail  bool
	failError   error
	wasReleased bool
}

type SendCall struct {
	From string
	To   []string
	Msg  []byte
}

func NewMockSmtpClient(host string, fail bool, failErr error) *mockSmtpClient {
	return &mockSmtpClient{
		host:       host,
		shouldFail: fail,
		failError:  failErr,
	}
}

func (sc *mockSmtpClient) Send(from string, to []string, msg []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.shouldFail {
		if sc.failError != nil {
			return sc.failError
		}
		return errors.New("mock send failed")
	}
	msgCopy := make([]byte, len(msg))
	copy(msgCopy, msg)
	sc.sendCalls = append(sc.sendCalls, SendCall{From: from, To: to, Msg: msgCopy})
	if sc.sendFunc != nil {
		return sc.sendFunc(from, to, msg)
	}
	return nil
}

func (sc *mockSmtpClient) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.closeCalled = true
	if sc.closeFunc != nil {
		return sc.closeFunc()
	}
	return nil
}

func (sc *mockSmtpClient) Host() string {
	return sc.host
}

func (sc *mockSmtpClient) GetSendCalls() []SendCall {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	callsCopy := make([]SendCall, len(sc.sendCalls))
	copy(callsCopy, sc.sendCalls)
	return callsCopy
}

// --- Mock SMTP Client Pool ---
type mockSmtpClientPool struct {
	mu          sync.Mutex
	clients     map[string][]*mockSmtpClient // Store mock clients for inspection
	getClientFn func(ctx context.Context, host string) (SMTPClientInterface, error)
	releaseFn   func(client SMTPClientInterface)
	failGet     bool
	failGetErr  error
}

func (p *mockSmtpClientPool) GetClient(ctx context.Context, host string) (SMTPClientInterface, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failGet {
		return nil, p.failGetErr
	}
	if p.getClientFn != nil {
		return p.getClientFn(ctx, host)
	}
	client := NewMockSmtpClient(host, false, nil)
	if p.clients == nil {
		p.clients = make(map[string][]*mockSmtpClient)
	}
	p.clients[host] = append(p.clients[host], client)
	return client, nil
}

func (p *mockSmtpClientPool) ReleaseClient(client SMTPClientInterface) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mockC, ok := client.(*mockSmtpClient); ok {
		mockC.wasReleased = true
	}
	if p.releaseFn != nil {
		p.releaseFn(client)
	}
}

func (p *mockSmtpClientPool) CloseAll() {}

// --- Mock Logger ---
type mockLogger struct {
	*logging.Logger // Embed the real logger to avoid reimplementing everything
	mu              sync.Mutex
	infos           []string
	warns           []string
	errors          []string
	debugs          []string
}

func newMockLogger() *mockLogger {
	// Correctly initialize the embedded logger
	baseLogger := logging.New(&logging.Config{Level: "debug", Output: "stdout", Format: "text"}) // Pass pointer
	return &mockLogger{Logger: baseLogger}
}

func (l *mockLogger) Info(msg string, args ...interface{}) {
	l.mu.Lock()
	l.infos = append(l.infos, fmt.Sprintf(msg, args...))
	l.mu.Unlock()
	l.Logger.Info(msg, args...)
}

func (l *mockLogger) Warn(msg string, args ...interface{}) {
	l.mu.Lock()
	l.warns = append(l.warns, fmt.Sprintf(msg, args...))
	l.mu.Unlock()
	l.Logger.Warn(msg, args...)
}

func (l *mockLogger) Error(msg string, args ...interface{}) {
	l.mu.Lock()
	l.errors = append(l.errors, fmt.Sprintf(msg, args...))
	l.mu.Unlock()
	l.Logger.Error(msg, args...)
}

func (l *mockLogger) Debug(msg string, args ...interface{}) {
	l.mu.Lock()
	l.debugs = append(l.debugs, fmt.Sprintf(msg, args...))
	l.mu.Unlock()
	l.Logger.Debug(msg, args...)
}

// WithComponent and WithFields can just return the same mock logger for simplicity in tests
func (l *mockLogger) WithComponent(name string) LoggerInterface {
	// Optionally create a new mock logger with a modified base logger if needed
	return l
}

func (l *mockLogger) WithFields(fields map[string]interface{}) LoggerInterface {
	// Optionally create a new mock logger with a modified base logger if needed
	return l
}

// --- Mock Metrics Recorder ---
type mockMetricsRecorder struct {
	mu            sync.Mutex
	statuses      map[string]int
	deliveryTimes []time.Duration
}

func newMockMetricsRecorder() *mockMetricsRecorder {
	return &mockMetricsRecorder{
		statuses:      make(map[string]int),
		deliveryTimes: []time.Duration{},
	}
}

func (m *mockMetricsRecorder) RecordMessageStatusByDomain(status string, domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statuses == nil {
		m.statuses = make(map[string]int)
	}
	key := fmt.Sprintf("%s_%s", status, domain)
	m.statuses[key]++
}

func (m *mockMetricsRecorder) RecordDeliveryTime(duration time.Duration, domain string) {
	m.mu.Lock()
	m.deliveryTimes = append(m.deliveryTimes, duration)
	m.mu.Unlock()
}

// --- Mock Dialer ---
type mockDialer struct {
	dialFunc    func(ctx context.Context, network, addr string) (net.Conn, error)
	dialError   error
	lastNetwork string
	lastAddr    string
}

func (m *mockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	m.lastNetwork = network
	m.lastAddr = addr
	if m.dialFunc != nil {
		return m.dialFunc(ctx, network, addr)
	}
	if m.dialError != nil {
		return nil, m.dialError
	}
	return &mockConn{}, nil
}

// --- Mock Conn ---
// mockConn simulates an SMTP server connection for testing.
// It responds to SMTP protocol commands so that smtp.NewClient and Hello work.
type mockConn struct {
	readDeadline  time.Time
	writeDeadline time.Time
	closed        atomic.Bool
	mu            sync.Mutex
	readBuf       []byte
	writeBuf      []byte
	greeted       bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	if !m.greeted {
		m.readBuf = append(m.readBuf, []byte("220 mock.example.com ESMTP ready\r\n")...)
		m.greeted = true
	}
	if len(m.readBuf) == 0 {
		m.mu.Unlock()
		// Block until closed or new data arrives
		for i := 0; i < 500; i++ {
			if m.closed.Load() {
				return 0, errors.New("connection closed")
			}
			time.Sleep(10 * time.Millisecond)
			m.mu.Lock()
			if len(m.readBuf) > 0 {
				break
			}
			m.mu.Unlock()
		}
		if m.closed.Load() {
			return 0, errors.New("connection closed")
		}
		// m.mu is locked here from the break
	}
	n = copy(b, m.readBuf)
	m.readBuf = m.readBuf[n:]
	m.mu.Unlock()
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return 0, errors.New("connection closed")
	}
	cmd := string(b)
	// Generate mock SMTP responses for protocol commands
	if len(cmd) >= 4 {
		switch {
		case cmd[:4] == "EHLO":
			m.readBuf = append(m.readBuf, []byte("250-mock.example.com\r\n250 OK\r\n")...)
		case cmd[:4] == "HELO":
			m.readBuf = append(m.readBuf, []byte("250 mock.example.com\r\n")...)
		case cmd[:4] == "MAIL":
			m.readBuf = append(m.readBuf, []byte("250 OK\r\n")...)
		case cmd[:4] == "RCPT":
			m.readBuf = append(m.readBuf, []byte("250 OK\r\n")...)
		case cmd[:4] == "DATA":
			m.readBuf = append(m.readBuf, []byte("354 Go ahead\r\n")...)
		case cmd[:4] == "QUIT":
			m.readBuf = append(m.readBuf, []byte("221 Bye\r\n")...)
		case cmd[:4] == "RSET":
			m.readBuf = append(m.readBuf, []byte("250 OK\r\n")...)
		case cmd == ".\r\n":
			m.readBuf = append(m.readBuf, []byte("250 OK\r\n")...)
		}
	}
	return len(b), nil
}
func (m *mockConn) Close() error                      { m.closed.Store(true); return nil }
func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 25} }
func (m *mockConn) SetDeadline(t time.Time) error {
	m.SetReadDeadline(t)
	m.SetWriteDeadline(t)
	return nil
}
func (m *mockConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.readDeadline = t
	m.mu.Unlock()
	return nil
}
func (m *mockConn) SetWriteDeadline(t time.Time) error {
	m.mu.Lock()
	m.writeDeadline = t
	m.mu.Unlock()
	return nil
}
func (m *mockConn) IsClosed() bool {
	return m.closed.Load()
}

// --- Helper Functions ---
func loadTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	return key
}

// --- Interface Assertions (Compile-time check) ---
var _ Resolver = (*mockResolver)(nil)
var _ SMTPClientInterface = (*mockSmtpClient)(nil)
var _ SMTPClientPoolInterface = (*mockSmtpClientPool)(nil)
var _ LoggerInterface = (*mockLogger)(nil)
var _ MetricsRecorderInterface = (*mockMetricsRecorder)(nil)
var _ Dialer = (*mockDialer)(nil)
var _ net.Conn = (*mockConn)(nil)
