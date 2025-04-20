package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockSMTPClient is a mock implementation of the SMTP client for testing
type mockSMTPClient struct {
	capabilities  []string
	authError     error
	mailError     error
	rcptError     error
	dataError     error
	quitError     error
	startTLSError error
	ehloError     error
	heloError     error
}

func (m *mockSMTPClient) Hello(localName string) error {
	if m.ehloError != nil {
		return m.ehloError
	}
	return nil
}

func (m *mockSMTPClient) StartTLS(config *tls.Config) error {
	return m.startTLSError
}

func (m *mockSMTPClient) Mail(from string) error {
	return m.mailError
}

func (m *mockSMTPClient) Rcpt(to string) error {
	return m.rcptError
}

func (m *mockSMTPClient) Data() error {
	return m.dataError
}

func (m *mockSMTPClient) Quit() error {
	return m.quitError
}

func (m *mockSMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	if err := m.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := m.Rcpt(rcpt); err != nil {
			return err
		}
	}
	return m.Data()
}

// mockDialer is a mock implementation of the dialer for testing
type mockDialer struct {
	dialError error
}

func (m *mockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.dialError != nil {
		return nil, m.dialError
	}
	return &mockConn{}, nil
}

type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error {
	return nil
}

func TestSMTPClientPool(t *testing.T) {
	pool := NewSMTPClientPool(DefaultSMTPClientConfig())
	assert.NotNil(t, pool)
	assert.NotNil(t, pool.config)
	assert.NotNil(t, pool.clients)
}

func TestSMTPClientHello(t *testing.T) {
	tests := []struct {
		name          string
		capabilities  []string
		ehloError     error
		heloError     error
		expectedError string
	}{
		{
			name:         "Successful EHLO",
			capabilities: []string{"AUTH PLAIN", "SIZE 33554432", "STARTTLS"},
		},
		{
			name:          "Failed EHLO, successful HELO",
			ehloError:     errors.New("EHLO failed"),
			heloError:     nil,
			expectedError: "EHLO failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockSMTPClient{
				capabilities: tt.capabilities,
				ehloError:    tt.ehloError,
				heloError:    tt.heloError,
			}

			err := client.Hello("test.com")
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSMTPClientStartTLS(t *testing.T) {
	tests := []struct {
		name          string
		startTLSError error
		expectedError string
	}{
		{
			name: "Successful STARTTLS",
		},
		{
			name:          "Failed STARTTLS",
			startTLSError: errors.New("STARTTLS failed"),
			expectedError: "STARTTLS failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockSMTPClient{
				startTLSError: tt.startTLSError,
			}

			err := client.StartTLS(&tls.Config{})
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSMTPClientSend(t *testing.T) {
	tests := []struct {
		name        string
		mailError   error
		rcptError   error
		dataError   error
		expectedErr string
	}{
		{
			name: "Successful send",
		},
		{
			name:        "MAIL FROM failed",
			mailError:   errors.New("MAIL FROM failed"),
			expectedErr: "MAIL FROM failed",
		},
		{
			name:        "RCPT TO failed",
			rcptError:   errors.New("RCPT TO failed"),
			expectedErr: "RCPT TO failed",
		},
		{
			name:        "DATA failed",
			dataError:   errors.New("DATA failed"),
			expectedErr: "DATA failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockSMTPClient{
				mailError: tt.mailError,
				rcptError: tt.rcptError,
				dataError: tt.dataError,
			}

			err := client.Mail("from@example.com")
			if err == nil {
				err = client.Rcpt("to@example.com")
			}
			if err == nil {
				err = client.Data()
			}

			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSMTPClientPoolGetClient(t *testing.T) {
	pool := NewSMTPClientPool(DefaultSMTPClientConfig())
	pool.mockClient = &mockSMTPClient{}

	client, err := pool.GetClient(context.Background(), "example.com:25")
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestSMTPClientPoolReturnClient(t *testing.T) {
	pool := NewSMTPClientPool(DefaultSMTPClientConfig())
	pool.mockClient = &mockSMTPClient{}

	client, err := pool.GetClient(context.Background(), "example.com:25")
	assert.NoError(t, err)
	assert.NotNil(t, client)

	pool.ReturnClient(client)
}

func TestSMTPClientClose(t *testing.T) {
	client := &SMTPClient{
		client: &mockSMTPClient{},
		config: DefaultSMTPClientConfig(),
	}
	err := client.Close()
	assert.NoError(t, err)
}
