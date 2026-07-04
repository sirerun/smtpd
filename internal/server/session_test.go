package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSessionHandleGreetingAndQuit(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 32 * 1024 * 1024

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO test.com")
		readEHLO(t, clientConn.reader)
		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}

func TestSessionHandleFullTransaction(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 32 * 1024 * 1024
		// recipient@test.com must be a local domain for this unauthenticated
		// delivery to be accepted -- see the relay-control tests below for
		// the non-local / cross-domain cases.
		session.localDomains = []string{"test.com"}

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO client.test")
		readEHLO(t, clientConn.reader)

		writeCmd(t, clientConn, "MAIL FROM:<sender@test.com>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "RCPT TO:<recipient@test.com>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "DATA")
		readExpected(t, clientConn.reader, "354")

		_, err := clientConn.Write([]byte("Subject: Test\r\n\r\nHello\r\n.\r\n"))
		require.NoError(t, err)
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}

// TestSessionRelayDenied_UnauthenticatedNonLocalRecipient is the regression
// test for the open-relay defect: an unauthenticated session must not be
// able to relay mail to a domain this server does not host.
func TestSessionRelayDenied_UnauthenticatedNonLocalRecipient(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 32 * 1024 * 1024
		session.localDomains = []string{"sire.run"}

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO client.test")
		readEHLO(t, clientConn.reader)

		writeCmd(t, clientConn, "MAIL FROM:<attacker@evil.example>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "RCPT TO:<victim@somewhere-else.example>")
		readExpected(t, clientConn.reader, "550")

		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}

// TestSessionRelayAllowed_UnauthenticatedLocalRecipient is the control case:
// mail addressed to a domain this server hosts is accepted without auth
// (standard inbound MX behavior).
func TestSessionRelayAllowed_UnauthenticatedLocalRecipient(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 32 * 1024 * 1024
		session.localDomains = []string{"sire.run"}

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO client.test")
		readEHLO(t, clientConn.reader)

		writeCmd(t, clientConn, "MAIL FROM:<someone@example.com>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "RCPT TO:<inbox@sire.run>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}

// TestSessionRelayAllowed_AuthenticatedNonLocalRecipient is the other control
// case: an authenticated session (e.g. a legitimate user submitting outbound
// mail) may relay to any domain, matching standard MSA submission behavior.
func TestSessionRelayAllowed_AuthenticatedNonLocalRecipient(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 32 * 1024 * 1024
		session.localDomains = []string{"sire.run"}
		session.auth = true

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO client.test")
		readEHLO(t, clientConn.reader)

		writeCmd(t, clientConn, "MAIL FROM:<user@sire.run>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "RCPT TO:<recipient@somewhere-else.example>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}

// TestSessionData_ExceedsMaxMessageSizeRejected guards against the memory-DoS
// defect: handleData must enforce maxMessageSize while reading, not buffer an
// unbounded body. Uses a tiny limit so the test body itself stays small.
func TestSessionData_ExceedsMaxMessageSizeRejected(t *testing.T) {
	runSessionTest(t, func(clientConn *mockConn, session *Session) {
		session.readTimeout = 5 * time.Second
		session.writeTimeout = 5 * time.Second
		session.idleTimeout = 10 * time.Second
		session.maxMessageSize = 16 // bytes
		session.localDomains = []string{"test.com"}

		readExpected(t, clientConn.reader, "220")
		writeCmd(t, clientConn, "EHLO client.test")
		readEHLO(t, clientConn.reader)

		writeCmd(t, clientConn, "MAIL FROM:<sender@test.com>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "RCPT TO:<recipient@test.com>")
		readExpected(t, clientConn.reader, "250")

		writeCmd(t, clientConn, "DATA")
		readExpected(t, clientConn.reader, "354")

		_, err := clientConn.Write([]byte("This body is much longer than the 16-byte limit.\r\n.\r\n"))
		require.NoError(t, err)
		readExpected(t, clientConn.reader, "552")

		// Session must still be usable afterward (transaction reset, not the
		// connection torn down).
		writeCmd(t, clientConn, "QUIT")
		readExpected(t, clientConn.reader, "221")
	})
}
