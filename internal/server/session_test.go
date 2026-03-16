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
