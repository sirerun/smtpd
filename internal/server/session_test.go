package server

import (
	"bufio"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionHandleGreetingAndQuit(t *testing.T) {
	clientConn, serverConn := newMockConn()
	session := &Session{
		conn:      serverConn,
		reader:    bufio.NewReader(serverConn),
		writer:    bufio.NewWriter(serverConn),
		userStore: testUserStore,
		queue:     testQueue,
		logger:    testSessionLogger,
	}

	go func() {
		err := session.Handle()
		require.NoError(t, err)
	}()

	// Test greeting
	writeCmd(t, clientConn, "EHLO test.com\r\n")
	response := readExpected(t, clientConn.reader, "250")
	assert.Contains(t, response, "test.com")

	// Test quit
	writeCmd(t, clientConn, "QUIT\r\n")
	response = readExpected(t, clientConn.reader, "221")
	assert.Contains(t, response, "Bye")
}

func TestSessionHandleEHLO_Refactored(t *testing.T) {
	clientConn, serverConn := newMockConn()
	defer clientConn.Close()

	session := &Session{}
	session.Reset(serverConn, testQueue, nil, testUserStore, nil, testSessionLogger, "test-session-"+t.Name())

	// Test EHLO
	err := session.handleHelo("EHLO", "client.test")
	require.NoError(t, err)
	response := readExpected(t, clientConn.reader, "250")
	assert.Contains(t, response, "250-") // Multi-line response
}

func TestSessionHandleFullTransaction_Refactored(t *testing.T) {
	clientConn, serverConn := newMockConn()
	defer clientConn.Close()

	session := &Session{}
	session.Reset(serverConn, testQueue, nil, testUserStore, nil, testSessionLogger, "test-session-"+t.Name())

	// EHLO
	err := session.handleHelo("EHLO", "client.test")
	require.NoError(t, err)
	response := readExpected(t, clientConn.reader, "250")
	assert.Contains(t, response, "250-")

	// MAIL FROM
	err = session.handleMail("MAIL FROM:<sender@test.com>")
	require.NoError(t, err)
	readExpected(t, clientConn.reader, "250")

	// RCPT TO
	err = session.handleRcpt("RCPT TO:<recipient@test.com>")
	require.NoError(t, err)
	readExpected(t, clientConn.reader, "250")

	// DATA
	err = session.handleData()
	require.NoError(t, err)
	readExpected(t, clientConn.reader, "354")

	// Message content
	_, err = serverConn.Write([]byte("Subject: Test\r\n\r\nHello\r\n.\r\n"))
	require.NoError(t, err)
	readExpected(t, clientConn.reader, "250")

	// QUIT
	err = session.writeResponse(221, "Goodbye")
	require.NoError(t, err)
	readExpected(t, clientConn.reader, "221")
}
