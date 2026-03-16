package dkim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/message"
	"github.com/sirerun/smtpd/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

// TODO: Add tests for DKIMVerifier.OnMessage
// - Mock DNS lookups for DKIM public keys.
// - Provide test messages (as []byte) with:
//   - Valid DKIM signature
//   - Invalid signature (bad body hash)
//   - Invalid signature (bad header hash/sig)
//   - Signature with missing/unresolvable public key
//   - Malformed DKIM-Signature header
//   - Multiple DKIM signatures (some valid, some invalid)
//   - Message with no DKIM signature
// - Test different canonicalization methods (simple/relaxed) if possible.
// - Verify correct SMTP error codes are returned on failure.

// Example messages (replace with actual minimal valid/invalid examples)
var testMsgNoSig = []byte(`From: sender@example.com
To: recipient@example.net
Subject: Test

This message has no DKIM signature.
`)

// NOTE: Creating valid signed messages requires a private key and proper signing.
// For robust testing, pre-signed messages or a test key pair are needed.
// The go-dkim library itself has test vectors that could be adapted.
// For this example, we will focus on the plugin's handling of Verify results,
// assuming the Verify function behaves correctly (which should be tested in the library itself).

// We need a way to inject results from dkim.Verify for testing the plugin logic.
// We can achieve this by creating a test harness or potentially wrapping/mocking dkim.Verify,
// though the latter is more complex.

// Let's simulate results by creating a custom verification function for tests.
// This avoids needing actual crypto operations or DNS mocking within the plugin test itself.

// mockVerify simulates dkim.Verify results for specific inputs.
// It now returns []*dkim.Verification as expected by the library.
func mockVerify(r io.Reader) ([]*dkim.Verification, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return nil, fmt.Errorf("mockVerify failed to read: %w", err)
	}
	msgStr := buf.String()

	if strings.Contains(msgStr, "X-Test-DKIM: NoSig") {
		return []*dkim.Verification{}, nil
	}
	if strings.Contains(msgStr, "X-Test-DKIM: Valid") {
		return []*dkim.Verification{
			{Domain: "test.com", Err: nil},
		}, nil
	}
	// Use errors.New or specific error types if available/needed for checks
	// For simplicity, using distinct error messages for test comparison.
	errSigInvalid := errors.New("signature invalid")
	errBodyHash := errors.New("body hash invalid")
	errKeyUnavailable := errors.New("key unavailable")

	if strings.Contains(msgStr, "X-Test-DKIM: InvalidSig") {
		return []*dkim.Verification{
			{Domain: "test.com", Err: errSigInvalid},
		}, nil
	}
	if strings.Contains(msgStr, "X-Test-DKIM: InvalidBody") {
		return []*dkim.Verification{
			{Domain: "test.com", Err: errBodyHash},
		}, nil
	}
	if strings.Contains(msgStr, "X-Test-DKIM: KeyNotFound") {
		return []*dkim.Verification{
			{Domain: "test.com", Err: errKeyUnavailable},
		}, nil
	}
	if strings.Contains(msgStr, "X-Test-DKIM: VerifyError") {
		// Simulate an error from the Verify function itself
		return nil, fmt.Errorf("internal verify error")
	}
	if strings.Contains(msgStr, "X-Test-DKIM: MultiMixed") {
		return []*dkim.Verification{
			{Domain: "good.com", Err: nil},
			{Domain: "bad.com", Err: errSigInvalid},
		}, nil
	}
	if strings.Contains(msgStr, "X-Test-DKIM: MultiInvalid") {
		return []*dkim.Verification{
			{Domain: "bad1.com", Err: errBodyHash},
			{Domain: "bad2.com", Err: errKeyUnavailable},
		}, nil
	}

	// Default: Simulate no signature found
	return []*dkim.Verification{}, nil
}

// Store the original dkim.Verify function
// var originalDkimVerifyFunc = dkim.Verify // No longer needed with DI

// Need a shared logger for tests
var testLogger = logging.New(logging.DefaultConfig())

var (
	ErrSignatureNotValid = errors.New("signature not valid")
)

type mockVerification struct {
	domain string
	err    error
}

func (v *mockVerification) Domain() string {
	return v.domain
}

func (v *mockVerification) Err() error {
	return v.err
}

func TestDKIMVerifier_OnMessage(t *testing.T) {
	tests := []struct {
		name     string
		verifier DKIMVerifier
		msg      *message.Message
		wantErr  bool
	}{
		{
			name: "Valid signature",
			verifier: DKIMVerifier{
				logger: testLogger,
				verifyFn: func(r io.Reader) ([]*dkim.Verification, error) {
					return []*dkim.Verification{
						{Domain: "example.com", Err: nil},
					}, nil
				},
			},
			msg:     &message.Message{},
			wantErr: false,
		},
		{
			name: "Invalid signature",
			verifier: DKIMVerifier{
				logger: testLogger,
				verifyFn: func(r io.Reader) ([]*dkim.Verification, error) {
					return []*dkim.Verification{
						{Domain: "example.com", Err: ErrSignatureNotValid},
					}, nil
				},
			},
			msg:     &message.Message{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientIP := net.ParseIP("192.0.2.1")
			sessionInfo := &plugin.SessionInfo{
				SessionID:  "test-session",
				RemoteAddr: &net.TCPAddr{IP: clientIP, Port: 12345},
			}
			msgInfo := &plugin.MessageInfo{Data: tt.msg.Data}
			err := tt.verifier.OnMessage(context.Background(), sessionInfo, msgInfo)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
