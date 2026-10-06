package mcpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeSender struct {
	sent []Email
	err  error
}

func (f *fakeSender) Send(_ context.Context, e Email) (string, error) {
	f.sent = append(f.sent, e)
	return "accepted", f.err
}

func TestMCPToolsRegisteredAndPreviewIsNetworkFree(t *testing.T) {
	sender := &fakeSender{}
	srv, err := NewServer(Config{EnableSend: true, From: "owner@example.com", Host: "relay.invalid:587"}, sender)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	serverSession, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	tools, err := clientSession.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"smtpd_preview_email": false, "smtpd_send_email": false, "smtpd_status": false}
	for _, tool := range tools.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %s was not registered", name)
		}
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "smtpd_preview_email", Arguments: map[string]any{"to": "person@example.net", "subject": "Hello", "text": "Preview body"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("preview returned tool error: %#v", result.Content)
	}
	if len(sender.sent) != 0 {
		t.Fatal("preview invoked sender")
	}
}

func TestValidationRejectsHeaderInjectionAndMalformedAddresses(t *testing.T) {
	for _, input := range []emailInput{
		{To: "victim@example.net\r\nBcc:evil@example.net", Subject: "ok", Text: "body"},
		{To: "victim@example.net", Subject: "ok\nBcc:evil@example.net", Text: "body"},
		{To: "<victim@example.net>", Subject: "ok", Text: "body"},
		{To: "victim@example.net", Subject: "ok", Text: strings.Repeat("x", maxFieldBytes+1)},
	} {
		if err := validateEmail(input); err == nil {
			t.Errorf("validateEmail(%+v) succeeded", input)
		}
	}
}

func TestEncodeMessageFoldsHeadersAndBodyLines(t *testing.T) {
	data, err := encodeMessage("sender@example.com", Email{To: "recipient@example.com", Subject: strings.Repeat("é", 80), Text: strings.Repeat("hello", 100)})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("RFC line is %d bytes", len(line))
		}
	}
	if !strings.Contains(string(data), "\r\n ") {
		t.Fatal("expected folded encoded subject")
	}
}

func TestSMTPRequiresTLSByDefault(t *testing.T) {
	addr, stop := startFakeSMTP(t, smtpBehavior{})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err == nil || !strings.Contains(err.Error(), "did not offer STARTTLS") {
		t.Fatalf("got %v", err)
	}
}

func TestSMTPNeverAuthenticatesWithoutTLS(t *testing.T) {
	addr, stop := startFakeSMTP(t, smtpBehavior{})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", Username: "relay-user", Password: "relay-secret", AllowPlaintext: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err == nil || !strings.Contains(err.Error(), "authentication without TLS") {
		t.Fatalf("got %v", err)
	}
}

func TestSMTPAcceptsOnlyAfterFinalDataResponse(t *testing.T) {
	addr, stop := startFakeSMTP(t, smtpBehavior{})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", AllowPlaintext: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err != nil || !strings.Contains(result, "accepted") {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func TestSMTPImplicitTLSWithConfiguredCA(t *testing.T) {
	cert, caPEM := testCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	caFile := t.TempDir() + "/relay.pem"
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	addr, stop := startFakeSMTPListener(t, listener, smtpBehavior{})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", TLSMode: "implicit", TLSCAFile: caFile, TLSServerName: "localhost", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err != nil || !strings.Contains(result, "accepted") {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func TestSMTPStartTLSVerifiesCertificateAndAuthenticates(t *testing.T) {
	cert, caPEM := testCertificate(t)
	caFile := t.TempDir() + "/relay.pem"
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	addr, stop := startFakeSMTP(t, smtpBehavior{advertiseStartTLS: true, startTLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", Username: "relay-user", Password: "relay-secret", TLSCAFile: caFile, TLSServerName: "localhost", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err != nil || !strings.Contains(result, "accepted") {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func TestSMTPStartTLSRejectsUnknownCertificate(t *testing.T) {
	cert, _ := testCertificate(t)
	addr, stop := startFakeSMTP(t, smtpBehavior{advertiseStartTLS: true, startTLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}})
	defer stop()
	sender, err := NewSMTPSender(Config{Host: addr, From: "sender@example.com", TLSServerName: "localhost", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
	if err == nil || !strings.Contains(err.Error(), "start TLS") {
		t.Fatalf("got %v", err)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSMTPRefusalAndCanceledUnknownOutcome(t *testing.T) {
	t.Run("final refusal", func(t *testing.T) {
		addr, stop := startFakeSMTP(t, smtpBehavior{rejectData: true})
		defer stop()
		sender, _ := NewSMTPSender(Config{Host: addr, From: "sender@example.com", AllowPlaintext: true, Timeout: time.Second})
		_, err := sender.Send(context.Background(), Email{To: "person@example.net", Subject: "Hi", Text: "body"})
		if err == nil || !strings.Contains(err.Error(), "rejected message after DATA") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cancel after data", func(t *testing.T) {
		addr, stop := startFakeSMTP(t, smtpBehavior{hangData: true})
		defer stop()
		sender, _ := NewSMTPSender(Config{Host: addr, From: "sender@example.com", AllowPlaintext: true, Timeout: time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		_, err := sender.Send(ctx, Email{To: "person@example.net", Subject: "Hi", Text: "body"})
		if err == nil || !strings.Contains(err.Error(), "outcome unknown") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSMTPSenderConfigRejectsInvalidTLSModeAndCredentials(t *testing.T) {
	for _, cfg := range []Config{{Host: "localhost:25", TLSMode: "future"}, {Host: "localhost:25", Username: "user", Password: "secret", AllowPlaintext: true}} {
		if _, err := NewSMTPSender(cfg); err == nil {
			t.Errorf("NewSMTPSender(%+v) succeeded", cfg)
		}
	}
}

type smtpBehavior struct {
	rejectData, hangData, advertiseStartTLS bool
	startTLS                                *tls.Config
}

func startFakeSMTP(t *testing.T, behavior smtpBehavior) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return startFakeSMTPListener(t, listener, behavior)
}

func startFakeSMTPListener(t *testing.T, listener net.Listener, behavior smtpBehavior) (string, func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		var netConn net.Conn = conn
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if tlsConn.Handshake() != nil {
				return
			}
			netConn = tlsConn
		}
		tp := textproto.NewConn(netConn)
		defer tp.Close()
		_ = tp.PrintfLine("220 test ESMTP")
		for {
			line, e := tp.ReadLine()
			if e != nil {
				return
			}
			command := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(command, "EHLO "), strings.HasPrefix(command, "HELO "):
				if behavior.advertiseStartTLS && behavior.startTLS != nil {
					_ = tp.PrintfLine("250-test")
					_ = tp.PrintfLine("250-STARTTLS")
					_ = tp.PrintfLine("250 AUTH PLAIN")
				} else {
					_ = tp.PrintfLine("250 test")
				}
			case command == "STARTTLS":
				if behavior.startTLS == nil {
					_ = tp.PrintfLine("454 unavailable")
					continue
				}
				_ = tp.PrintfLine("220 begin TLS")
				tlsConn := tls.Server(netConn, behavior.startTLS)
				if tlsConn.Handshake() != nil {
					return
				}
				netConn = tlsConn
				tp = textproto.NewConn(netConn)
			case strings.HasPrefix(command, "AUTH "):
				_ = tp.PrintfLine("235 authenticated")
			case strings.HasPrefix(command, "MAIL FROM:"):
				_ = tp.PrintfLine("250 sender ok")
			case strings.HasPrefix(command, "RCPT TO:"):
				_ = tp.PrintfLine("250 recipient ok")
			case command == "DATA":
				_ = tp.PrintfLine("354 continue")
				for {
					body, e := tp.ReadLine()
					if e != nil {
						return
					}
					if body == "." {
						break
					}
				}
				if behavior.hangData {
					for {
						if _, e := tp.ReadLine(); e != nil {
							return
						}
					}
				}
				if behavior.rejectData {
					_ = tp.PrintfLine("550 policy rejected")
				} else {
					_ = tp.PrintfLine("250 queued")
				}
			case command == "QUIT":
				_ = tp.PrintfLine("221 bye")
				return
			default:
				_ = tp.PrintfLine("250 ok")
			}
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close(); <-done }
}
