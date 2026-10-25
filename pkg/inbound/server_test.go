package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	netsmtp "net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirerun/smtpd/pkg/smtp"
)

type backend struct {
	mu    sync.Mutex
	raw   []byte
	env   Envelope
	err   error
	calls int
}

func (b *backend) CheckRecipient(_ context.Context, _ Envelope, to string) error {
	if to != "yes@example.org" {
		return smtp.NewError(550, "", "Unknown recipient")
	}
	return nil
}
func (b *backend) Accept(_ context.Context, e Envelope, raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.raw = append([]byte(nil), raw...)
	b.env = e
	return b.err
}

type client struct {
	net.Conn
	r *bufio.Reader
	t *testing.T
}

func (c *client) read(code string) {
	c.t.Helper()
	for {
		line, e := c.r.ReadString('\n')
		if e != nil {
			c.t.Fatal(e)
		}
		if !strings.HasPrefix(line, code) {
			c.t.Fatalf("want %s got %q", code, line)
		}
		if len(line) < 4 || line[3] != '-' {
			return
		}
	}
}
func (c *client) cmd(s, code string) { c.t.Helper(); fmt.Fprintf(c.Conn, "%s\r\n", s); c.read(code) }
func start(t *testing.T, cfg Config, b Backend) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	cfg.Hostname = "mx.example.org"
	s, e := New(cfg, b)
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("shutdown timeout")
		}
	})
	return l.Addr().String(), cancel, done
}
func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return &client{c, bufio.NewReader(c), t}
}
func TestDurableAndRaw(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			b := &backend{}
			if fail {
				b.err = fmt.Errorf("disk unavailable")
			}
			addr, _, _ := start(t, Config{}, b)
			c := dial(t, addr)
			c.read("220")
			c.cmd("EHLO test.example", "250")
			c.cmd("MAIL FROM:<>", "250")
			c.cmd("RCPT TO:<no@example.org>", "550")
			c.cmd("DATA", "503")
			c.cmd("RCPT TO:<yes@example.org>", "250")
			c.cmd("DATA", "354")
			want := "Subject: raw\r\n\r\n.dot\r\n"
			code := "250"
			if fail {
				code = "451"
			}
			c.cmd("Subject: raw\r\n\r\n..dot\r\n.", code)
			c.cmd("QUIT", "221")
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.calls != 1 || string(b.raw) != want || len(b.env.Recipients) != 1 {
				t.Fatalf("bad acceptance: %+v %q", b, string(b.raw))
			}
		})
	}
}
func TestLimitsAndGrammar(t *testing.T) {
	b := &backend{}
	addr, _, _ := start(t, Config{MaxRecipients: 1, MaxMessageBytes: 4}, b)
	c := dial(t, addr)
	c.read("220")
	c.cmd("EHLO bad name", "501")
	c.cmd("MAIL FROM:<>", "503")
	c.cmd("EHLO good.example", "250")
	c.cmd("AUTH PLAIN abc", "502")
	c.cmd("MAIL FROM:<a@example.org> SMTPUTF8", "555")
	c.cmd("MAIL FROM:<>", "250")
	c.cmd("RCPT TO:<yes@example.org>", "250")
	c.cmd("RCPT TO:<yes@example.org>", "452")
	c.cmd("DATA", "354")
	c.cmd("large", "552")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.calls != 0 {
		t.Fatal("accepted oversized message")
	}
}
func TestIPLimits(t *testing.T) {
	for _, cfg := range []Config{{MaxConnectionsPerIP: 1}, {ConnectionsPerMinute: 1}} {
		b := &backend{}
		addr, _, _ := start(t, cfg, b)
		c := dial(t, addr)
		c.read("220")
		other := dial(t, addr)
		other.read("421")
	}
}
func TestSTARTTLSReset(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	b := &backend{}
	addr, _, _ := start(t, Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}}, b)
	c := dial(t, addr)
	c.read("220")
	c.cmd("EHLO old.example", "250")
	c.cmd("MAIL FROM:<>", "250")
	c.cmd("RCPT TO:<yes@example.org>", "250")
	c.cmd("STARTTLS", "220")
	tc := tls.Client(c.Conn, &tls.Config{InsecureSkipVerify: true})
	if e := tc.Handshake(); e != nil {
		t.Fatal(e)
	}
	c.Conn = tc
	c.r = bufio.NewReader(tc)
	c.cmd("DATA", "503")
	c.cmd("MAIL FROM:<>", "503")
	c.cmd("EHLO new.example", "250")
	c.cmd("MAIL FROM:<>", "250")
	c.cmd("RCPT TO:<yes@example.org>", "250")
	c.cmd("DATA", "354")
	c.cmd("x\r\n.", "250")
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.env.TLS || b.env.Helo != "new.example" {
		t.Fatal(b.env)
	}
}
func TestSafeErrors(t *testing.T) {
	for _, e := range []error{smtp.NewError(250, "", "ok"), smtp.NewError(550, "", "bad\r\n250 injected")} {
		if replyError(e) != "451 Temporary local failure" {
			t.Fatal("unsafe error")
		}
	}
}

type blockedBackend struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockedBackend) CheckRecipient(context.Context, Envelope, string) error { return nil }
func (b *blockedBackend) Accept(ctx context.Context, _ Envelope, _ []byte) error {
	close(b.entered)
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestAcknowledgementWaitsForCommit(t *testing.T) {
	b := &blockedBackend{make(chan struct{}), make(chan struct{})}
	addr, _, _ := start(t, Config{}, b)
	c := dial(t, addr)
	c.read("220")
	c.cmd("HELO example.org", "250")
	c.cmd("MAIL FROM:<>", "250")
	c.cmd("RCPT TO:<local@example.org>", "250")
	c.cmd("DATA", "354")
	fmt.Fprint(c.Conn, "x\r\n.\r\n")
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("Accept not called")
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Fatalf("premature acknowledgement %q", line)
	}
	close(b.release)
	c.SetReadDeadline(time.Now().Add(time.Second))
	c.read("250")
}
func TestCancellationClosesConnection(t *testing.T) {
	addr, cancel, _ := start(t, Config{}, &backend{})
	c := dial(t, addr)
	c.read("220")
	cancel()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("connection remained open")
	}
}
func TestCommandBound(t *testing.T) {
	addr, _, _ := start(t, Config{}, &backend{})
	c := dial(t, addr)
	c.read("220")
	fmt.Fprint(c.Conn, strings.Repeat("X", 513)+"\r\n")
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("overlong command accepted")
	}
}

func TestSIZEAndStandardClient(t *testing.T) {
	b := &backend{}
	addr, _, _ := start(t, Config{MaxMessageBytes: 1024}, b)
	c := dial(t, addr)
	c.read("220")
	c.cmd("EHLO example.org", "250")
	c.cmd("MAIL FROM:<a@example.org> SIZE=1025", "552")
	c.cmd("MAIL FROM:<a@example.org> SIZE=-1", "501")
	c.cmd("MAIL FROM:<a@example.org> SIZE=10 SIZE=20", "555")
	c.cmd("MAIL FROM:<a@example.org> SIZE=10", "250")
	c.cmd("RSET", "250")
	c.cmd("QUIT", "221")
	standard, err := netsmtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer standard.Close()
	if err = standard.Mail("sender@example.org"); err != nil {
		t.Fatal(err)
	}
	if err = standard.Rcpt("yes@example.org"); err != nil {
		t.Fatal(err)
	}
	w, err := standard.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("Subject: standard\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = standard.Quit(); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.calls != 1 {
		t.Fatal("standard client message not accepted")
	}
}
