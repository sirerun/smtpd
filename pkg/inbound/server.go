// Package inbound provides an SMTP receiver whose success acknowledgement is
// conditional on durable acceptance by the caller. It does not provide relay,
// authentication, submission, delivery queues, or SMTPUTF8.
package inbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirerun/smtpd/pkg/smtp"
)

type Envelope struct {
	From       string
	Recipients []string
	RemoteIP   net.IP
	Helo       string
	TLS        bool
}
type Backend interface {
	CheckRecipient(context.Context, Envelope, string) error
	Accept(context.Context, Envelope, []byte) error
}
type Config struct {
	Hostname                                                 string
	TLSConfig                                                *tls.Config
	MaxMessageBytes                                          int64
	MaxRecipients, MaxConnections, MaxData                   int
	MaxConnectionsPerIP, ConnectionsPerMinute, MaxTrackedIPs int
	IdleTimeout, TransactionTimeout                          time.Duration
}
type peer struct {
	active, attempts int
	window           time.Time
}
type Server struct {
	cfg     Config
	backend Backend
	data    chan struct{}
	mu      sync.Mutex
	serving bool
	peers   map[string]*peer
}

func New(c Config, b Backend) (*Server, error) {
	if b == nil || !validHost(c.Hostname) {
		return nil, errors.New("inbound: backend and valid hostname required")
	}
	if c.MaxConnectionsPerIP < 0 || c.ConnectionsPerMinute < 0 || c.MaxTrackedIPs < 0 || c.MaxMessageBytes < 0 || c.MaxRecipients < 0 || c.MaxConnections < 0 || c.MaxData < 0 || c.IdleTimeout < 0 || c.TransactionTimeout < 0 {
		return nil, errors.New("inbound: negative limit")
	}
	if c.MaxConnectionsPerIP == 0 {
		c.MaxConnectionsPerIP = 10
	}
	if c.ConnectionsPerMinute == 0 {
		c.ConnectionsPerMinute = 60
	}
	if c.MaxTrackedIPs == 0 {
		c.MaxTrackedIPs = 10000
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 25 << 20
	}
	if c.MaxRecipients == 0 {
		c.MaxRecipients = 100
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 100
	}
	if c.MaxData == 0 {
		c.MaxData = 10
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = time.Minute
	}
	if c.TransactionTimeout == 0 {
		c.TransactionTimeout = 5 * time.Minute
	}
	if c.TLSConfig != nil {
		c.TLSConfig = c.TLSConfig.Clone()
	}
	return &Server{cfg: c, backend: b, data: make(chan struct{}, c.MaxData), peers: make(map[string]*peer)}, nil
}
func validHost(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		v := s[1 : len(s)-1]
		v = strings.TrimPrefix(v, "IPv6:")
		return net.ParseIP(v) != nil
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Serve owns and closes l. Cancellation closes all connections and waits for
// handlers. Backends must honor context cancellation; a Server serves once at a time.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if l == nil {
		return errors.New("inbound: nil listener")
	}
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return errors.New("inbound: already serving")
	}
	s.serving = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.serving = false; s.mu.Unlock() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	var wg sync.WaitGroup
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
			mu.Lock()
			for c := range conns {
				c.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	defer func() {
		cancel()
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		now := time.Now()
		s.mu.Lock()
		for k, p := range s.peers {
			if p.active == 0 && now.Sub(p.window) >= time.Minute {
				delete(s.peers, k)
			}
		}
		p := s.peers[host]
		if p == nil {
			p = &peer{window: now}
			if len(s.peers) < s.cfg.MaxTrackedIPs {
				s.peers[host] = p
			}
		}
		if now.Sub(p.window) >= time.Minute {
			p.attempts = 0
			p.window = now
		}
		mu.Lock()
		allowed := len(conns) < s.cfg.MaxConnections && s.peers[host] != nil && p.active < s.cfg.MaxConnectionsPerIP && p.attempts < s.cfg.ConnectionsPerMinute && ctx.Err() == nil
		if allowed {
			p.active++
			p.attempts++
			conns[c] = true
		}
		mu.Unlock()
		s.mu.Unlock()
		if !allowed {
			c.SetWriteDeadline(time.Now().Add(time.Second))
			io.WriteString(c, "421 Too many connections\r\n")
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
				s.mu.Lock()
				p.active--
				s.mu.Unlock()
			}()
			s.session(ctx, c, net.ParseIP(host))
		}()
	}
}
func clone(e Envelope) Envelope {
	e.Recipients = append([]string(nil), e.Recipients...)
	e.RemoteIP = append(net.IP(nil), e.RemoteIP...)
	return e
}
func replyError(err error) string {
	var e smtp.Error
	if errors.As(err, &e) && e.Code() >= 400 && e.Code() <= 599 {
		message := e.Message()
		if len(message) <= 400 && strings.HasPrefix(message, fmt.Sprintf("%d ", e.Code())) && !strings.ContainsAny(message, "\r\n") {
			return message
		}
	}
	return "451 Temporary local failure"
}

// readLine enforces CRLF and never allocates an unbounded line.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > max || len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errors.New("invalid line")
	}
	return line, nil
}
func path(arg, prefix string, empty bool) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(arg), prefix+":<") || !strings.HasSuffix(arg, ">") {
		return "", false
	}
	v := arg[len(prefix)+2 : len(arg)-1]
	if v == "" {
		return v, empty
	}
	if len(v) > 254 || strings.Count(v, "@") != 1 {
		return "", false
	}
	a, b, _ := strings.Cut(v, "@")
	if a == "" || strings.HasPrefix(a, ".") || strings.HasSuffix(a, ".") || strings.Contains(a, "..") || !validHost(b) {
		return "", false
	}
	for _, r := range a {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", r)) {
			return "", false
		}
	}
	return v, true
}

// mailPath accepts only the SIZE extension advertised by this receiver.
func mailPath(arg string, limit int64) (string, string) {
	end := strings.IndexByte(arg, '>')
	if end < 0 {
		return "", "501 Invalid sender"
	}
	sender, ok := path(arg[:end+1], "FROM", true)
	if !ok {
		return "", "501 Invalid sender"
	}
	tail := arg[end+1:]
	if tail == "" {
		return sender, ""
	}
	if !strings.HasPrefix(tail, " ") {
		return "", "501 Invalid MAIL parameters"
	}
	params := strings.Fields(tail)
	if len(params) != 1 || !strings.HasPrefix(strings.ToUpper(params[0]), "SIZE=") {
		return "", "555 Unsupported MAIL parameters"
	}
	value := params[0][5:]
	if value == "" {
		return "", "501 Invalid SIZE"
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return "", "501 Invalid SIZE"
		}
	}
	size, err := strconv.ParseUint(value, 10, 64)
	if err != nil || size > uint64(limit) {
		return "", "552 Declared message size exceeds limit"
	}
	return sender, ""
}

// transactionContext transfers cancellation ownership to session. The session
// keeps only one active cancellation function, cancels it on reset, and cancels
// the final transaction when the session exits.
func (s *Server) transactionContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, s.cfg.TransactionTimeout)
}

func (s *Server) session(ctx context.Context, c net.Conn, ip net.IP) {
	r := bufio.NewReaderSize(c, 4096)
	var e Envelope
	e.RemoteIP = ip
	var tx context.Context
	var stop context.CancelFunc
	var started time.Time
	mail := false
	reset := func() {
		if stop != nil {
			stop()
			stop = nil
		}
		tx = nil
		started = time.Time{}
		e.From = ""
		e.Recipients = nil
		mail = false
	}
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	send := func(msg string) bool {
		c.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout))
		_, err := io.WriteString(c, msg+"\r\n")
		return err == nil
	}
	if !send("220 " + s.cfg.Hostname + " ESMTP") {
		return
	}
	for {
		deadline := time.Now().Add(s.cfg.IdleTimeout)
		if !started.IsZero() && started.Add(s.cfg.TransactionTimeout).Before(deadline) {
			deadline = started.Add(s.cfg.TransactionTimeout)
		}
		c.SetReadDeadline(deadline)
		raw, err := readLine(r, 512)
		if err != nil {
			return
		}
		line := string(raw[:len(raw)-2])
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		switch cmd {
		case "EHLO", "HELO":
			if !validHost(arg) {
				if !send("501 Invalid greeting") {
					return
				}
				continue
			}
			reset()
			e.Helo = arg
			response := "250 " + s.cfg.Hostname
			if cmd == "EHLO" {
				response = "250-" + s.cfg.Hostname + "\r\n250-SIZE " + fmt.Sprint(s.cfg.MaxMessageBytes)
				if s.cfg.TLSConfig != nil && !e.TLS {
					response += "\r\n250-STARTTLS"
				}
				response += "\r\n250 HELP"
			}
			if !send(response) {
				return
			}
		case "STARTTLS":
			if arg != "" {
				if !send("501 Unexpected arguments") {
					return
				}
				continue
			}
			if s.cfg.TLSConfig == nil || e.TLS || e.Helo == "" {
				if !send("503 STARTTLS unavailable") {
					return
				}
				continue
			}
			if r.Buffered() != 0 {
				send("554 Pipelining across STARTTLS prohibited")
				return
			}
			if !send("220 Ready for TLS") {
				return
			}
			reset()
			tc := tls.Server(c, s.cfg.TLSConfig)
			hc, cancel := context.WithTimeout(ctx, s.cfg.IdleTimeout)
			err := tc.HandshakeContext(hc)
			cancel()
			if err != nil {
				return
			}
			c = tc
			r = bufio.NewReaderSize(c, 4096)
			e = Envelope{RemoteIP: ip, TLS: true}
		case "MAIL":
			if e.Helo == "" || mail {
				if !send("503 Bad sequence") {
					return
				}
				continue
			}
			from, failure := mailPath(arg, s.cfg.MaxMessageBytes)
			if failure != "" {
				if !send(failure) {
					return
				}
				continue
			}
			reset()
			e.From = from
			mail = true
			started = time.Now()
			tx, stop = s.transactionContext(ctx)
			if !send("250 Sender accepted") {
				reset()
				return
			}
		case "RCPT":
			if !mail {
				if !send("503 MAIL required") {
					return
				}
				continue
			}
			to, ok := path(arg, "TO", false)
			if !ok {
				if !send("501 Invalid recipient or unsupported parameters") {
					return
				}
				continue
			}
			if len(e.Recipients) >= s.cfg.MaxRecipients {
				if !send("452 Too many recipients") {
					return
				}
				continue
			}
			err := s.backend.CheckRecipient(tx, clone(e), to)
			if err == nil {
				err = tx.Err()
			}
			if err != nil {
				if !send(replyError(err)) {
					return
				}
				continue
			}
			e.Recipients = append(e.Recipients, to)
			if !send("250 Recipient accepted") {
				return
			}
		case "DATA":
			if arg != "" {
				if !send("501 Unexpected arguments") {
					return
				}
				continue
			}
			if !mail || len(e.Recipients) == 0 {
				if !send("503 Recipient required") {
					return
				}
				continue
			}
			select {
			case s.data <- struct{}{}:
			default:
				if !send("452 DATA capacity exceeded") {
					return
				}
				continue
			}
			if !send("354 End with <CRLF>.<CRLF>") {
				<-s.data
				return
			}
			var data bytes.Buffer
			var failure error
			for {
				deadline := time.Now().Add(s.cfg.IdleTimeout)
				if started.Add(s.cfg.TransactionTimeout).Before(deadline) {
					deadline = started.Add(s.cfg.TransactionTimeout)
				}
				c.SetReadDeadline(deadline)
				b, err := readLine(r, 1001)
				if err != nil {
					failure = err
					break
				}
				if bytes.Equal(b, []byte(".\r\n")) {
					break
				}
				if b[0] == '.' {
					b = b[1:]
				}
				if len(b) > 1000 || int64(data.Len())+int64(len(b)) > s.cfg.MaxMessageBytes {
					failure = errors.New("message too large")
					break
				}
				data.Write(b)
			}
			if failure != nil {
				<-s.data
				send("552 Message size or framing limit exceeded")
				return
			}
			err := tx.Err()
			if err == nil {
				err = s.backend.Accept(tx, clone(e), data.Bytes())
			}
			if err == nil {
				err = tx.Err()
			}
			<-s.data
			if err != nil {
				if !send(replyError(err)) {
					return
				}
			} else if !send("250 Message accepted") {
				return
			}
			reset()
		case "RSET":
			if arg != "" {
				if !send("501 Unexpected arguments") {
					return
				}
				continue
			}
			reset()
			if !send("250 Reset") {
				return
			}
		case "NOOP":
			if !send("250 OK") {
				return
			}
		case "QUIT":
			send("221 Bye")
			return
		default:
			if !send("502 Command not implemented") {
				return
			}
		}
	}
}
