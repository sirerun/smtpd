// Command smtpd-mcp runs the SMTP MCP server over stdio.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirerun/smtpd/internal/mcpserver"
)

func main() {
	fs := flag.NewFlagSet("smtpd-mcp", flag.ExitOnError)
	cfg := mcpserver.Config{}
	fs.BoolVar(&cfg.EnableSend, "enable-send", false, "enable smtpd_send_email (required to send)")
	fs.StringVar(&cfg.Host, "smtp-host", "", "owner-configured SMTP submission relay host:port")
	fs.StringVar(&cfg.From, "from", "", "fixed owner-configured sender email address")
	fs.StringVar(&cfg.Username, "smtp-user", "", "SMTP authentication username")
	fs.BoolVar(&cfg.AllowPlaintext, "allow-plaintext-loopback", false, "allow unencrypted SMTP only to an explicit loopback IP")
	fs.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "per-message SMTP timeout")
	fs.StringVar(&cfg.TLSCAFile, "tls-ca-file", "", "additional CA certificate PEM file for relay TLS")
	fs.StringVar(&cfg.TLSServerName, "tls-server-name", "", "TLS certificate server name (defaults to smtp-host name)")
	fs.StringVar(&cfg.TLSMode, "smtp-tls-mode", "starttls", "SMTP TLS mode: starttls (required by default) or implicit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		log.Printf("unexpected positional arguments: %v", fs.Args())
		os.Exit(2)
	}
	cfg.Password = os.Getenv("SMTPD_MCP_PASSWORD")
	server, err := mcpserver.NewServer(cfg, nil)
	if err != nil {
		log.Printf("configure smtpd MCP server: %v", err)
		os.Exit(2)
	}
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		if err != io.EOF {
			log.Printf("run smtpd MCP server: %v", err)
			os.Exit(1)
		}
	}
}
