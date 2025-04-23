package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfig holds the configuration for TLS
type TLSConfig struct {
	CertFile string // Path to the certificate file
	KeyFile  string // Path to the private key file
	// CAFile is only needed if client certificate validation is required
	// This can be omitted for most typical SMTP server deployments
	CAFile string
}

// NewTLSConfig creates a new TLS configuration
func NewTLSConfig(certFile, keyFile string) (*TLSConfig, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("certificate and key files are required")
	}

	return &TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}, nil
}

// CreateTLSConfig creates a tls.Config from the TLSConfig
func (c *TLSConfig) CreateTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	// Only configure client certificate validation if CAFile is specified
	if c.CAFile != "" {
		caCert, err := c.LoadCA()
		if err != nil {
			return nil, err
		}

		if caCert != nil {
			config.ClientCAs = caCert
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return config, nil
}

// LoadCA loads the CA certificate from file.
func (c *TLSConfig) LoadCA() (*x509.CertPool, error) {
	if c.CAFile == "" {
		return nil, nil
	}

	caCert, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to append CA certificate")
	}

	return caCertPool, nil
}
