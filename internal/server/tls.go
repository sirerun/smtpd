package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
)

// TLSConfig holds the configuration for TLS
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// NewTLSConfig creates a new TLS configuration
func NewTLSConfig(certFile, keyFile, caFile string) (*TLSConfig, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("certificate and key files are required")
	}

	return &TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
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

	if c.CAFile != "" {
		caCert, err := ioutil.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to append CA certificate")
		}

		config.ClientCAs = caCertPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}
