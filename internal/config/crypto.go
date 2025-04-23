package config

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPrivateKey loads a private key from a PEM file.
// It supports RSA private keys and returns a crypto.Signer interface.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from file %s", path)
	}

	var privateKey crypto.Signer

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		privateKey = rsaKey
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}

		// Try to convert to appropriate type
		switch k := key.(type) {
		case *rsa.PrivateKey:
			privateKey = k
		default:
			return nil, fmt.Errorf("unsupported private key type from PKCS8: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("failed to load private key from %s", path)
	}

	return privateKey, nil
}
