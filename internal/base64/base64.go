package base64

import (
	"encoding/base64"
)

// Encode encodes the given data using base64 encoding
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode decodes the given base64 string
func Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
