package base64

import (
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "simple",
			data: []byte("hello world"),
		},
		{
			name: "binary",
			data: []byte{0x00, 0xFF, 0x80, 0x7F},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Encode(tt.data)
			decoded, err := Decode(encoded)
			if err != nil {
				t.Errorf("Decode returned error: %v", err)
			}
			if string(decoded) != string(tt.data) {
				t.Errorf("Decode() = %v, want %v", decoded, tt.data)
			}
		})
	}
}

func TestDecodeInvalid(t *testing.T) {
	_, err := Decode("not base64")
	if err == nil {
		t.Error("Decode should return error for invalid input")
	}
}
