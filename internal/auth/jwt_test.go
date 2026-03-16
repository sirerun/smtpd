package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testSecret = []byte("test-secret-key-for-hmac-signing")

func makeToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(testSecret)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return s
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "testuser",
		"iss": "sire",
		"aud": jwt.ClaimStrings{"smtpd"},
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": jwt.NewNumericDate(time.Now()),
	}
}

func TestJWTAuthenticateToken(t *testing.T) {
	auth := NewJWTAuthenticatorHMAC(testSecret, "sire", "smtpd")

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantSub   string
		wantErr   bool
		errTarget error
	}{
		{
			name:    "valid token",
			claims:  validClaims(),
			wantSub: "testuser",
			wantErr: false,
		},
		{
			name: "expired token",
			claims: jwt.MapClaims{
				"sub": "testuser",
				"iss": "sire",
				"aud": jwt.ClaimStrings{"smtpd"},
				"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				"iat": jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
			wantErr:   true,
			errTarget: ErrTokenInvalid,
		},
		{
			name: "wrong issuer",
			claims: jwt.MapClaims{
				"sub": "testuser",
				"iss": "evil",
				"aud": jwt.ClaimStrings{"smtpd"},
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			wantErr:   true,
			errTarget: ErrInvalidIssuer,
		},
		{
			name: "wrong audience",
			claims: jwt.MapClaims{
				"sub": "testuser",
				"iss": "sire",
				"aud": jwt.ClaimStrings{"other-service"},
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			wantErr:   true,
			errTarget: ErrInvalidAud,
		},
		{
			name: "missing subject",
			claims: jwt.MapClaims{
				"iss": "sire",
				"aud": jwt.ClaimStrings{"smtpd"},
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			wantErr:   true,
			errTarget: ErrTokenInvalid,
		},
		{
			name: "missing expiry",
			claims: jwt.MapClaims{
				"sub": "testuser",
				"iss": "sire",
				"aud": jwt.ClaimStrings{"smtpd"},
			},
			wantErr:   true,
			errTarget: ErrTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenStr := makeToken(t, tt.claims)
			sub, err := auth.AuthenticateToken(tokenStr)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (sub=%q)", sub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sub != tt.wantSub {
				t.Errorf("subject = %q, want %q", sub, tt.wantSub)
			}
		})
	}
}

func TestJWTWrongSigningKey(t *testing.T) {
	auth := NewJWTAuthenticatorHMAC(testSecret, "sire", "smtpd")

	// Sign with a different key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	tokenStr, err := token.SignedString([]byte("wrong-key"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.AuthenticateToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestJWTWrongSigningMethod(t *testing.T) {
	// Create authenticator expecting HMAC but give it a token claiming "none"
	auth := NewJWTAuthenticatorHMAC(testSecret, "sire", "smtpd")

	_, err := auth.AuthenticateToken("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")
	if err == nil {
		t.Fatal("expected error for 'none' algorithm")
	}
}
