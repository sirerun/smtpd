//go:build integration

package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestIntegration_BcryptStoreRoundTrip(t *testing.T) {
	store := NewStore()

	users := []struct {
		username string
		password string
	}{
		{"alice", "hunter2"},
		{"bob", "correct-horse-battery-staple"},
		{"carol", "p@$$w0rd!"},
	}

	for _, u := range users {
		if err := store.AddUser(u.username, u.password); err != nil {
			t.Fatalf("AddUser(%q): %v", u.username, err)
		}
	}

	// Verify all users can authenticate
	for _, u := range users {
		ok, err := store.Authenticate(u.username, u.password)
		if err != nil || !ok {
			t.Errorf("Authenticate(%q) failed: ok=%v err=%v", u.username, ok, err)
		}
	}

	// Verify wrong passwords fail
	for _, u := range users {
		ok, err := store.Authenticate(u.username, "wrong")
		if ok {
			t.Errorf("Authenticate(%q, wrong) should fail", u.username)
		}
		if err != ErrInvalidCredentials {
			t.Errorf("Authenticate(%q, wrong) err = %v, want ErrInvalidCredentials", u.username, err)
		}
	}

	// Verify unknown users fail
	ok, err := store.Authenticate("eve", "whatever")
	if ok || err != ErrUserNotFound {
		t.Errorf("Authenticate(eve) = (%v, %v), want (false, ErrUserNotFound)", ok, err)
	}
}

func TestIntegration_BcryptHashFormat(t *testing.T) {
	store := NewStore()
	if err := store.AddUser("test", "mypassword"); err != nil {
		t.Fatal(err)
	}

	store.mu.RLock()
	user := store.users["test"]
	store.mu.RUnlock()

	// Verify it's a valid bcrypt hash with cost >= 10
	cost, err := bcrypt.Cost(user.PasswordHash)
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost < 10 {
		t.Errorf("bcrypt cost = %d, want >= 10", cost)
	}
}

func TestIntegration_JWTFullFlow(t *testing.T) {
	secret := []byte("integration-test-secret")
	jwtAuth := NewJWTAuthenticatorHMAC(secret, "sire", "smtpd")

	// Valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "integration-user",
		"iss": "sire",
		"aud": jwt.ClaimStrings{"smtpd"},
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat": jwt.NewNumericDate(time.Now()),
	})
	tokenStr, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}

	sub, err := jwtAuth.AuthenticateToken(tokenStr)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if sub != "integration-user" {
		t.Errorf("subject = %q, want %q", sub, "integration-user")
	}

	// Expired token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "integration-user",
		"iss": "sire",
		"aud": jwt.ClaimStrings{"smtpd"},
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})
	expiredStr, _ := expiredToken.SignedString(secret)
	_, err = jwtAuth.AuthenticateToken(expiredStr)
	if err == nil {
		t.Error("expected error for expired token")
	}

	// Wrong secret
	wrongToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "integration-user",
		"iss": "sire",
		"aud": jwt.ClaimStrings{"smtpd"},
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	wrongStr, _ := wrongToken.SignedString([]byte("wrong-secret"))
	_, err = jwtAuth.AuthenticateToken(wrongStr)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}
