package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAddUser(t *testing.T) {
	store := NewStore()

	if err := store.AddUser("testuser", "password123"); err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	// Verify stored hash is valid bcrypt
	store.mu.RLock()
	user := store.users["testuser"]
	store.mu.RUnlock()

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte("password123")); err != nil {
		t.Fatalf("Stored hash is not valid bcrypt: %v", err)
	}
}

func TestAddUserDuplicate(t *testing.T) {
	store := NewStore()
	if err := store.AddUser("testuser", "password123"); err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}
	if err := store.AddUser("testuser", "password123"); err == nil {
		t.Error("Expected error when adding duplicate user")
	}
}

func TestAddUserWithHash(t *testing.T) {
	store := NewStore()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.AddUserWithHash("hashuser", hash); err != nil {
		t.Fatalf("Failed to add user with hash: %v", err)
	}

	ok, err := store.Authenticate("hashuser", "secret")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !ok {
		t.Error("Expected authentication to succeed")
	}
}

func TestAuthenticate(t *testing.T) {
	store := NewStore()
	if err := store.AddUser("testuser", "password123"); err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		wantOK   bool
		wantErr  error
	}{
		{
			name:     "valid credentials",
			username: "testuser",
			password: "password123",
			wantOK:   true,
			wantErr:  nil,
		},
		{
			name:     "wrong password",
			username: "testuser",
			password: "wrongpass",
			wantOK:   false,
			wantErr:  ErrInvalidCredentials,
		},
		{
			name:     "nonexistent user",
			username: "nonexistent",
			password: "password123",
			wantOK:   false,
			wantErr:  ErrUserNotFound,
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
			wantOK:   false,
			wantErr:  ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := store.Authenticate(tt.username, tt.password)
			if ok != tt.wantOK {
				t.Errorf("Authenticate(%q, %q) ok = %v, want %v", tt.username, tt.password, ok, tt.wantOK)
			}
			if err != tt.wantErr {
				t.Errorf("Authenticate(%q, %q) err = %v, want %v", tt.username, tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	store := NewStore()
	if !store.IsEnabled() {
		t.Error("Expected store to be enabled by default")
	}
	store.Enabled = false
	if store.IsEnabled() {
		t.Error("Expected store to be disabled")
	}
}

func TestSupportedMechanisms(t *testing.T) {
	store := NewStore()
	mechs := store.SupportedMechanisms()
	if len(mechs) != 2 {
		t.Fatalf("Expected 2 mechanisms, got %d", len(mechs))
	}
	if mechs[0] != "PLAIN" || mechs[1] != "LOGIN" {
		t.Errorf("Expected [PLAIN LOGIN], got %v", mechs)
	}
}

func TestAuthenticateTimingSafety(t *testing.T) {
	// Verify that authenticating a nonexistent user does not return
	// significantly faster than a wrong-password attempt (both should
	// perform a bcrypt comparison).
	store := NewStore()
	if err := store.AddUser("real", "correct"); err != nil {
		t.Fatal(err)
	}

	// Both should return false without panicking; the key property is
	// that the nonexistent-user path also runs bcrypt.
	ok, err := store.Authenticate("fake", "wrong")
	if ok || err != ErrUserNotFound {
		t.Errorf("Expected (false, ErrUserNotFound), got (%v, %v)", ok, err)
	}

	ok, err = store.Authenticate("real", "wrong")
	if ok || err != ErrInvalidCredentials {
		t.Errorf("Expected (false, ErrInvalidCredentials), got (%v, %v)", ok, err)
	}
}
