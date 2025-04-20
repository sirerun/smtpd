package auth

import (
	"testing"
)

func TestUserStore(t *testing.T) {
	store := NewStore()

	// Test adding a user
	if err := store.AddUser("testuser", "password123"); err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	// Test adding duplicate user
	if err := store.AddUser("testuser", "password123"); err == nil {
		t.Error("Expected error when adding duplicate user")
	}

	// Test authentication
	tests := []struct {
		username string
		password string
		wantErr  error
	}{
		{"testuser", "password123", nil},
		{"testuser", "wrongpass", ErrInvalidCredentials},
		{"nonexistent", "password123", ErrUserNotFound},
	}

	for _, tt := range tests {
		_, err := store.Authenticate(tt.username, tt.password)
		if err != tt.wantErr {
			t.Errorf("Authenticate(%q, %q) = %v, want %v", tt.username, tt.password, err, tt.wantErr)
		}
	}
}
