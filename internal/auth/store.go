package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// User represents a user in the system
type User struct {
	Username string
	Password []byte // Hashed password
	Salt     []byte
}

// Store is an in-memory user store
type Store struct {
	users   map[string]*User
	mu      sync.RWMutex
	Enabled bool // Track if auth is enabled for this store
	// Add supported mechanisms if they vary per store instance
	// mechanisms []string
}

// NewStore creates a new user store
func NewStore() *Store {
	return &Store{
		users:   make(map[string]*User),
		Enabled: true, // Default to enabled when created? Or rely on config?
	}
}

// AddUser adds a new user to the store
func (s *Store) AddUser(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return errors.New("user already exists")
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Hash password with salt
	hashedPassword := hashPassword(password, salt)

	user := &User{
		Username: username,
		Password: hashedPassword,
		Salt:     salt,
	}

	s.users[username] = user
	return nil
}

// Authenticate verifies user credentials
// Returns true if successful, false otherwise, and an error for system issues.
func (s *Store) Authenticate(username, password string) (bool, error) {
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		return false, ErrUserNotFound // Return false for user not found
	}

	// Hash provided password with stored salt
	hashedPassword := hashPassword(password, user.Salt)

	// Compare hashes in constant time
	if subtle.ConstantTimeCompare(hashedPassword, user.Password) != 1 {
		return false, ErrInvalidCredentials // Return false for invalid credentials
	}

	return true, nil // Return true on success
}

// IsEnabled returns true if the authentication store is configured as enabled.
func (s *Store) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Enabled
}

// SupportedMechanisms returns the list of SASL mechanisms supported by this store.
func (s *Store) SupportedMechanisms() []string {
	// For this basic store, assume PLAIN and LOGIN.
	// This could be made configurable if needed.
	return []string{"PLAIN", "LOGIN"}
}

// hashPassword hashes a password with a salt
func hashPassword(password string, salt []byte) []byte {
	// In a real implementation, use a proper password hashing function like bcrypt
	// This is a simplified version for demonstration
	combined := append([]byte(password), salt...)
	return combined
}
