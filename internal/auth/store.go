package auth

import (
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// User represents a user in the system
type User struct {
	Username     string
	PasswordHash []byte // bcrypt hash
}

// Store is an in-memory user store
type Store struct {
	users   map[string]*User
	mu      sync.RWMutex
	Enabled bool
}

// NewStore creates a new user store
func NewStore() *Store {
	return &Store{
		users:   make(map[string]*User),
		Enabled: true,
	}
}

// AddUser adds a new user to the store with a bcrypt-hashed password.
func (s *Store) AddUser(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return errors.New("user already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.users[username] = &User{
		Username:     username,
		PasswordHash: hash,
	}
	return nil
}

// AddUserWithHash adds a user with a pre-computed bcrypt hash.
func (s *Store) AddUserWithHash(username string, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return errors.New("user already exists")
	}

	s.users[username] = &User{
		Username:     username,
		PasswordHash: hash,
	}
	return nil
}

// Authenticate verifies user credentials using bcrypt.
// To prevent timing attacks on user enumeration, a dummy bcrypt compare
// is performed when the user is not found.
func (s *Store) Authenticate(username, password string) (bool, error) {
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()

	if !exists {
		// Perform a dummy bcrypt comparison to prevent timing-based user enumeration.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$dummyhashtopreventtimingleak000000000000000000000"),
			[]byte(password),
		)
		return false, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return false, ErrInvalidCredentials
	}

	return true, nil
}

// IsEnabled returns true if the authentication store is configured as enabled.
func (s *Store) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Enabled
}

// SupportedMechanisms returns the list of SASL mechanisms supported by this store.
func (s *Store) SupportedMechanisms() []string {
	return []string{"PLAIN", "LOGIN"}
}
