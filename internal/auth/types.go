package auth

// AuthStore defines the interface for authentication stores
type AuthStore interface {
	// Authenticate checks the username and password.
	// Returns true if authentication is successful, false otherwise.
	Authenticate(username, password string) (bool, error)

	// IsEnabled checks if authentication is globally enabled for this store.
	IsEnabled() bool

	// SupportedMechanisms returns a list of supported SASL mechanisms (e.g., "PLAIN", "LOGIN")
	SupportedMechanisms() []string

	// AddUser adds a new user to the store
	AddUser(username, password string) error
}

// JWTValidator defines the interface for JWT token validation.
type JWTValidator interface {
	// AuthenticateToken validates a JWT token and returns the subject (username).
	AuthenticateToken(token string) (string, error)
}
