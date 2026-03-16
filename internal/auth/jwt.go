package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenInvalid  = errors.New("token invalid")
	ErrInvalidIssuer = errors.New("invalid issuer")
	ErrInvalidAud    = errors.New("invalid audience")
)

// JWTAuthenticator validates Sire JWT tokens for SMTP authentication.
type JWTAuthenticator struct {
	mu       sync.RWMutex
	keyFunc  jwt.Keyfunc
	issuer   string
	audience string
}

// NewJWTAuthenticator creates a new JWT authenticator.
// keyFunc is called to resolve the signing key for token verification.
// issuer and audience are validated against the token claims.
func NewJWTAuthenticator(keyFunc jwt.Keyfunc, issuer, audience string) *JWTAuthenticator {
	return &JWTAuthenticator{
		keyFunc:  keyFunc,
		issuer:   issuer,
		audience: audience,
	}
}

// NewJWTAuthenticatorHMAC creates a JWT authenticator using a shared HMAC secret.
func NewJWTAuthenticatorHMAC(secret []byte, issuer, audience string) *JWTAuthenticator {
	return NewJWTAuthenticator(func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	}, issuer, audience)
}

// AuthenticateToken validates a JWT token string.
// Returns the subject (username) from the token on success.
func (j *JWTAuthenticator) AuthenticateToken(tokenString string) (string, error) {
	j.mu.RLock()
	keyFunc := j.keyFunc
	issuer := j.issuer
	audience := j.audience
	j.mu.RUnlock()

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.Parse(tokenString, keyFunc)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", ErrTokenInvalid
	}

	// Validate issuer using timing-safe comparison
	iss, err := claims.GetIssuer()
	if err != nil || subtle.ConstantTimeCompare([]byte(iss), []byte(issuer)) != 1 {
		return "", ErrInvalidIssuer
	}

	// Validate audience
	aud, err := claims.GetAudience()
	if err != nil {
		return "", ErrInvalidAud
	}
	audMatch := false
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(audience)) == 1 {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return "", ErrInvalidAud
	}

	// Validate expiry (jwt library checks exp, but be explicit)
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", ErrTokenExpired
	}
	if time.Now().After(exp.Time) {
		return "", ErrTokenExpired
	}

	// Extract subject (username)
	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return "", fmt.Errorf("%w: missing subject claim", ErrTokenInvalid)
	}

	return sub, nil
}
