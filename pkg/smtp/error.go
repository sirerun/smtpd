package smtp

import "fmt"

// Error represents an SMTP error with a code and message.
// It provides a standardized way to handle SMTP protocol errors
// with support for both basic and enhanced status codes.
type Error interface {
	error
	// Code returns the 3-digit SMTP reply code (e.g., 550)
	Code() int
	// Message returns the full SMTP reply message (including code and enhanced code)
	Message() string
	// EnhCode returns the enhanced status code (e.g., "5.7.1") or empty string if not set
	EnhCode() string
}

// smtpError implements the Error interface.
type smtpError struct {
	code    int
	enhCode string // Optional enhanced status code (e.g., 5.1.1)
	message string
}

// NewError creates a new SMTP error.
// code: 3-digit SMTP reply code (e.g., 550)
// enhCode: Optional enhanced status code (e.g., "5.1.1")
// message: Human-readable error message
func NewError(code int, enhCode string, message string) Error {
	return &smtpError{
		code:    code,
		enhCode: enhCode,
		message: message,
	}
}

func (e *smtpError) Error() string {
	// Format according to RFC 5321 section 4.2.1
	// Example: 550 5.1.1 User unknown
	// If no enhanced code, just: 550 User unknown
	if e.enhCode != "" {
		return fmt.Sprintf("%d %s %s", e.code, e.enhCode, e.message)
	}
	return fmt.Sprintf("%d %s", e.code, e.message)
}

func (e *smtpError) Code() int {
	return e.code
}

// Message returns the full reply line, including code(s).
func (e *smtpError) Message() string {
	return e.Error()
}

// EnhCode returns the enhanced status code (e.g., "5.7.1") or "" if not set.
func (e *smtpError) EnhCode() string {
	return e.enhCode
}
