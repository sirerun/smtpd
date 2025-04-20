package message

import (
	"time"
)

// Message represents an email message
type Message struct {
	ID            string
	From          string
	To            []string
	Data          []byte
	CreatedAt     time.Time
	RetryCount    int
	NextAttemptAt time.Time
}

// NewMessage creates a new Message instance
func NewMessage(from string, to []string, data []byte) *Message {
	now := time.Now()
	return &Message{
		ID:            time.Now().Format("20060102150405.000000"),
		From:          from,
		To:            to,
		Data:          data,
		CreatedAt:     now,
		RetryCount:    0,
		NextAttemptAt: now,
	}
}
