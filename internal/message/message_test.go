package message

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewMessage(t *testing.T) {
	from := "sender@example.com"
	to := []string{"recipient@example.net"}
	data := []byte("Subject: Test\r\n\r\nHello.")
	now := time.Now()

	msg := NewMessage(from, to, data)

	assert.NotEmpty(t, msg.ID)
	assert.Equal(t, from, msg.From)
	assert.Equal(t, to, msg.To)
	assert.Equal(t, data, msg.Data)
	assert.WithinDuration(t, now, msg.CreatedAt, time.Second)
	assert.Equal(t, 0, msg.RetryCount)
	assert.WithinDuration(t, now, msg.NextAttemptAt, time.Second)
}
