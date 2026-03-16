package queue

import (
	// "container/heap" // Unused in test file
	"context"
	"errors"

	// "sync"
	"testing"
	"time"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/pkg/message"

	// "github.com/sirerun/smtpd/internal/metrics" // Unused in test file
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueueEnqueueDequeue(t *testing.T) {
	logger := logging.New(logging.DefaultConfig())
	q := NewQueue(10, logger) // Pass buffer size and logger
	defer q.Close()

	msg := message.NewMessage("sender@example.com", []string{"recipient@example.com"}, []byte("Test message")) // Use []byte
	err := q.Enqueue(context.Background(),msg)
	require.NoError(t, err)

	// Use context for Dequeue
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	dequeued, err := q.Dequeue(ctx)
	require.NoError(t, err)
	require.NotNil(t, dequeued)
	assert.Equal(t, msg.ID, dequeued.ID)
}

func TestQueueRequeueAndSchedule(t *testing.T) {
	logger := logging.New(logging.DefaultConfig())
	q := NewQueue(10, logger)
	defer q.Close()

	// Message for future attempt
	retryTime := time.Now().Add(100 * time.Millisecond)
	msg1 := message.NewMessage("retry@example.com", []string{"rcpt@test.net"}, []byte("Retry me"))
	msg1.NextAttemptAt = retryTime
	msg1.RetryCount = 1
	err := q.Requeue(context.Background(),msg1)
	require.NoError(t, err)

	// Message for immediate attempt (should be dequeued first)
	msg2 := message.NewMessage("now@example.com", []string{"rcpt@test.net"}, []byte("Process now"))
	err = q.Enqueue(context.Background(),msg2)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// 1. Dequeue immediate message
	dequeued1, err1 := q.Dequeue(ctx)
	require.NoError(t, err1)
	require.NotNil(t, dequeued1)
	assert.Equal(t, msg2.ID, dequeued1.ID)

	// 2. Wait for retry message to become ready
	dequeued2, err2 := q.Dequeue(ctx)
	require.NoError(t, err2)
	require.NotNil(t, dequeued2)
	assert.Equal(t, msg1.ID, dequeued2.ID)
}

func TestQueueClose(t *testing.T) {
	logger := logging.New(logging.DefaultConfig())
	q := NewQueue(10, logger)

	msg := message.NewMessage("sender@example.com", []string{"rcpt@test.net"}, []byte("Test Close"))
	err := q.Enqueue(context.Background(),msg)
	require.NoError(t, err)

	// Drain the already-enqueued message before closing
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer drainCancel()
	_, err = q.Dequeue(drainCtx)
	require.NoError(t, err)

	q.Close()

	// Further enqueues should fail
	err = q.Enqueue(context.Background(), msg)
	assert.Error(t, err, "Enqueue after Close should return an error")

	// Verify the error is specifically ErrQueueClosed
	if err != nil {
		assert.Equal(t, ErrQueueClosed.Error(), err.Error(), "Expected specific error message")
	}

	// Dequeue on closed queue should fail
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = q.Dequeue(ctx)
	assert.Error(t, err, "Dequeue after Close should return an error")

	// The error should either be context.DeadlineExceeded or ErrQueueClosed
	assert.Condition(t, func() bool {
		return errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, ErrQueueClosed) ||
			(err != nil && err.Error() == ErrQueueClosed.Error())
	}, "Expected either deadline exceeded or queue closed error")
}

// Note: Removed TestQueueDelivery and TestQueueConcurrent as they
// depended on the old Start/StopDelivery mechanism which is now handled
// by the separate QueueProcessor.
