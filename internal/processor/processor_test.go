package processor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirerun/smtpd/internal/errors"
	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/internal/message"
	"github.com/sirerun/smtpd/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockQueue simulates the Queuer interface.
type mockQueue struct {
	dequeueChan chan *message.Message
	requeueChan chan *message.Message
	mu          sync.Mutex
	closed      bool
}

func newMockQueue(bufferSize int) *mockQueue {
	return &mockQueue{
		dequeueChan: make(chan *message.Message, bufferSize),
		requeueChan: make(chan *message.Message, bufferSize),
	}
}

func (mq *mockQueue) Enqueue(ctx context.Context, msg *message.Message) error {
	mq.mu.Lock()
	if mq.closed {
		mq.mu.Unlock()
		return errors.NewControlledStop(context.Canceled)
	}
	mq.mu.Unlock()
	select {
	case mq.dequeueChan <- msg:
		return nil
	case <-time.After(100 * time.Millisecond):
		return fmt.Errorf("mock Enqueue timed out")
	}
}

func (mq *mockQueue) Requeue(ctx context.Context, msg *message.Message) error {
	mq.mu.Lock()
	if mq.closed {
		mq.mu.Unlock()
		return errors.NewControlledStop(context.Canceled)
	}
	mq.mu.Unlock()
	select {
	case mq.requeueChan <- msg:
		return nil
	case <-time.After(100 * time.Millisecond):
		return fmt.Errorf("mock Requeue timed out")
	}
}

func (mq *mockQueue) Dequeue(ctx context.Context) (*message.Message, error) {
	select {
	case msg, ok := <-mq.dequeueChan:
		if !ok {
			return nil, errors.NewControlledStop(context.Canceled)
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (mq *mockQueue) Close() {
	mq.mu.Lock()
	defer mq.mu.Unlock()
	if !mq.closed {
		close(mq.dequeueChan)
		close(mq.requeueChan)
		mq.closed = true
	}
}

// mockDeliverer simulates the Deliverer interface.
type mockDeliverer struct {
	deliverFunc func(context.Context, *message.Message) error
	mu          sync.Mutex
	calls       map[string]int // Store call count per message ID
}

func newMockDeliverer() *mockDeliverer {
	return &mockDeliverer{
		calls: make(map[string]int),
	}
}

func (md *mockDeliverer) Deliver(ctx context.Context, msg *message.Message) error {
	md.mu.Lock()
	md.calls[msg.ID]++ // Increment call count for this message ID
	md.mu.Unlock()
	if md.deliverFunc != nil {
		return md.deliverFunc(ctx, msg)
	}
	// Default success
	return nil
}

func (md *mockDeliverer) GetCallCount(msgID string) int {
	md.mu.Lock()
	defer md.mu.Unlock()
	return md.calls[msgID]
}

// --- Helper ---
var testLogger = logging.New(logging.DefaultConfig()) // Reduce log noise for tests
var testMetrics = metrics.NewMetrics()

// --- Test Suite ---

func TestQueueProcessor_Run_SingleWorker_SimpleCases(t *testing.T) {
	// Test Success
	mqSuccess := newMockQueue(1)
	mdSuccess := newMockDeliverer()
	pSuccess := NewQueueProcessor(mqSuccess, mdSuccess, 1, testLogger, testMetrics)
	pSuccess.Start()
	msgSuccess := &message.Message{ID: "success-1", From: "a@a.com", To: []string{"b@b.com"}}
	mdSuccess.deliverFunc = func(ctx context.Context, m *message.Message) error {
		return nil
	}
	require.NoError(t, mqSuccess.Enqueue(context.Background(), msgSuccess))
	time.Sleep(50 * time.Millisecond) // Allow processing
	pSuccess.Stop()
	mqSuccess.Close()
	assert.Equal(t, 1, mdSuccess.GetCallCount("success-1"))
	assert.Len(t, mqSuccess.requeueChan, 0, "Success case should not requeue")

	// Test TempFail -> Requeue
	mqRetry := newMockQueue(1)
	mdRetry := newMockDeliverer()
	pRetry := NewQueueProcessor(mqRetry, mdRetry, 1, testLogger, testMetrics)
	pRetry.Start()
	msgRetry := &message.Message{ID: "retry-1", From: "c@c.com", To: []string{"d@temp.com"}}
	mdRetry.deliverFunc = func(ctx context.Context, m *message.Message) error {
		return fmt.Errorf("temporary failure")
	}
	require.NoError(t, mqRetry.Enqueue(context.Background(), msgRetry))
	time.Sleep(50 * time.Millisecond)
	pRetry.Stop()
	mqRetry.Close()
	assert.Equal(t, 1, mdRetry.GetCallCount("retry-1"))
	require.Len(t, mqRetry.requeueChan, 1, "TempFail case should requeue")
	select {
	case requeued := <-mqRetry.requeueChan:
		assert.Equal(t, "retry-1", requeued.ID)
		assert.Equal(t, 1, requeued.RetryCount)
		assert.True(t, requeued.NextAttemptAt.After(time.Now()))
	default:
		t.Fatal("Expected message in requeue channel")
	}

	// Test PermFail -> Bounce (No Requeue)
	mqPerm := newMockQueue(1)
	mdPerm := newMockDeliverer()
	pPerm := NewQueueProcessor(mqPerm, mdPerm, 1, testLogger, testMetrics)
	pPerm.Start()
	msgPerm := &message.Message{ID: "perm-1", From: "e@e.com", To: []string{"f@perm.com"}}
	mdPerm.deliverFunc = func(ctx context.Context, m *message.Message) error {
		return fmt.Errorf("permanent failure")
	}
	require.NoError(t, mqPerm.Enqueue(context.Background(), msgPerm))
	time.Sleep(50 * time.Millisecond)
	pPerm.Stop()
	mqPerm.Close()
	assert.Equal(t, 1, mdPerm.GetCallCount("perm-1"))
	assert.Len(t, mqPerm.requeueChan, 0, "PermFail case should not requeue")
	// TODO: Verify bounce logs when implemented
}

func TestQueueProcessor_ParallelRun_Counts(t *testing.T) {
	mq := newMockQueue(50) // Larger buffer
	md := newMockDeliverer()
	numWorkers := 4
	numMessages := 30 // Increase message count for better concurrency test

	p := NewQueueProcessor(mq, md, numWorkers, testLogger, testMetrics)
	p.Start()

	var wg sync.WaitGroup
	wg.Add(numMessages)

	expectedRequeues := make(map[string]bool)
	expectedPermFails := make(map[string]bool)
	var mu sync.Mutex

	md.deliverFunc = func(ctx context.Context, m *message.Message) error {
		defer wg.Done()
		if strings.HasPrefix(m.ID, "temp-") {
			mu.Lock()
			expectedRequeues[m.ID] = true
			mu.Unlock()
			return fmt.Errorf("temporary failure")
		} else if strings.HasPrefix(m.ID, "perm-") {
			mu.Lock()
			expectedPermFails[m.ID] = true
			mu.Unlock()
			return fmt.Errorf("permanent failure")
		} else {
			return nil
		}
	}

	for i := 0; i < numMessages; i++ {
		var msg *message.Message
		var id string
		if i%3 == 0 {
			id = fmt.Sprintf("temp-%d", i)
			msg = &message.Message{ID: id, From: "temp@test.com", To: []string{"rcpt@temp.com"}}
		} else if i%3 == 1 {
			id = fmt.Sprintf("perm-%d", i)
			msg = &message.Message{ID: id, From: "perm@test.com", To: []string{"rcpt@perm.com"}}
		} else {
			id = fmt.Sprintf("good-%d", i)
			msg = &message.Message{ID: id, From: "good@test.com", To: []string{"rcpt@success.com"}}
		}
		err := mq.Enqueue(context.Background(), msg)
		require.NoError(t, err, "Failed to enqueue message %s", id)
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond) // Longer wait for requeues with more messages/workers
	p.Stop()
	mq.Close()

	// Verify call counts
	mu.Lock()
	callCounts := md.calls
	mu.Unlock()
	assert.Len(t, callCounts, numMessages, "Incorrect total number of Deliver calls")
	for i := 0; i < numMessages; i++ {
		var id string
		if i%3 == 0 {
			id = fmt.Sprintf("temp-%d", i)
		} else if i%3 == 1 {
			id = fmt.Sprintf("perm-%d", i)
		} else {
			id = fmt.Sprintf("good-%d", i)
		}
		assert.Equal(t, 1, callCounts[id], "Expected 1 call for message %s", id)
	}

	// Verify requeues
	actualRequeues := make(map[string]bool)
	closeLoop := false
	for !closeLoop {
		select {
		case requeuedMsg, ok := <-mq.requeueChan:
			if !ok {
				closeLoop = true
				break
			}
			if requeuedMsg != nil {
				actualRequeues[requeuedMsg.ID] = true
			}
		case <-time.After(100 * time.Millisecond):
			closeLoop = true
		}
	}

	mu.Lock()
	assert.Equal(t, len(expectedRequeues), len(actualRequeues), "Number of requeued messages mismatch")
	for id := range expectedRequeues {
		assert.True(t, actualRequeues[id], "Message %s was expected to be requeued but wasn't", id)
	}
	mu.Unlock()
}
