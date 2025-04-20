package queue

import (
	"container/heap"
	"context"
	"sync"
	"time"

	"github.com/mailtive/smtpd/internal/errors"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/message"
	"github.com/mailtive/smtpd/internal/metrics"
)

// --- Retry Heap Implementation ---

// retryItem stores a message and its next attempt time in the heap.
type retryItem struct {
	msg      *message.Message
	priority time.Time // The NextAttemptAt time, used for heap ordering
	index    int       // Index in the heap, needed for heap.Interface
}

// retryHeap implements heap.Interface for retryItem, ordered by priority (NextAttemptAt).
// This is a min-heap.
type retryHeap []*retryItem

func (rh retryHeap) Len() int { return len(rh) }

func (rh retryHeap) Less(i, j int) bool {
	// Min-heap based on time
	return rh[i].priority.Before(rh[j].priority)
}

func (rh retryHeap) Swap(i, j int) {
	rh[i], rh[j] = rh[j], rh[i]
	rh[i].index = i
	rh[j].index = j
}

func (rh *retryHeap) Push(x interface{}) {
	n := len(*rh)
	item := x.(*retryItem)
	item.index = n
	*rh = append(*rh, item)
}

func (rh *retryHeap) Pop() interface{} {
	old := *rh
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*rh = old[0 : n-1]
	return item
}

// peek returns the next item without removing it.
func (rh retryHeap) peek() *retryItem {
	if len(rh) == 0 {
		return nil
	}
	return rh[0]
}

// --- Queue Implementation ---

// Queue represents a message queue with retry logic.
type Queue struct {
	mu          sync.Mutex
	readyChan   chan *message.Message
	retryHeap   retryHeap
	retrySignal chan struct{}
	stopChan    chan struct{}
	stopWg      sync.WaitGroup
	closed      bool
	logger      *logging.Logger
}

// NewQueue creates a new message queue with retry handling.
func NewQueue(bufferSize int, logger *logging.Logger) *Queue {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
	}
	q := &Queue{
		readyChan:   make(chan *message.Message, bufferSize),
		retryHeap:   make(retryHeap, 0),
		retrySignal: make(chan struct{}, 1),
		stopChan:    make(chan struct{}),
		logger:      logger,
	}
	heap.Init(&q.retryHeap)
	q.stopWg.Add(1)
	go q.scheduleRetryMessages()
	q.logger.Info("Queue initialized", "buffer_size", bufferSize)
	return q
}

// Enqueue adds a message for immediate processing.
func (q *Queue) Enqueue(msg *message.Message) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		q.logger.Warn("Attempted to enqueue to closed queue", "msg_id", msg.ID)
		return errors.NewControlledStop(context.Canceled)
	}
	if msg.NextAttemptAt.IsZero() {
		msg.NextAttemptAt = time.Now()
	}
	q.logger.Debug("Enqueueing message for immediate processing", "msg_id", msg.ID)
	q.mu.Unlock()

	select {
	case q.readyChan <- msg:
		metrics.QueueSizeReady.Inc()
		return nil
	case <-q.stopChan:
		q.logger.Warn("Enqueue failed, queue is stopping", "msg_id", msg.ID)
		return errors.NewControlledStop(context.Canceled)
	}
}

// Requeue adds a message back for a later retry attempt.
func (q *Queue) Requeue(msg *message.Message) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		q.logger.Warn("Attempted to requeue to closed queue", "msg_id", msg.ID)
		return errors.NewControlledStop(context.Canceled)
	}

	if msg.NextAttemptAt.IsZero() || msg.NextAttemptAt.Before(time.Now()) {
		q.logger.Error("Requeue called with invalid or past NextAttemptAt", "msg_id", msg.ID, "attempt_at", msg.NextAttemptAt)
		msg.NextAttemptAt = time.Now().Add(5 * time.Second)
	}

	q.logger.Debug("Requeueing message", "msg_id", msg.ID, "next_attempt_at", msg.NextAttemptAt, "retry_count", msg.RetryCount)
	heap.Push(&q.retryHeap, &retryItem{msg: msg, priority: msg.NextAttemptAt})
	metrics.QueueSizeRetry.Inc()

	select {
	case q.retrySignal <- struct{}{}:
	default:
	}
	return nil
}

// Dequeue removes and returns the next message ready for processing.
func (q *Queue) Dequeue(ctx context.Context) (*message.Message, error) {
	select {
	case msg, ok := <-q.readyChan:
		if !ok {
			return nil, errors.NewControlledStop(context.Canceled)
		}
		metrics.QueueSizeReady.Dec()
		return msg, nil
	case <-ctx.Done():
		return nil, errors.NewControlledStop(ctx.Err())
	case <-q.stopChan:
		return nil, errors.NewControlledStop(context.Canceled)
	}
}

// scheduleRetryMessages runs in the background.
func (q *Queue) scheduleRetryMessages() {
	defer q.stopWg.Done()
	schedulerLogger := q.logger.WithComponent("queue.scheduler")
	schedulerLogger.Info("Retry scheduler started")

	heapCheckTimer := time.NewTimer(time.Hour)
	defer heapCheckTimer.Stop()

	metricsUpdateTicker := time.NewTicker(30 * time.Second)
	defer metricsUpdateTicker.Stop()

	for {
		nextAttemptIn := q.getNextRetryDelay(schedulerLogger)

		if !heapCheckTimer.Stop() {
			select {
			case <-heapCheckTimer.C:
			default:
			}
		}
		heapCheckTimer.Reset(nextAttemptIn)

		select {
		case <-heapCheckTimer.C:
			q.promoteReadyMessages(schedulerLogger)
		case <-metricsUpdateTicker.C:
			metrics.QueueSizeReady.Set(float64(len(q.readyChan)))
		case <-q.retrySignal:
			continue
		case <-q.stopChan:
			schedulerLogger.Info("Stop signal received, scheduler exiting")
			return
		}
	}
}

// getNextRetryDelay calculates the duration until the next message is due and updates metrics.
func (q *Queue) getNextRetryDelay(logger *logging.Logger) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()

	retryQueueSize := len(q.retryHeap)
	metrics.QueueSizeRetry.Set(float64(retryQueueSize))

	if retryQueueSize == 0 {
		return time.Hour
	}

	nextItem := q.retryHeap[0]
	now := time.Now()
	if nextItem.priority.After(now) {
		delay := nextItem.priority.Sub(now)
		return delay
	} else {
		return 0
	}
}

// promoteReadyMessages moves ready messages from heap to ready channel.
func (q *Queue) promoteReadyMessages(logger *logging.Logger) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	promotedCount := 0
	for len(q.retryHeap) > 0 {
		if q.retryHeap[0].priority.After(now) {
			break
		}

		item := heap.Pop(&q.retryHeap).(*retryItem)
		metrics.QueueSizeRetry.Dec()

		select {
		case q.readyChan <- item.msg:
			promotedCount++
		case <-q.stopChan:
			logger.Warn("Stop signal during promotion, requeueing message internally", "msg_id", item.msg.ID)
			heap.Push(&q.retryHeap, item)
			return
		default:
			logger.Warn("Ready channel full during promotion, requeueing message internally", "msg_id", item.msg.ID)
			heap.Push(&q.retryHeap, item)
			select {
			case q.retrySignal <- struct{}{}:
			default:
			}
			return
		}
	}
	if promotedCount > 0 {
		logger.Debug("Messages promoted from retry heap", "count", promotedCount)
	}
}

// Close shuts down the queue gracefully.
func (q *Queue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.logger.Info("Closing queue...")
	q.closed = true
	close(q.stopChan)
	q.mu.Unlock()

	q.stopWg.Wait()
	q.logger.Info("Queue scheduler stopped.")

	q.mu.Lock()
	close(q.readyChan)
	q.retryHeap = nil
	q.logger.Info("Queue closed", "remaining_retry_items", len(q.retryHeap))
	q.mu.Unlock()
}

// Len returns the number of messages waiting in the retry heap.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.retryHeap)
}

// ReadyLen returns the number of messages currently buffered in the ready channel.
func (q *Queue) ReadyLen() int {
	return len(q.readyChan)
}
