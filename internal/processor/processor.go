package processor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sirerun/smtpd/internal/logging"
	"github.com/sirerun/smtpd/pkg/message"
	"github.com/sirerun/smtpd/internal/metrics"
)

// Define retry parameters
const (
	MaxRetries     = 5
	BaseRetryDelay = 1 * time.Minute
	MaxRetryDelay  = 30 * time.Minute
)

// Queuer represents the interface for message queuing operations needed by the processor.
type Queuer interface {
	Dequeue(ctx context.Context) (*message.Message, error) // Blocking dequeue with context for cancellation
	Enqueue(ctx context.Context, msg *message.Message) error // Enqueue for immediate processing
	Requeue(ctx context.Context, msg *message.Message) error // Requeue for later retry
}

// Deliverer represents the interface for message delivery operations.
type Deliverer interface {
	Deliver(ctx context.Context, msg *message.Message) error
}

// QueueProcessor handles message processing from the queue.
type QueueProcessor struct {
	queue     Queuer
	deliverer Deliverer
	workers   []*worker
	stopChan  chan struct{}
	stopWg    sync.WaitGroup
	logger    *logging.Logger
	metrics   *metrics.Metrics
}

// NewQueueProcessor creates a new queue processor.
// numWorkers specifies how many concurrent delivery goroutines to run.
func NewQueueProcessor(
	q Queuer,
	d Deliverer,
	numWorkers int,
	logger *logging.Logger,
	m *metrics.Metrics,
) *QueueProcessor {
	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
	}
	if m == nil {
		m = metrics.NewMetrics()
	}
	p := &QueueProcessor{
		queue:     q,
		deliverer: d,
		workers:   make([]*worker, numWorkers),
		stopChan:  make(chan struct{}),
		logger:    logger,
		metrics:   m,
	}
	for i := 0; i < numWorkers; i++ {
		p.workers[i] = newWorker(i, p)
	}
	p.logger.Info("Queue processor initialized", "num_workers", numWorkers)
	return p
}

// Start begins processing messages from the queue using multiple workers.
func (p *QueueProcessor) Start() {
	p.logger.Info("Starting queue processor", "workers", len(p.workers))
	ctx, cancel := context.WithCancel(context.Background())

	// Start a goroutine to cancel the context when stopChan is closed
	go func() {
		<-p.stopChan
		p.logger.Info("Stop signal received, cancelling worker context")
		cancel()
	}()

	for _, worker := range p.workers {
		p.stopWg.Add(1)
		go worker.process(ctx)
	}
	p.logger.Info("Workers started")
}

// Stop signals the processor to stop processing messages and waits for all workers to finish.
func (p *QueueProcessor) Stop() {
	p.logger.Info("Stopping queue processor...")
	close(p.stopChan) // Close channel to signal stop (triggers context cancellation)
	p.stopWg.Wait()   // Wait for all worker goroutines to exit
	p.logger.Info("Queue processor stopped")
}

// worker represents a single processing worker.
type worker struct {
	id        int
	processor *QueueProcessor
	logger    *logging.Logger
}

func newWorker(id int, p *QueueProcessor) *worker {
	return &worker{
		id:        id,
		processor: p,
		logger:    p.logger.WithComponent("processor.worker"),
	}
}

// process is the main processing loop for a single worker goroutine.
func (w *worker) process(ctx context.Context) {
	defer w.processor.stopWg.Done()
	w.logger.Info("Worker started", "worker_id", w.id)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Worker exiting due to context cancellation", "worker_id", w.id)
			return
		default:
			// Continue to dequeue with a timeout context to ensure we can respond quickly to cancellation
			dequeueCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			msg, err := w.processor.queue.Dequeue(dequeueCtx)
			cancel()

			// Handle context cancellation from parent
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				if ctx.Err() != nil {
					// Parent context is done, exit completely
					w.logger.Info("Worker detected parent context cancellation during dequeue", "worker_id", w.id)
					return
				}
				// Only the local timeout expired, continue loop to check parent context again
				continue
			}

			if err != nil {
				// Log other unexpected errors
				w.logger.Error("Worker received error during Dequeue", "worker_id", w.id, "error", err)
				// Sleep briefly to avoid hammering the queue in case of persistent errors
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if msg == nil {
				// Should not happen if error is nil, but check defensively
				continue
			}

			msgLogger := w.logger.With("msg_id", msg.ID, "mail_from", msg.From, "worker_id", w.id)

			// Check if it's time to attempt delivery
			if time.Now().Before(msg.NextAttemptAt) {
				if requeueErr := w.processor.queue.Requeue(ctx, msg); requeueErr != nil {
					msgLogger.Error("CRITICAL - Failed to requeue sleepy message", "error", requeueErr)
				}
				continue // Get another message
			}

			msgLogger.Info("Processing message", "attempt", msg.RetryCount+1)

			// Use a separate context with timeout for delivery to ensure we don't block shutdown
			deliveryCtx, deliveryCancel := context.WithTimeout(ctx, 2*time.Minute)
			err = w.processor.deliverer.Deliver(deliveryCtx, msg)
			deliveryCancel()

			if err != nil {
				// Check for context cancellation during delivery
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					if ctx.Err() != nil {
						// Parent context is done, requeue and exit
						msgLogger.Info("Worker detected context cancellation during delivery, requeueing message")
						if requeueErr := w.processor.queue.Requeue(ctx, msg); requeueErr != nil {
							msgLogger.Error("CRITICAL - Failed to requeue message during shutdown", "error", requeueErr)
						}
						return
					}
					// Only the delivery timeout expired, treat as temporary failure and requeue
					msgLogger.Warn("Delivery timed out, will retry", "timeout", "2m")
					msg.RetryCount++
					delay := calculateRetryDelay(msg.RetryCount)
					msg.NextAttemptAt = time.Now().Add(delay)
					if requeueErr := w.processor.queue.Requeue(ctx, msg); requeueErr != nil {
						msgLogger.Error("CRITICAL - Failed to requeue message after timeout", "error", requeueErr)
					}
					continue
				}

				msgLogger.Error("Delivery failed", "error", err)
				metrics.RecordMessageStatusByDomain("delivery_failed", msg.From)

				// Determine if this is a permanent failure or temporary failure
				// For now, check if the error message contains "permanent"
				isPermanentFailure := err != nil && isPermFailure(err.Error())

				if isPermanentFailure {
					msgLogger.Warn("Permanent delivery failure, not requeueing", "error", err)
					// Here we would normally generate a bounce message
					// TODO: Implement bounce message generation
				} else if msg.RetryCount >= MaxRetries {
					msgLogger.Warn("Message exceeded max retries, marking for bounce", "max_retries", MaxRetries)
					// Here we would normally generate a bounce message
					// TODO: Implement bounce message generation
				} else {
					msg.RetryCount++
					delay := calculateRetryDelay(msg.RetryCount)
					msg.NextAttemptAt = time.Now().Add(delay)
					msgLogger.Info("Message needs retry, requeueing", "attempt", msg.RetryCount, "delay", delay.String(), "next_attempt_at", msg.NextAttemptAt)
					if requeueErr := w.processor.queue.Requeue(ctx, msg); requeueErr != nil {
						msgLogger.Error("CRITICAL - Failed to requeue message for retry", "error", requeueErr)
					}
				}
			} else {
				msgLogger.Info("Message processed successfully")
				metrics.RecordMessageStatusByDomain("delivered", msg.From)
			}

			// Check for shutdown after each message
			select {
			case <-ctx.Done():
				msgLogger.Info("Worker exiting due to context cancellation after processing message")
				return
			default:
				// Continue processing
			}
		}
	}
}

// isPermFailure determines if an error is a permanent failure.
// In a real implementation, this would check for SMTP 5xx error codes
// and other indicators of permanent failures.
func isPermFailure(errMsg string) bool {
	return strings.Contains(strings.ToLower(errMsg), "permanent")
}

// calculateRetryDelay calculates the delay for the next retry attempt.
// Uses exponential backoff with a cap.
func calculateRetryDelay(retryCount int) time.Duration {
	if retryCount <= 0 {
		return BaseRetryDelay
	}
	// Exponential backoff: BaseRetryDelay * 2^(retryCount-1)
	delay := BaseRetryDelay * time.Duration(1<<(retryCount-1))
	if delay > MaxRetryDelay {
		delay = MaxRetryDelay
	}
	// TODO: Add jitter?
	return delay
}
