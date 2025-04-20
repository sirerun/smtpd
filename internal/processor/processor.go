package processor

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mailtive/smtpd/internal/errors"
	"github.com/mailtive/smtpd/internal/logging"
	"github.com/mailtive/smtpd/internal/message"
	"github.com/mailtive/smtpd/internal/metrics"
	"github.com/mailtive/smtpd/internal/outbound"
	"github.com/mailtive/smtpd/internal/queue"
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
	Enqueue(msg *message.Message) error                    // Enqueue for immediate processing
	Requeue(msg *message.Message) error                    // Requeue for later retry
}

// Deliverer represents the interface for message delivery operations.
type Deliverer interface {
	Deliver(*message.Message) map[string]outbound.DomainDeliveryStatus
}

// QueueProcessor handles message processing from the queue.
type QueueProcessor struct {
	queue     *queue.Queue
	deliverer *outbound.Deliverer
	workers   []*worker
	stopChan  chan struct{}
	stopWg    sync.WaitGroup
	logger    *logging.Logger
	metrics   *metrics.Metrics
}

// NewQueueProcessor creates a new queue processor.
// numWorkers specifies how many concurrent delivery goroutines to run.
func NewQueueProcessor(
	q *queue.Queue,
	d *outbound.Deliverer,
	numWorkers int,
	logger *logging.Logger,
	metrics *metrics.Metrics,
) *QueueProcessor {
	if logger == nil {
		logger = logging.New(logging.DefaultConfig())
	}
	if metrics == nil {
		metrics = &metrics.Metrics{Logger: logger.With("plugin", "metrics")}
	}
	p := &QueueProcessor{
		queue:     q,
		deliverer: d,
		workers:   make([]*worker, numWorkers),
		stopChan:  make(chan struct{}),
		logger:    logger,
		metrics:   metrics,
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
	w.logger.Info("Worker started")
	for {
		// Blocking Dequeue - waits for a message or context cancellation
		msg, err := w.processor.queue.Dequeue(ctx)
		if err != nil {
			if errors.IsControlledStop(err) {
				w.logger.Info("Worker exiting gracefully", "reason", err)
				return // Exit loop gracefully
			}
			// Log other unexpected errors
			w.logger.Error("Worker received error during Dequeue, exiting", "error", err)
			return
		}
		if msg == nil {
			// Should not happen if error is nil, but check defensively
			continue
		}

		msgLogger := w.logger.With("msg_id", msg.ID, "mail_from", msg.From)

		// Check if it's time to attempt delivery
		if time.Now().Before(msg.NextAttemptAt) {
			if requeueErr := w.processor.queue.Requeue(msg); requeueErr != nil {
				msgLogger.Error("CRITICAL - Failed to requeue sleepy message", "error", requeueErr)
			}
			continue // Get another message
		}

		msgLogger.Info("Processing message", "attempt", msg.RetryCount+1)
		err = w.processor.deliverer.Deliver(ctx, msg)

		// Initialize variables for retry/bounce logic
		needsRetry := false
		needsBounce := false
		failedDomains := []string{}
		tempFailDomains := []string{}

		if err != nil {
			msgLogger.Error("Delivery failed", "error", err)
			w.processor.metrics.RecordMessageStatusByDomain("delivery_failed", msg.From)
			needsRetry = true
			tempFailDomains = append(tempFailDomains, msg.From)
		} else {
			msgLogger.Info("Delivery successful")
			w.processor.metrics.RecordMessageStatusByDomain("delivered", msg.From)
		}

		if needsRetry {
			msg.RetryCount++
			if msg.RetryCount > MaxRetries {
				msgLogger.Warn("Message exceeded max retries, marking for bounce", "max_retries", MaxRetries, "failed_domains", tempFailDomains)
				needsBounce = true
				failedDomains = append(failedDomains, tempFailDomains...) // Add temp fail domains to bounce list
			} else {
				delay := calculateRetryDelay(msg.RetryCount)
				msg.NextAttemptAt = time.Now().Add(delay)
				msgLogger.Info("Message needs retry, requeueing", "attempt", msg.RetryCount, "delay", delay.String(), "next_attempt_at", msg.NextAttemptAt, "failed_domains", tempFailDomains)
				if requeueErr := w.processor.queue.Requeue(msg); requeueErr != nil {
					msgLogger.Error("CRITICAL - Failed to requeue message for retry", "error", requeueErr)
				}
				continue // Message was requeued, don't process bounce for this round
			}
		}

		if needsBounce {
			msgLogger.Warn("Message needs bounce", "failed_domains", failedDomains)
			// TODO: Implement bounce generation (NDR).
		}

		// If message was neither requeued nor bounced, it's considered fully processed (successfully or permanently failed)
		if !needsRetry && !needsBounce {
			msgLogger.Info("Message processed successfully")
		}

		// Check context after processing a message to allow faster shutdown
		select {
		case <-ctx.Done():
			w.logger.Info("Worker exiting due to context cancellation after processing message")
			return
		default:
			// Continue loop
		}
	}
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
