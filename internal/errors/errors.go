package errors

import (
	"context"
	"errors"
)

// ControlledStopError represents an error that indicates a controlled stop/shutdown.
// This is used to distinguish between intentional stops and actual errors.
type ControlledStopError struct {
	Err error
}

func (e *ControlledStopError) Error() string {
	return e.Err.Error()
}

func (e *ControlledStopError) Unwrap() error {
	return e.Err
}

// IsControlledStop returns true if the error is a controlled stop error.
// This includes context.Canceled, queue.ErrQueueClosed, and context.DeadlineExceeded.
func IsControlledStop(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a ControlledStopError
	var controlledStopErr *ControlledStopError
	if errors.As(err, &controlledStopErr) {
		return true
	}

	// Check for specific controlled stop errors
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// NewControlledStop wraps an error as a ControlledStopError.
// This should be used when we want to explicitly mark an error as a controlled stop.
func NewControlledStop(err error) error {
	if err == nil {
		return nil
	}
	return &ControlledStopError{Err: err}
}

// IsQueueClosed returns true if the error indicates the queue is closed.
func IsQueueClosed(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a ControlledStopError that wraps a queue closed error
	var controlledStopErr *ControlledStopError
	if errors.As(err, &controlledStopErr) {
		return IsQueueClosed(controlledStopErr.Err)
	}

	// Check for specific queue closed error
	return errors.Is(err, context.Canceled) // Queue closed errors are treated as context.Canceled
}
