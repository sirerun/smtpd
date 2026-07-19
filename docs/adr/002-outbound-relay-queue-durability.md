# ADR 002: Outbound relay queue durability and per-recipient delivery state

## Status
Accepted

## Date
2026-07-19

## Context
Findings C2, H7, H8, H9, H10, and H15 in `.claude/scratch/code-review-report.md` show the
outbound relay path is unsafe: `pkg/outbound.Deliver` returns nil even when delivery fails
(so the processor drops mail), the in-memory queue panics on shutdown (close-with-live-
senders), can deadlock (lock held across a blocking send) and busy-spin under backpressure,
discards queued and in-flight mail on SIGTERM, and retries the whole message (duplicating
delivery to recipients that already succeeded).

Spool (ADR 001) stores inbound mail for local mailboxes; it is not an outbound relay queue
(its contract is tenant/user mailbox oriented, not "retry to remote MX with backoff"). The
outbound path therefore needs its own durable queue.

## Decision
Replace the in-memory outbound queue with a disk-backed persistent queue that tracks
per-recipient (per-domain) delivery state, so:
1. `Deliver` returns a structured per-recipient result (delivered / temp-fail / perm-fail);
   the processor requeues only unfinished recipients and bounces perm-fails.
2. A message is removed from the queue only after ALL recipients reach a terminal state
   (delivered or bounced).
3. Queue entries are persisted (write-then-fsync) on enqueue and on state change, and
   reloaded on startup, so a crash does not lose queued or in-flight relay mail.
4. Shutdown drains: stop accepting new work, flush in-flight state to disk, and wait up to
   `shutdown_timeout` for active deliveries.
5. Shutdown signaling uses a context / stop channel that senders observe; the ready channel
   is never closed from the receiver side.

The queue abstraction is kept behind an interface so the on-disk implementation can later be
swapped for a shared queue service without changing the processor.

## Consequences
Positive: outbound mail survives restart; transient failures retry with backoff; permanent
failures bounce; no duplicate delivery; deterministic, race-free shutdown.
Negative: added disk I/O and a persistence format to maintain; more complex queue state
machine; per-recipient tracking increases per-message metadata. A local disk queue is
single-node; multi-node relay would need a follow-up (out of scope for this remediation).
