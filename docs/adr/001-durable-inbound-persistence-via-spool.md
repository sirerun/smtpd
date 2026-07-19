# ADR 001: Durable inbound persistence via the spool service

## Status
Accepted

## Date
2026-07-19

## Context
The code review (`.claude/scratch/code-review-report.md`, finding C1) established that
smtpd holds accepted mail only in memory (`internal/queue`, `pkg/message`). smtpd returns
`250 OK` after DATA, which under RFC 5321 accepts responsibility for the message, yet a
crash or restart loses every accepted-but-undelivered message with no NDR. An MTA that
loses accepted mail is not shippable.

smtpd is one of four cooperating services in `github.com/sirerun`:
- `smtpd` -- inbound MTA (this repo).
- `spool` -- S3-backed durable message store, gRPC contract in `pkg/spoolapi`:
  `StoreMessage(tenant_id, user_id, raw_mime) -> message_id` and
  `FetchMessage(message_id) -> raw_mime`.
- `imapd` -- IMAP retrieval, reads messages back from spool.
- `mailtive` -- control plane / provisioning (tenant and user resolution).

The durable store already exists (spool). Building a second private on-disk spool inside
smtpd would duplicate it and diverge from how imapd reads mail back.

## Decision
For inbound mail addressed to a LOCAL recipient, smtpd calls spool `StoreMessage` and only
returns `250 OK` after StoreMessage succeeds. Delivery-to-mailbox responsibility moves to
spool + imapd; smtpd's in-memory queue is retained ONLY for the outbound relay path
(authenticated submission relayed to remote MX), whose durability is handled separately in
ADR 002.

Local-recipient resolution (recipient address -> tenant_id + user_id) is obtained from the
mailtive control plane and cached; unresolved local recipients are rejected with `550`
rather than accepted-then-lost.

The spool client is wrapped behind a small internal interface (`internal/spool`) so the
gRPC dependency is mockable in tests and the transport can change without touching session
handling.

## Consequences
Positive: accepted local mail is durable before acknowledgement; smtpd stops owning
long-term storage; retrieval stays consistent with imapd; the failure mode becomes "reject
on store failure" (client retries) instead of "silent loss".
Negative: smtpd gains a hard runtime dependency on spool and mailtive for inbound
acceptance; a spool outage means smtpd must issue temporary `4xx` deferrals rather than
accept. Adds gRPC and a recipient-resolution cache to the smtpd process. Cross-repo proto
version coupling must be managed.
