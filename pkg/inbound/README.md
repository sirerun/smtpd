# Inbound SMTP

`New(Config, Backend)` creates a receiver. Call `Serve(ctx, listener)`; cancel
`ctx` to close the listener and active sockets and wait for handlers. Backends
must honor their context. `CheckRecipient` decides whether every recipient is
local and authorized before DATA. `Accept` must durably commit the complete
message before returning nil: only then does the transport send 250. A failed
commit returns a temporary 451 unless the backend supplies a safe 4xx/5xx
`pkg/smtp.Error`. Backend callbacks can run concurrently and receive independent
envelope slices. Copy message bytes if retaining them beyond the call.

No delivery scheduler, relay policy, AUTH, submission, SMTPUTF8, or ESMTP MAIL
parameters other than SIZE are provided. Only ASCII dot-atom mailbox paths and the null sender
are accepted. The recipient backend is the mandatory routing authority; rejected
recipients never reach Accept. A client can retry after an uncertain disconnect,
so the backend must provide its desired deduplication semantics.

Zero configuration limits default to 25 MiB/message, 100 recipients, 100 active
connections, 10 concurrent DATA operations, a one-minute idle timeout and a
five-minute transaction timeout. Additional public limits are
`MaxConnectionsPerIP` (10), `ConnectionsPerMinute` (60 admissions per fixed
one-minute window per IP), and `MaxTrackedIPs` (10,000). Tracking capacity fails
closed until expired inactive entries can be reclaimed. These use the socket's
peer IP, never forwarded headers. Negative limits are invalid.

Commands are bounded to 512 octets and DATA lines to 1000 octets after SMTP dot
unstuffing, including CRLF. Input requires CRLF; message bytes are preserved
exactly except for dot unstuffing and the final SMTP terminator. Size/framing
violations close the connection after rejection to avoid protocol ambiguity.
STARTTLS requires a greeting, disallows buffered plaintext across the upgrade,
and clears all greeting and transaction state. Provide certificates through
TLSConfig; use an appropriate minimum TLS version for your deployment.
