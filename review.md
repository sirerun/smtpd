In some internal areas, we pass context but do not always observe ctx.Done()—for example, some places just do a blocking channel send or are missing a check. All blocking calls should be select { case ... ; case <-ctx.Done(): }.

Some code logs with logger.Info(...), others with s.logger.Info(...), or fmt.Fprintf(os.Stderr, ...).  Unify around your slog-based logger.

I want a configurable DNS max lookups or caching layer to avoid repeated queries for high-volume traffic.

I want more advanced DMARC logic checks policy features (like storing or sending aggregated reports, etc.)

I want to hold new inbound messages while shutting down, letting the queue drain fully.

I want streaming to disk or chunking for many concurrent large messages.

Unify so that the “server side” is our code and the “client side” is just net/smtp (which we do in internal/outbound). 

Add a per user rate limiting feature. Could be a plugin.

Add a standard “request ID” and “session ID” across logs to track an email from acceptance to delivery.

We do pass sessionID in logs, which is good—just ensure it’s used consistently.

We should beletting plugins hook the final delivery step too so we can do advanced rewriting or routing (like forging DSNs, rewriting headers, quarantining spam, etc.)

Unify the inbound/outbound plugin approach.

