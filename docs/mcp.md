# Agent mail submission with MCP

`smtpd-mcp` exposes mail tools over stdio. It submits to an existing SMTP endpoint,
which can be this repository's daemon or an authenticated submission relay. It does
not start another SMTP listener or outbound delivery queue. The operator fixes the
endpoint and sender identity at startup; tool arguments cannot change them.

## Tools

- `smtpd_preview_email`: validate and render one plain-text email without connecting
  to SMTP.
- `smtpd_send_email`: submit one email to one recipient when sending is enabled.
- `smtpd_status`: inspect effective non-secret configuration. This is configuration
  status, not a network or deliverability check.

An SMTP acceptance is **not inbox delivery**. The configured server can still defer,
bounce, filter, or lose a message after acceptance. smtpd's current queue is in memory,
so accepted mail is not yet durable across process failure or restart.

There is no automatic retry or deduplication. If the connection fails during final
DATA acknowledgement, acceptance can be unknown. Check the submission server's logs
before resubmitting; a blind retry can produce duplicates.

## Build and connect

Requires Go 1.24 or later (the MCP SDK minimum; see `go.mod`).

```sh
go build -o /path/to/bin/smtpd-mcp ./cmd/smtpd-mcp
```

Configuration examples and the complete flag reference are added with the binary's
final interface below.

The MCP client launches the binary as a subprocess and speaks JSON-RPC on stdin and
stdout. Diagnostics use stderr. No HTTP listener is opened. Treat access to a
send-enabled subprocess as authority to send mail as its configured identity.

For this daemon, enable SMTP authentication and TLS, configure its users file, and
use a trusted certificate matching the submission hostname. The current server opens
one listener at `server.port`: when that port equals `server.submission_port`, it
uses implicit TLS; otherwise it offers STARTTLS when TLS is configured. Match the
adapter TLS mode to the actual listener. Unauthenticated
loopback access is not permission to relay externally: smtpd enforces authenticated
relay. See [operations.md](operations.md). The MCP process does not bypass the
server's relay, plugin, queue, or signing behavior.

## Before workshop outreach

Running the agent interface on a Mac is reasonable. Direct-to-MX delivery through a
home or office internet connection needs separate qualification. Never having sent
mail from an IP does not establish reputation or absence from blocklists: Spamhaus's
Policy Blocklist includes IP ranges that should use a submission relay, independent
of past abuse. A static IP alone does not resolve that policy.

Prefer a submission service whose policy explicitly permits your intended outreach,
or a qualified mail host with operator-controlled reverse DNS. When using a relay,
recipients primarily see the relay's sending IP, so sending through it does not warm
the Mac's public IP. Neither transport guarantees acceptance of unsolicited mail.

Before direct delivery, verify the actual public egress IP and its policy/reputation,
ISP permission and outbound port 25, stable addressing, matching PTR/forward DNS and
EHLO, SPF, DKIM, DMARC alignment, and a working return path for bounces and replies.
There is no IP lookup or live-delivery qualification in this feature. The existing
outbound deliverer can continue without a DKIM signature after a signing error;
verify signatures in received test messages rather than assume configuration proves
authentication.

Start with a small number of relevant, individually reviewed messages and measure
real replies, bounces and complaints. Do not treat a fixed daily ramp as proof of
reputation, and do not manufacture warm-up engagement. Stop on adverse feedback.

This adapter is **not a campaign engine**. Before letting several agents conduct
outreach, provide shared durable pacing, deduplication, suppression/unsubscribe state,
bounce/complaint processing, and an audit trail. Per-process counters would reset on
restart and multiply across clients, so they would not provide a reliable global cap.
The daemon's configuration-visible security rate limit is not currently enforced.

For US commercial mail, the FTC describes requirements including accurate sender
information and subject lines, identification as advertising, a valid physical
postal address, clear opt-out, and honoring opt-outs within ten business days.
Business-to-business email is included. Recipient-country rules and provider policies
may impose additional requirements; the MCP interface does not determine eligibility.

Sources:

- [Spamhaus Policy Blocklist](https://www.spamhaus.org/blocklists/policy-blocklist/)
- [Google email sender guidelines](https://support.google.com/mail/answer/81126?hl=en)
- [FTC CAN-SPAM compliance guide](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)

## Future HTTP transport

Tool registration is separate from the stdio entrypoint. A later Streamable HTTP
entrypoint can reuse it, but must first define caller authentication and authorization,
origin validation, per-caller sender permissions, durable shared send controls, and
an exposure/deployment policy. Stdio ownership is a local process boundary; it cannot
be carried over as anonymous HTTP sending authority.
