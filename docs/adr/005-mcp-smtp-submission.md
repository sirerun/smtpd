# ADR 005: MCP submits through SMTP

Status: Accepted

## Context

Agents need a stdio mail interface now, with an HTTP transport possible later.
The SMTP daemon already owns authentication, relay authorization, message plugins,
DKIM configuration, and its outbound queue. Its current queue is volatile.

## Decision

Add a separate `smtpd-mcp` executable using the official Go MCP SDK. Keep server/tool
construction separate from stdio transport. Submit messages to an operator-configured
SMTP endpoint through a narrow submitter interface rather than instantiate an outbound
queue for every MCP client. Keep sender/endpoint/credentials outside tool inputs.

Provide non-network preview and configuration status, and an explicitly enabled send
tool for one recipient per invocation. Require verified TLS by default; plaintext
is limited to explicit loopback testing. Do not retry ambiguous submissions. Report
SMTP acceptance separately from delivery.

## Consequences

The same interface works with a local smtpd server or a permitted external relay.
The SMTP endpoint owns durability, signing and actual delivery. This feature does
not fix the existing volatile queue or qualify any IP/domain for outreach. Shared
campaign pacing, suppression, feedback and deduplication are separate durable state
requirements. HTTP reuse requires a new authentication and authorization boundary.
