# ADR 003: SPF/DKIM are advisory inputs; DMARC is the sole accept/reject authority

## Status
Accepted

## Date
2026-07-19

## Context
Findings C3, H12, H13, H14, M13, M17, L14, L15 show the inbound mail-authentication layer is
both wired wrong and RFC-incomplete:
- SPF and DKIM store their results on a discarded local `context` copy (the `Plugin`
  interface returns only `error`), so DMARC never receives them and every `p=reject` domain
  gets all mail rejected (C3).
- SPF and DKIM each reject independently as standalone gates, rejecting legitimate mail
  (Google/M365 `include:` senders via a hand-rolled partial SPF evaluator; forwarded and
  mailing-list mail via DKIM) (H12, H13).
- DMARC has no organizational-domain fallback, leaving a subdomain-spoofing bypass (H14).

## Decision
1. Change the plugin contract so per-transaction authentication results flow forward. Results
   are attached to a mutable per-transaction result object carried on `SessionInfo` (not via
   a returned-and-discarded context), so DMARC reads real SPF and DKIM outcomes.
2. SPF and DKIM become advisory: they compute a result and never reject on their own. DMARC
   is the only plugin that issues an accept/reject verdict, based on aligned SPF or DKIM plus
   the published policy.
3. Replace the hand-rolled SPF evaluator with a maintained, RFC 7208-complete library
   (evaluates `include`/`a`/`mx`/`redirect`/bare `ip4:`/`ip6:` and the void-lookup limit).
4. DMARC performs the organizational-domain lookup (Public Suffix List) when the exact domain
   has no record, and applies `sp=` policy to subdomains.

## Consequences
Positive: legitimate senders stop being rejected; subdomain spoofing against `p=reject` is
blocked; Authentication-Results reflect reality; DMARC aggregate reports stop containing
fabricated constants.
Negative: adds a third-party SPF library and a PSL dependency (both maintained, low risk); the
plugin interface change touches the session transaction flow and all existing plugins; DMARC
becomes the single decision point and must be correct (well covered by tests).
