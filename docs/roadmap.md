# smtpd Roadmap

## Planned

Remediation of the 56-finding code review (`.claude/scratch/code-review-report.md`). Full
plan: `docs/plan.md`.

- E1 -- Eliminate outbound mail loss (C2, H15, L2, M8-M10, M12, M18). Frontier; start here.
- E2 -- Durable persistence via spool + safe shutdown (C1, H7-H10). ADR 001, 002.
- E3 -- Mail-authentication correctness: SPF/DKIM advisory, DMARC decides (C3, H12-H14). ADR 003.
- E4 -- Resource-exhaustion hardening: line/size/recipient caps, DNS cache, metrics (H1-H6, M11, M14, M19).
- E5 -- Security mitigations: bcrypt timing fix, wire the security layer, AUTH gaps (H16, H17, M1, M5, M6).
- E6 -- CI safety gates: -race, golangci-lint, govulncheck (H11). ADR 004.
- E7 -- (outline) SMTP protocol correctness + config validation + Low cleanup. Expands after E1/E4/E5.
- E8 -- (outline) End-to-end cross-repo wiring test (smtpd -> spool -> imapd). Expands after E2.

## In Progress

(none)

## Done

(none)
