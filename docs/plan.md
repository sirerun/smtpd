# smtpd Remediation Plan

## Context

This plan remediates the 56 findings catalogued in `.claude/scratch/code-review-report.md`
(3 Critical, 17 High, 20 Medium, 16 Low) for `github.com/sirerun/smtpd`, an inbound SMTP
daemon written in Go. The review verdict: the server is not production-safe because it (1)
loses mail, (2) is trivially DoS-able by unauthenticated clients, and (3) has mail
authentication wired wrong, plus two security mitigations that do not actually work.

smtpd cooperates with three sibling repositories under `../` (all `github.com/sirerun/*`):
- `spool` -- S3-backed durable message store, gRPC contract in `pkg/spoolapi`:
  `StoreMessage(tenant_id, user_id, raw_mime) -> message_id`, `FetchMessage(message_id) -> raw_mime`.
- `imapd` -- IMAP retrieval, reads mail back from spool.
- `mailtive` -- control plane / provisioning (tenant and user resolution).

smtpd currently references none of them in Go code. The durability remediation integrates
smtpd with spool (for inbound local mail) rather than building a private disk spool; see
`docs/adr/001-durable-inbound-persistence-via-spool.md`. The outbound relay path keeps a
smtpd-owned queue, made durable per `docs/adr/002-outbound-relay-queue-durability.md`.

Definition of done for this project (per repo CLAUDE.md, staging is shut down): local
verification with the race detector plus the CI suites. Every code change must pass
`go test ./... -race`, `golangci-lint run`, and `govulncheck ./...` (the gates this plan
adds in E6). Staging deployment is not available; production verification applies only when
the services are deployed by the operator.

kazi is on PATH, so engineering tasks carry an `acc:` line (a machine-checkable acceptance
predicate). `/apply`'s kazi lane derives one predicate per `acc:` line just-in-time.

### Architecture decisions (ADRs created with this plan)
- `docs/adr/001-durable-inbound-persistence-via-spool.md` -- inbound local mail is stored in
  spool before `250 OK`.
- `docs/adr/002-outbound-relay-queue-durability.md` -- disk-backed outbound queue with
  per-recipient state and draining shutdown.
- `docs/adr/003-mail-authentication-advisory-to-dmarc.md` -- SPF/DKIM advisory, DMARC decides;
  replace hand-rolled SPF with a maintained library; add DMARC org-domain fallback.
- `docs/adr/004-ci-race-lint-vuln-gates.md` -- CI runs `-race`, `golangci-lint`, `govulncheck`.

## Discovery Summary

- No `docs/plan.md` existed before this run; this is a new plan. No completed work to trim.
- kazi resolves at `/usr/local/bin/kazi`; origin remote is `git@github.com:sirerun/smtpd.git`.
- `spool` exposes only `StoreMessage`/`FetchMessage` over gRPC; it is mailbox-oriented
  (tenant_id/user_id), so it fits inbound local delivery but is NOT an outbound relay queue.
  smtpd has no recipient -> tenant/user mapping today (only `localDomains`), so a resolution
  step against mailtive is required for spool integration.
- The four Critical/High themes map cleanly onto six executable epics (E1-E6). The remaining
  Medium/Low correctness and cleanup work (E7) and the cross-repo end-to-end integration test
  (E8) are outline epics, expanded once the safety-critical epics land and their integration
  seams are proven.

## Use Case Summary

Full manifest: `.claude/scratch/usecases-manifest.json`. Each is BROKEN or MISSING today.

| UC | Capability | Epic |
|----|------------|------|
| UC-01 | Inbound local mail durably stored (spool) before 250 OK; survives restart | E2 |
| UC-02 | Outbound relay retries transient failures; never silently drops mail | E1 |
| UC-03 | Permanent failures generate a bounce (NDR) | E1 |
| UC-04 | Legitimate SPF senders (include:, bare ip4:) accepted | E3 |
| UC-05 | Forwarded/mailing-list mail not rejected by DKIM alone | E3 |
| UC-06 | Subdomain spoofing blocked (DMARC org fallback) | E3 |
| UC-07 | Pre-auth memory DoS resisted (line/size/recipient/auth caps) | E4 |
| UC-08 | DNS lookups do not serialize; cache scales | E4 |
| UC-09 | No Prometheus cardinality explosion; accurate queue depth | E4 |
| UC-10 | Graceful shutdown drains/persists all mail; no panic/deadlock | E2 |
| UC-11 | Rate limiting and IP/domain filtering enforce config | E5 |
| UC-12 | AUTH timing-safe; hashed creds; no nil-store panic; no cleartext AUTH | E5 |
| UC-13 | Null sender accepted; ESMTP params parsed; SIZE consistent | E7 |
| UC-14 | Config typos/invalid values rejected; bind failure exits non-zero | E7 |
| UC-15 | End-to-end: smtpd accepts -> spool stores -> imapd fetches | E8 |
| UC-16 | CI catches concurrency/lint/vuln regressions | E6 |
| UC-17 | UUID message IDs; correct version/secret-file perms; cleanup | E7 |

## Scope and Deliverables

In scope: all 56 review findings. Delivered as six executable epics (safety-critical:
mail-loss, durability, mail-auth, DoS hardening, security mitigations, CI gates) plus two
outline epics (protocol/config/low cleanup, end-to-end wiring). Out of scope: multi-node relay
clustering, new product features, changes to spool/imapd/mailtive beyond the client
integration and one shared integration test.

## Checkable Work Breakdown

Status legend: `[ ]` todo, `[~]` in progress, `[x]` done. Every engineering task lists
`verifies:` (use case IDs) and `acc:` (kazi predicate). Waves within an epic may run in
parallel across tasks with no ordering dependency.

---

### E1 -- Eliminate outbound mail loss
fidelity: executable | verifies: UC-02, UC-03
Frontier, highest-impact/lowest-risk. Make delivery report real results so the processor
requeues, bounces, and never silently drops. Independent of the durability rewrite (E2) and
can land first.

Wave 1 (delivery result contract):
- [ ] T1.1 Define a per-recipient delivery result type (`Delivered` / `TempFail` / `PermFail`
  with reason and SMTP code) in `pkg/outbound`. verifies: UC-02
  acc: [pkg/outbound exposes a DeliveryResult type carrying per-recipient status and the go test for it passes]
- [ ] T1.2 Rewrite `Deliverer.Deliver` (`pkg/outbound/deliverer.go:129-181`) to collect each
  domain goroutine's outcome into an aggregated per-recipient result and return it (no more
  unconditional nil). verifies: UC-02
  acc: [Deliver returns a non-nil result set whose entries reflect each recipient outcome; a simulated 451 yields TempFail not success]
- [ ] T1.3 Classify permanent vs temporary by SMTP reply code, not `strings.Contains("permanent")`
  (`internal/processor/processor.go:240`). verifies: UC-02
  acc: [a 5xx reply with no word "permanent" classifies as PermFail and a 4xx as TempFail in the processor unit test]

Wave 2 (processor consumes results):
- [ ] T1.4 Update the processor (`internal/processor/processor.go:171-223`) to requeue only
  recipients with TempFail, mark the message terminal only when all recipients are Delivered
  or PermFail, and remove the "always success on nil" branch. verifies: UC-02
  acc: [processor unit test: message to two recipients where one temp-fails is requeued only for the failed recipient]
- [ ] T1.5 On PermFail or MaxRetries exceeded, generate an RFC 3464 DSN (bounce) to the
  envelope sender instead of the `TODO` drop (`processor.go:203-210`). verifies: UC-03
  acc: [processor unit test: a PermFail recipient produces a DSN message addressed to the original MAIL FROM]
- [ ] T1.6 Retry targets only unfinished recipients so a partially-delivered message is never
  re-sent to a recipient that already succeeded (H15). verifies: UC-02
  acc: [retry of a 2-recipient message re-sends only to the unfinished recipient in the outbound test]

Wave 3 (connection-pool correctness):
- [ ] T1.7 Close (do not pool) a client left mid-transaction after a failed Send
  (`deliverer.go:234-236`); only healthy, reset connections return to the pool. verifies: UC-02
  acc: [a client whose RCPT failed mid-transaction is closed, not returned to the pool, per the pool unit test]
- [ ] T1.8 Enforce `IdleTimeout` in the pool with a liveness check / eviction so dead
  connections are not handed out (`smtp_client.go:293-326`). verifies: UC-02
  acc: [a pooled connection older than IdleTimeout is evicted before reuse in the pool test]
- [ ] T1.9 On a 4xx at one MX, try the next MX host instead of aborting the domain
  (`deliverer.go:242-246`); defer whole DKIM-signing failures instead of sending unsigned
  (`deliverer.go:211-214`). verifies: UC-02
  acc: [delivery test with a temp-failing primary MX and an accepting secondary MX succeeds via the secondary]
- [ ] T1.10 Add `golangci-lint`-clean formatting and a `go test ./pkg/outbound/... ./internal/processor/... -race` pass for E1. verifies: infrastructure
  acc: [go test ./pkg/outbound/... ./internal/processor/... -race passes]

Milestone M1: outbound path returns real results, requeues per-recipient, bounces perm-fails,
never silently drops. Unblocks E8 planning.

---

### E2 -- Durable persistence and safe shutdown
fidelity: executable | verifies: UC-01, UC-10, UC-15
Integrate spool for inbound local mail (ADR 001) and make the outbound queue disk-durable with
a draining, race-free shutdown (ADR 002). Wave 1 (spool) and Wave 2 (queue) are independent and
parallelizable; Wave 3 depends on both.

Wave 1 (inbound spool integration):
- [ ] T2.1 Add a `internal/spool` client wrapper around `spoolapi.SpoolClient` (dial, timeouts,
  a mockable interface). verifies: UC-01
  acc: [internal/spool exposes a Store(ctx, tenant, user, raw) method with a mock used in tests, and its unit test passes]
- [ ] T2.2 Add recipient -> (tenant_id, user_id) resolution against mailtive with an in-process
  TTL cache; unresolved local recipients are rejected `550` (not accepted-then-lost). verifies: UC-01
  acc: [a local recipient resolves to a tenant/user via the resolver mock; an unknown local recipient yields a 550 in the session test]
- [ ] T2.3 In the DATA completion path, call spool `StoreMessage` for each resolved local
  recipient and only emit `250 OK` after all stores succeed; on store failure reply `451`
  (temporary) so the client retries. verifies: UC-01, UC-15
  acc: [session test: 250 is returned only after the spool mock StoreMessage succeeds; a store error yields 451 and no 250]

Wave 2 (durable outbound queue + safe shutdown):
- [ ] T2.4 Replace the send-on-closed-channel shutdown with context/stop-channel signaling that
  senders observe; never `close(readyChan)` from the receiver (H7). verifies: UC-10
  acc: [go test ./internal/queue/... -race passes a shutdown-under-load test with no panic]
- [ ] T2.5 Remove the lock-held-across-blocking-send in `Requeue` (H8) and the busy-spin under a
  full ready channel (H9); use non-blocking signal + backoff. verifies: UC-10
  acc: [a queue stress test with a saturated ready channel completes without deadlock and CPU stays bounded (test asserts progress within a deadline)]
- [ ] T2.5b Fix the queue-depth gauge drift: increment `QueueSizeReady` on promotion to match the
  `Dequeue` decrement (M14). verifies: UC-09
  acc: [queue test asserts size_ready never goes negative across enqueue/promote/dequeue cycles]
- [ ] T2.6 Persist outbound queue entries (write-then-fsync) on enqueue and on per-recipient
  state change; reload on startup (ADR 002). verifies: UC-10
  acc: [a queue with N persisted messages reloads all N after a simulated restart in the queue test]
- [ ] T2.7 Implement draining shutdown: stop intake, flush in-flight and retry-heap state to
  disk, wait up to `shutdown_timeout` for active deliveries (H10). verifies: UC-10
  acc: [shutdown test: messages in ready/retry/in-flight are all persisted or delivered, none dropped]

Wave 3 (integration wiring):
- [ ] T2.8 Wire spool + queue into the composition root (`cmd/smtpd`, `internal/server`);
  a spool dial failure at startup is a hard error (exit non-zero), a spool outage at runtime
  yields `451` deferrals. verifies: UC-01, UC-10
  acc: [smtpd fails to start with exit code != 0 when the spool endpoint is unreachable at boot]
- [ ] T2.9 `go test ./internal/queue/... ./internal/server/... ./internal/spool/... -race` green. verifies: infrastructure
  acc: [go test ./internal/queue/... ./internal/server/... ./internal/spool/... -race passes]

Milestone M2: accepted local mail is durable in spool before ack; outbound queue survives
restart; shutdown drains with no panic/deadlock/spin. Unblocks E8.

---

### E3 -- Mail-authentication correctness
fidelity: executable | verifies: UC-04, UC-05, UC-06
Fix the SPF/DKIM->DMARC data flow and make DMARC the sole authority (ADR 003).

Wave 1 (result-passing contract):
- [ ] T3.1 Add a mutable per-transaction auth-result object on `plugin.SessionInfo` (SPF result,
  DKIM results); remove the discarded-context pattern (C3). verifies: UC-04, UC-06
  acc: [after OnMailFrom/OnMessage run, DMARC reads a non-nil SPF result and DKIM results from SessionInfo in a plugin integration test]
- [ ] T3.2 Make SPF and DKIM advisory: they populate results and return nil (never reject)
  (H12/H13); DMARC issues the only verdict. verifies: UC-04, UC-05
  acc: [a message failing DKIM but passing aligned SPF is accepted, not 550, in the plugin integration test]

Wave 2 (RFC-complete evaluation):
- [ ] T3.3 Replace the hand-rolled SPF evaluator with a maintained RFC 7208 library that handles
  `include`/`a`/`mx`/`redirect`/bare `ip4:`/`ip6:` and the void-lookup limit (H12, M17, L15).
  verifies: UC-04
  acc: [SPF eval of "v=spf1 include:_spf.google.com -all" for a Google-published sender IP returns Pass, not Fail]
- [ ] T3.4 Add DMARC organizational-domain fallback via the Public Suffix List and apply `sp=`
  to subdomains (H14). verifies: UC-06
  acc: [a From of phish.victim.com with victim.com p=reject and no _dmarc.phish record is rejected via the org-domain policy in the DMARC test]
- [ ] T3.5 Populate real DMARC aggregate-report fields from evaluation instead of the fabricated
  constants (M13); route the DKIM caching resolver through the DNS cache (L14). verifies: UC-06
  acc: [a DMARC report record reflects the actual evaluated disposition/spf/dkim, not the "none/fail/none" constants, in the reporting test]
- [ ] T3.6 `go test ./internal/plugins/... -race` green; `golangci-lint` clean. verifies: infrastructure
  acc: [go test ./internal/plugins/... -race passes]

Milestone M3: legitimate senders accepted, forwarded mail not DKIM-rejected, subdomain spoofing
blocked, reports truthful.

---

### E4 -- Resource-exhaustion hardening
fidelity: executable | verifies: UC-07, UC-08, UC-09
Cap unbounded reads and growth; stop the DNS cache from serializing.

Wave 1 (connection input caps):
- [ ] T4.1 Bound command and AUTH sub-reads to the RFC 5321 line limit; reject overlong lines
  with `500` instead of growing the buffer (H1, `session.go:161,720,740`). verifies: UC-07
  acc: [a command line exceeding the configured max is rejected with 500 and memory stays bounded in the session test]
- [ ] T4.2 Enforce `maxMessageSize` incrementally while reading DATA (bounded/chunked read), not
  per completed line (H2, `session.go:532`). verifies: UC-07
  acc: [a DATA stream with no newline exceeding maxMessageSize is rejected without buffering past the limit in the session test]
- [ ] T4.3 Cap recipients per message (configurable, default 100) with `452`, and drop the
  connection after N failed AUTH attempts (H3). verifies: UC-07
  acc: [the (N+1)th RCPT past the cap gets 452 and the (K+1)th failed AUTH disconnects, per session tests]

Wave 2 (DNS + metrics scaling):
- [ ] T4.4 Refactor the DNS cache to not hold the write lock across the live lookup; dedupe
  concurrent lookups (singleflight) (H4, `internal/dns/cache.go`). verifies: UC-08
  acc: [go test -race shows concurrent cache lookups for distinct keys do not serialize (a timing/assertion test) and pass]
- [ ] T4.5 Short-TTL negative caching so a transient DNS failure does not poison the entry for
  the full TTL (M11). verifies: UC-08
  acc: [a cached DNS error expires after the negative TTL and a subsequent lookup re-queries in the cache test]
- [ ] T4.6 Bound outbound per-domain goroutine fan-out with a worker pool / semaphore (M19). verifies: UC-08
  acc: [delivering to 500 domains never exceeds the configured concurrency bound in the deliverer test]
- [ ] T4.7 Pass the parsed domain (not the full sender address) to
  `RecordMessageStatusByDomain` (H5, `processor.go:197,222`). verifies: UC-09
  acc: [the domain metric label receives "example.com" for a sender "a@example.com" in the metrics test]
- [ ] T4.8 `go test ./internal/dns/... ./internal/metrics/... ./pkg/outbound/... -race` green. verifies: infrastructure
  acc: [go test ./internal/dns/... ./internal/metrics/... ./pkg/outbound/... -race passes]

Milestone M4: no pre-auth memory DoS; DNS scales; metrics bounded and accurate.

---

### E5 -- Security mitigations that actually work
fidelity: executable | verifies: UC-11, UC-12
Fix the broken timing defense, wire the dead security layer, close AUTH gaps.

Wave 1 (auth hardening):
- [ ] T5.1 Replace the malformed 56-char dummy bcrypt hash with a real 60-char hash generated at
  `DefaultCost`; add a timing assertion to the test (H16, `store.go:84`). verifies: UC-12
  acc: [the no-such-user and wrong-password AUTH paths are within a small timing ratio in a timing test that fails on the old dummy hash]
- [ ] T5.2 Nil-guard `s.userStore` in `handleAuthPlain`/`handleAuthLogin` so AUTH with auth
  disabled returns `503`/`454` instead of panicking (M1, `session.go:683,755`). verifies: UC-12
  acc: [AUTH PLAIN with auth disabled returns an SMTP error and does not panic in the session test]
- [ ] T5.3 Support pre-hashed credentials in the users file (wire `AddUserWithHash`) so plaintext
  passwords need not sit on disk (M5); refuse AUTH over cleartext when TLS is absent (L3);
  restrict JWT valid methods to the keyFunc's family (M6). verifies: UC-12
  acc: [a users file with a bcrypt hash authenticates without a plaintext password field in the auth test]

Wave 2 (wire the security layer):
- [ ] T5.4 Wire `internal/security` (rate limiter + IP/domain filter) into the accept/OnConnect
  path so `rate_limit`/`allowed_ips`/`blocked_ips`/`allowed_domains`/`blocked_domains` are
  enforced (H17). verifies: UC-11
  acc: [a connection from a blocked_ips CIDR is refused before the banner in an integration test]
- [ ] T5.5 Key the rate limiter per client IP (not one global bucket), lower-case domain matching,
  and bound the ratelimit map; fix the pre-lock `cleanupAt` read race in the ratelimit plugin
  (H6, L3). verifies: UC-11
  acc: [go test ./internal/security/... ./pkg/plugin/ratelimit/... -race passes and one abusive IP does not deny a second IP in the test]

Milestone M5: timing side channel closed, security config enforced, AUTH gaps shut.

---

### E6 -- CI safety gates
fidelity: executable | verifies: UC-16
Small but load-bearing: make regressions of E1-E5 impossible to ship green (ADR 004).

- [ ] T6.1 Add a `go test ./... -race` job to `.github/workflows/ci.yml` (keep the fast `-short`
  job). verifies: UC-16
  acc: [the CI workflow contains a required job running go test with -race]
- [ ] T6.2 Add `golangci-lint run` (govet + staticcheck incl. SA1029) and fix or explicitly
  exclude pre-existing findings so the gate is green. verifies: UC-16
  acc: [golangci-lint run exits 0 on the repo]
- [ ] T6.3 Add `govulncheck ./...` as a CI job. verifies: UC-16
  acc: [govulncheck ./... exits 0 in CI]

Milestone M6: CI runs race + lint + vuln on every PR to main.

---

### E7 -- SMTP protocol correctness, config validation, and cleanup
fidelity: outline | verifies: UC-13, UC-14, UC-17
Intent: fix the remaining RFC-correctness gaps (null sender, ESMTP params, advertised SIZE),
harden config parsing and startup, and clear the Low cleanup backlog (UUID IDs, TLS cert
caching, dead fields, string context keys, version string, secret-file perms, benchmark and
loadtest tool bugs). Exit criteria: findings M2, M3, M4, M7, M16, L1, L4-L11, L13, M20, L16 all
resolved with tests, `-race` and `golangci-lint` green. This epic is deferred behind the
safety-critical epics because these are lower-severity and several touch files that E1-E5 are
actively rewriting (session.go, config.go); expanding now would create merge churn.
- [ ] T7.0 PLAN: expand E7 into executable tasks once E1, E4, and E5 have landed (they finalize
  session.go and config.go). kind: plan. deps: M1, M4, M5. verifies: infrastructure
  acc: [docs/plan.md E7 contains executable 30-90 min tasks with acc lines for every listed M/L finding]

---

### E8 -- End-to-end cross-repo wiring verification
fidelity: outline | verifies: UC-15
Intent: prove the full inbound path works across repos -- smtpd accepts a message, spool stores
it, imapd fetches the same bytes back -- with an automated integration test spanning the three
services (per the repo's Wiring Completeness Rule). Exit criteria: an integration test (spool +
smtpd + imapd, wired via their real gRPC/IMAP boundaries, using `sire dev`/SQLite or ephemeral
containers) that submits a message to smtpd and asserts imapd returns identical MIME. This is an
outline because it depends on the spool integration (E2) existing and on deciding the test
harness (in-repo vs a shared e2e location in one of the sibling repos).
- [ ] T8.0 PLAN: expand E8 into executable tasks once E2 lands; decide the harness location and
  whether the test lives in smtpd, spool, or a shared e2e module. kind: plan. deps: M2. verifies: infrastructure
  acc: [docs/plan.md E8 contains an executable integration-test task with a concrete harness and acc line]

## Parallel Work

- E1, E3, E4, E5, E6 are largely independent and can run concurrently across sessions/agents.
- E2 Wave 1 (spool) and Wave 2 (queue) are independent; E2 Wave 3 joins them.
- Cross-epic file contention to coordinate (claim before editing): `internal/server/session.go`
  is touched by E1(none), E4 (T4.1-T4.3), E5 (T5.2-T5.3), E2 (T2.3). Sequence session.go edits
  or land them on one branch to avoid conflicts. `internal/config/config.go` is touched by E5
  (T5.3) and E7. `.github/workflows/ci.yml` only by E6.
- Recommended first wave to run in parallel: E1, E4, E6 (no shared files among them except
  processor/metrics which E1 and E4 partly share -- coordinate T1.3/T4.7).

## Timeline and Milestones

Ordering by dependency, not calendar (operator schedules waves):
1. M1 (E1) + M6 (E6) first -- stop silent loss, turn on the gates that protect everything after.
2. M4 (E4) + M5 (E5) -- close the remotely-triggerable DoS and the security holes.
3. M2 (E2) -- durability and safe shutdown (largest epic; needs spool/mailtive reachable).
4. M3 (E3) -- mail-auth correctness.
5. Expand and execute E7, then E8 (end-to-end) last.

## Risk Register

- R1: spool/mailtive integration (E2) requires a recipient->tenant/user contract that may not
  exist in mailtive yet. Mitigation: T2.2 defines the resolver interface behind a mock; confirm
  the mailtive endpoint early, and if absent, file a mailtive task before E2 Wave 1.
  Impact: high, likelihood: medium.
- R2: E2 Wave 3 depends on runtime spool availability; a spool outage changes smtpd behavior to
  `451` deferrals. Mitigation: explicit deferral path (T2.8) and tests for it.
- R3: session.go is edited by E2/E4/E5 concurrently. Mitigation: claim locks and the sequencing
  note in Parallel Work; land session.go changes on a shared branch.
- R4: Replacing the SPF evaluator (T3.3) and adding a PSL introduce new dependencies.
  Mitigation: choose maintained libraries, run `govulncheck` (E6) before merge.
- R5: Enabling `golangci-lint` (T6.2) may surface a wall of pre-existing findings. Mitigation:
  baseline-exclude pre-existing issues, gate only new code initially, then burn down.

## Operating Procedure

- Work one epic/wave at a time per session; claim shared files (`/claim R-<file>`) before edits.
- Before any wave: `go test ./... -race` green on the base branch (repo CLAUDE.md preflight).
- Every task: implement, add/extend tests at the real boundary, run `go test ./<pkg>/... -race`
  and `golangci-lint run`, then check the box.
- Small, focused commits; do not commit files in separate top-level directories in one commit.
- Rebase-and-merge PRs (no squash, no merge commits) per operator convention.
- Do not deploy to staging (shut down); production verification only when the operator deploys.

## Progress Log

- 2026-07-19: Plan created from `.claude/scratch/code-review-report.md` (56 findings). Defined
  UC-01..UC-17, epics E1-E8 (E1-E6 executable, E7-E8 outline). Created ADR 001-004. Engineering
  tasks carrying `acc:` lines: 41. Tasks routed `lane: agent`: 0.

## Hand-off Notes

- The review report is the source of truth for finding detail (file:line + fix); this plan
  references findings by ID (C/H/M/L numbers).
- E1 is the recommended starting point: contained, high-impact, no cross-repo dependency.
- Before starting E2, verify the mailtive recipient-resolution endpoint exists (R1); it is the
  one genuine cross-repo unknown.

## Appendix

- Source review: `.claude/scratch/code-review-report.md`
- Use case manifest: `.claude/scratch/usecases-manifest.json`
- ADRs: `docs/adr/001` (spool persistence), `002` (outbound queue), `003` (mail-auth), `004` (CI gates)
- Sibling repos: `../spool`, `../imapd`, `../mailtive`
