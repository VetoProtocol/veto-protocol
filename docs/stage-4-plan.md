# Stage 4 plan — Gmail, Calendar, alerts, emergency lock

**Exit condition (§13):** revocation across all sessions.

That sentence is the reason for the phase order below. Stage 4 adds two more
Google services, which means two more scopes and two more ways for a credential
to be reachable. Widening the blast radius *before* proving that pulling the
plug works would be the wrong order, so revocation goes first and the new
services go last.

## What already works, and what that leaves

| Mechanism | State |
| --- | --- |
| Agent revoked → next MCP request refused | Works. `session.ts` reads the agent row every request and never caches it |
| Agent revoked → Permit facts removed, Redis sessions dropped | Works (`revocation.ts`) |
| Emergency lock → every decision denies | Works. Pipeline step 3, before Permit is consulted |
| Connection revoked → next call has no credential | Works. `findActiveConnection` runs per call |
| **Outstanding approvals survive a lock** | **Gap.** A `challenge` granted a minute before the lock is still redeemable after it |
| **Proof that any of this lands within five seconds** | **Gap.** §11 names the number; nothing asserts it |
| **Anyone finds out** | **Gap.** §5.4 lists eight events and none of them are emitted |

So "revocation across all sessions" is roughly two thirds built and zero
percent proven.

## Phases

### Phase 1 — Revocation that actually reaches everything

Close the two gaps above.

- **A lock or a revoke invalidates outstanding approvals.** An approval is a
  grant to perform one action later; "later" must not outlive the authority it
  was granted under. Locking a workspace expires every live grant in it;
  revoking an agent expires the grants that name it.
- **Sessions are terminated, not just refused.** Refusal already happens on the
  next request. The session row should also go, so the audit trail shows the
  session ending rather than a series of denials against a session nobody
  closed.
- **A timing assertion.** §11 wants revocation effective on the next protected
  request, targeted within five seconds. Write the test that fails if it is not.

**Exit:** a revoked agent, a locked workspace and a revoked connection each stop
an in-flight session on its next call, with any outstanding approval dead too.

### Phase 2 — Alerts (§5.4)

Eight events: `decision.denied`, `approval.requested`, `approval.resolved`,
`agent.revoked`, `workspace.locked`, `connection.expired`, `credential.revoked`,
`risk.anomaly_detected`.

Requirements are explicit: HMAC signatures, timestamp tolerance, replay
protection, event identifiers, exponential-backoff retry, idempotent consumers.

Design notes decided up front:

- **The payload carries no content and no secrets** (invariant 5). An event says
  *that* a decision was denied and names the reason code; it does not carry the
  arguments, the document, or the challenge.
- **Delivery is outside the request.** A webhook endpoint that hangs must not
  hold up a decision. Events are written to a table in the same transaction as
  the thing they describe, and a worker delivers them — so an event cannot be
  emitted for something that rolled back, and a delivery failure cannot undo it.
- **Signature covers the timestamp and the body.** A signature over the body
  alone can be replayed forever.
- **The endpoint URL is checked against the same SSRF rules as any other
  destination** (`checkDestination`). A webhook target is a caller-supplied URL
  that the server fetches; that is the SSRF scenario with a different label.

**Exit:** locking a workspace delivers a signed `workspace.locked` to a
registered endpoint, retries on failure, and cannot be replayed.

### Phase 3 — Gmail, read only

§9.1: separate search from read, and keep sending out of the MVP entirely.

- Scope `gmail.readonly`, requested **only** when the user activates Gmail —
  the connect flow gains a service parameter rather than widening what it asks
  for by default.
- Tools: `google_gmail.search_messages` (query, bounded page size) and
  `google_gmail.read_message` (one message id).
- Searching is a separate permission from reading, the way listing a folder is
  separate from reading a file.
- Message bodies are hostile input, exactly like Drive file contents. §12.1's
  first scenario — an email that instructs the agent to go and find tax records
  — becomes directly testable here for the first time, because now the email is
  real.

**Exit:** a Gmail read is decided by the same pipeline, and a poisoned message
changes no decision.

### Phase 4 — Calendar, read only

Scope `calendar.readonly`. Tools: `google_calendar.list_events` (bounded time
window) and `google_calendar.read_event`. §9.1 says create/update requires
step-up approval in a later release — so not now, and no write tool exists to
be authorized by accident.

**Exit:** a Calendar read is decided by the same pipeline.

### Phase 5 — The browser, and the docs

- A **lock** control that is impossible to miss and impossible to hit by
  accident, on its own screen.
- Per-service connect: Drive, Gmail and Calendar activated one at a time, each
  showing what it actually granted.
- An **alerts** screen: endpoints, recent deliveries, failures, and the retry
  state.
- `docs/google-setup.md` extended with the two new scopes and their
  verification implications.

**Exit:** all four are usable without curl.

## Risks

| Risk | Handling |
| --- | --- |
| Gmail and Calendar scopes are *restricted*, not merely sensitive — Google's verification is heavier | Internal consent screen, or Testing mode with listed testers. Documented rather than discovered |
| A webhook worker is a new outbound-request surface inside the perimeter | Same destination checks as any other call, and no redirects followed |
| Three services sharing one connection row | Scopes are per grant; `findActiveConnection` already matches on required scope, so a Drive-only connection cannot serve a Gmail call |
| Expiring approvals on lock could erase who approved what | Expire, never delete. The row keeps its resolution the way migration 0008 decided |
