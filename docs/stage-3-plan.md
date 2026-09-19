# Stage 3 plan — presence, passkey challenge, audit timeline

**Exit condition (§13):** an away-state sensitive action requires the *correct*
user to approve it — and "correct" now means proven, not asserted.

Stage 2 already denies, challenges, and binds an approval to one action and one
approver. What is missing is proof that the human resolving it is present and is
who they say they are. That is this stage.

## Phases

### Phase 1 — Presence as a state machine

Today presence is a row the pipeline reads. §7.2 wants states with rules:

| State | Meaning |
| --- | --- |
| `active` | Low-risk actions inside scope go ahead |
| `away` | Sensitive reads and every write need approval |
| `locked` | Everything denies |
| `automation` | Only the named workflow, tools, resources and limits |

Plus `assurance` — how strongly the state is believed. A state set by a fresh
passkey is not the same claim as one set by a keyboard event, and the policy
that gates a sensitive action should be able to say which it needs.

`/v1/presence` (read, set) and `/v1/emergency-lock` (set, clear). Expiry decays
to `away`, never to `active`.

**Never inferred from IP or geolocation** (§7.2). Enforced by the shape of the
input: there is no field to put one in.

**Exit:** presence transitions are legal-only, expiry decays downward, and the
lock is reachable and reversible through the API.

**Done 2026-09-19**, 24 tests. Three properties are enforced by shape rather
than by discipline: the user id comes from the principal so nobody can set
another person's presence; the body schema is closed so there is nowhere to put
an IP address or a location (§7.2); and a source cannot claim more assurance
than it can witness, so `assurance` is not a number the caller picks.

A lapsed record decays to `away` and never to `active`. A lapsed *lock* stays
locked — a lock that expires on a timer is one an attacker only has to outwait.

### Phase 2 — Passkey ceremony (WebAuthn)

The approval state machine exists and refuses replay, expiry, the wrong
approver, and a changed action. What it cannot do yet is prove a human was
there.

- Registration: enrol a passkey against a user (`users.passkey_enrolled`).
- Assertion: resolving an approval requires a signature over the challenge
  already stored on the approval row.
- The challenge is single-use and never leaves the server in a log or an audit
  event (invariant 5).
- Verification uses a library. Hand-rolling COSE key parsing and signature
  verification is where this goes wrong silently.

**Exit:** an approval cannot be resolved without a valid assertion from the
delegating user's enrolled credential, and §12.1's approval-link scenario stays
green with the ceremony in place.

**Done 2026-09-19**, 18 tests. The challenge signed is the one already stored on
the approval row, so a valid signature proves three things at once: a human was
present, they hold the delegator's credential, and what they agreed to was *that*
approval.

`userVerification` is `required`, not `preferred` — a step-up a device may
silently skip is not a step-up. Refusals need proof too: otherwise anyone
holding the link could deny an approval the real user wanted.

The positive test earns its keep. `createVirtualAuthenticator` signs with a real
P-256 key, because every negative test would also pass against a verifier that
rejects everything, and "nothing gets through" is indistinguishable from
"nothing works".

### Phase 3 — Audit timeline

`/v1/audit-events`, tenant-scoped, paginated, with the hash chain verifiable on
demand. The dashboard renders it.

The list is already append-only and hash-chained; this exposes it, and exposes
the verification so a break is visible rather than theoretical.

**Exit:** a workspace's timeline is readable, a tampered chain reports the
break, and nothing in the response carries content or a credential.

### Phase 4 — Dashboard

Presence control, the approval screen, and the timeline — in the design language
already established. Keyboard-complete (§11).

**Exit:** the §13 walkthrough is doable in a browser: go away, have an agent try
something sensitive, approve it with a passkey, see it in the timeline.

## Risks

| Risk | Mitigation |
| --- | --- |
| WebAuthn needs HTTPS and a real origin | `localhost` is the standard exception; the origin is configured, not derived from the request |
| A passkey is lost and the user is locked out | Out of scope for the MVP, but the *shape* matters: enrolment must allow more than one credential per user |
| Presence becomes a way to grant access | It cannot grant: it only ever moves an answer toward more restrictive. A policy names which states allow, and absence is `away` |
| The timeline leaks content | `AuditEventInput` has no field that can carry any; the response is built from the row, not from a join |
