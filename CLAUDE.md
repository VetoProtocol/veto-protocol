# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## How to talk to this user

**Plain words. Short lines. No long paragraphs.**

- Explain things the way you would to a smart person who does not work on this
  codebase. Skip the jargon, or define it in the same breath.
- Break answers into short bullets, tables, or two-line paragraphs. Never a wall
  of text.
- Lead with the answer, then the detail. Not the other way round.
- Say what broke and what it means, not how clever the fix was.
- This is about the *chat*, not the code: comments, commit messages and docs
  keep their normal depth.

## Repository state — read this first

`veto-protocol-spec.md` is the authoritative v1.0 developer specification. Everything
below is derived from it; when this file and the spec disagree, **the spec wins**.
Section references (§3.3, §12.1) point there. An older version of this file called it
`SPEC.md` — that filename does not exist.

**Stage 1 is done.** Identities can be modelled and revoked, over HTTP, behind OIDC
sign-in, with tenant isolation enforced in three places.

**Stage 2 is done.** Allow/deny works end to end: an MCP client asks for a Drive
file, the nine-step pipeline decides, and either the file comes back or a reason
code does. All twelve §12.1 adversarial scenarios are implemented
(`packages/core/src/adversarial.ts`).

What is **not** built: the passkey ceremony (stage 3), presence transitions beyond a
stored state, Gmail and Calendar, and the browser half of the Google connect flow.

### Commands

```bash
pnpm install
pnpm -r typecheck            # tsc --noEmit in every package
pnpm lint                    # eslint; no-explicit-any and no-non-null-assertion are errors
pnpm -r test                 # all packages
pnpm --filter @veto/api test # one package
pnpm --filter @veto/api exec vitest run -t 'IDOR'   # one test by name
pnpm --filter @veto/db migrate                     # apply pending migrations
pnpm --filter @veto/api start                      # control plane on :4000
pnpm --filter @veto/gateway start                  # MCP gateway on :4100
pnpm --filter @veto/dashboard dev                  # dashboard on :3000
pnpm --filter @veto/identity invite -- --subject "oidc|<from the auth log>" --workspace "Name"
```

Every entry point loads the repo-root `.env`, with anything already set in the
environment winning over the file.

`db`, `identity` and `api` tests need a live Postgres and Redis and read `DATABASE_URL`
and `REDIS_URL` from `.env` (gitignored; see `.env.example`). They run with
`fileParallelism: false` and pin `NODE_ENV=test` — the Permit fake refuses to construct
outside a test env, and the app `.env` sets `NODE_ENV=development`.

### Layout

| Package | Holds |
| --- | --- |
| `packages/core` | Branded ids, the 25 reason codes, action digest. No I/O. |
| `packages/db` | Pool, `withWorkspace`, migration runner, `migrations/*.sql` |
| `packages/permit` | `PolicyFacts` and `PolicyDecisions` ports, real adapters, and test fakes |
| `packages/identity` | Agent registration, revocation, sessions, audit writer |
| `packages/tokens` | Short-lived internal capability tokens. HMAC, no algorithm field. |
| `packages/decisions` | The §3.3 pipeline. Decides; never executes. |
| `packages/vault` | Envelope encryption. The encryption context is a tenant boundary. |
| `packages/connections` | Credential vault and broker. Never returns a refresh token. |
| `apps/api` | Fastify control plane (§5). Manages objects; not an enforcement point. |
| `apps/gateway` | **The** MCP enforcement point (§3.1). Calls the pipeline in process. |
| `apps/dashboard` | Next.js dashboard. Theme matches vetoprotocol.live; dark only. |

Sign-in is OIDC against any conformant provider (`docs/auth-setup.md`). There is
**no auto-provisioning**: an unknown subject is refused, and membership is
inserted by hand until an invitation flow exists.

### Conventions this repo already commits to

- **Relative imports carry `.ts` extensions**, not `.js`. `node --experimental-strip-types`
  cannot resolve `.js` specifiers, and `allowImportingTsExtensions` is on.
- **No TypeScript parameter properties.** `node --experimental-strip-types` only
  erases types, and a parameter property emits an assignment, so such a file compiles
  under vitest and then fails whenever anything runs it directly. Assign fields in the
  constructor body instead.
- **`pg` is CommonJS.** `import pg from 'pg'; const { Pool } = pg;` — a named ESM import
  fails at runtime, not at typecheck.
- **Every tenant-scoped query runs inside `withWorkspace()`**, which sets
  `veto.workspace_id` transaction-locally. Session scope would leak across pooled
  checkouts. RLS is `FORCE`d because the `veto` role owns the tables.
- **Migrations are immutable once applied.** The runner records a checksum and refuses
  to run if an applied file changed on disk. Write a new migration instead.
- **Audit events take a typed input that cannot carry content** — no body, token or
  challenge field exists on `AuditEventInput`. That type is the control (invariant 5).
- **Migration 0007 widens invariant 4, deliberately.** `resolve_identity_subject()`
  reads `users` across tenants because sign-in must find the workspace before it can
  scope to one. It takes one exact subject, returns two columns, filters to active
  users, and is SELECT-only. Do not extend it.
- **The vault never returns a refresh token.** `Connection` has no field that could
  carry one; the broker hands back a short-lived access token instead. Keep it
  unrepresentable rather than remembering not to.
- **The pipeline decides and never fetches.** Step 8 lives in
  `apps/gateway/src/execute.ts`, downstream of the decision — the pipeline returns
  `allow` and something else acts on it.
- **Retrieved content never reaches the authorization path.** Whatever a model does
  after reading a poisoned file arrives as a new tool call and gets a new decision.
  Never feed a tool response back into normalization, policy, or the digest.
- **Every route asserts its credential scope** (`requireScope`). A sign-in credential
  cannot reach the agent routes and vice versa.
- New HTTP routes get a closed request schema (`additionalProperties: false`) and a
  response schema. Fastify's AJV defaults (`removeAdditional`, `coerceTypes`) are
  disabled in `createApp` — do not re-enable them.

### Open items

- `docs/threat-model.md` §8 was signed off and the owner accepted the four residual
  risks on 2026-09-18, which lifted the §16 gate on storing credentials. Acceptance
  covers those four as written; a new trust boundary or a second cross-tenant read
  brings the document back for review.
- **The local key wrapper is not a KMS.** `VAULT_MASTER_KEY` sits in the process
  environment, so anything that can read the environment can unwrap every data key.
  Production swaps the `KeyWrapper` implementation, not its callers.
- **A local PDP is required in production.** The hosted PDP was measured at min 211 ms,
  p50 ~225 ms, p95 293–739 ms per check — the fastest single check exceeds the whole
  §11 200 ms P95 budget. There is no container runtime on this machine, so development
  runs against hosted and accepts the latency. See `docs/permit-setup.md`.
- Permit principal keys are `agent|{id}` / `human|{id}`, not §4.2's `agent:{id}` —
  Permit rejects colons in user keys. `packages/permit/src/model.ts` explains.
- `packages/db/migrations/0002` carries a stale comment about burning a revoked
  `client_id`; `0006` replaced that constraint and explains why.

## What we're building

A **continuous-consent authorization gateway** between AI agents/clients and connected
applications (Google Workspace + MCP clients for the MVP). Every protected action is
**allowed, challenged (passkey step-up), or denied** based on user policy, presence
state, and risk signals.

Correctness of authorization *is* the product. A wrong `allow` is a security incident,
not a bug.

## Architecture: the one flow that matters

Everything in the system exists to serve the decision pipeline in §3.3. Understand this
before writing any component:

```
AI client/agent --MCP or HTTPS--> Veto Gateway --> Credential broker --> Google Workspace
                                       |
             identity · presence · Permit decision · risk · approval · audit
```

The ordered pipeline for every protected request:

1. Authenticate client; resolve **human + tenant + agent** identities.
2. Normalize into action, resource, arguments, declared intent, destination.
3. Check session status, presence state, expiry, **emergency lock**.
4. Deterministic prechecks — tool allowlist, resource scope, rate, volume.
5. `permit.check` — the relationship/attribute decision, and **only** that.
6. Veto-side risk checks Permit cannot express — intent mismatch, sensitive argument
   inspection, SSRF/destination checks, transaction simulation.
7. Emit `allow` / `deny` / `challenge`.
8. On allow: mint the **narrowest** upstream token and call upstream.
9. Write the audit event — no secrets, no full document content.

Steps 3, 4, and 6 are Veto's own authority and must sit **outside** Permit. A component
that skips its pipeline position is a security defect regardless of test results.

### Service boundaries (§3.2)

Gateway (enforcement point, fails closed) · Identity · Policy adapter (Permit keys stay
server-side) · Presence (a *signal*, never proof of intent) · Approval (approver must
match the original delegator) · Credential vault (never returns root credentials) ·
Risk engine (deterministic controls override model recommendations) · Audit
(append-only) · Web3 adapter (signer separate from policy authority).

### Decision semantics (§5.3) — the three results are not interchangeable

| Result | Gateway behavior |
| --- | --- |
| `allow` | Forward *exactly* the approved operation and resource — no widening |
| `deny` | Never contact upstream; return a stable reason code |
| `challenge` | Pause/reject safely; resume only with an unexpired, single-use grant |

Every decision carries a `reason_code` and a human-readable message. Define reason codes
*before* building approval screens (§16).

### Key contracts

- **Veto-owned API** (§5): `/v1/agents`, `/v1/connections/google`, `/v1/policies`,
  `/v1/decisions/evaluate`, `/v1/approvals[/{id}/resolve]`, `/v1/presence`,
  `/v1/emergency-lock`, `/v1/audit-events`. These are Veto endpoints, not Permit ones.
- **Data model** (§6): Workspace, User, Agent, Connection, Policy, Presence, Session,
  Decision, Approval, Audit event. Note `Decision` records *both* `permit_result` and
  `veto_result` — they are distinct and both are audited.
- **Presence states** (§7.2): `active` (allow low-risk in scope) · `away` (challenge
  sensitive reads and all writes) · `locked` (deny all) · `automation` (only the named
  workflow/tools/resources/limits). Never infer presence from IP or geolocation alone.
- **Webhooks** (§5.4): `decision.denied`, `approval.requested`, `approval.resolved`,
  `agent.revoked`, `workspace.locked`, `connection.expired`, `credential.revoked`,
  `risk.anomaly_detected`.

## Stack (§3.4 — fixed, do not substitute)

TypeScript + Node.js · **Fastify** gateway (streamable HTTP, strict JSON-RPC validation,
strict timeouts) · **Next.js** dashboard/consent/approvals/admin · **PostgreSQL**
(durable) + **Redis** (nonce, challenge, rate, session coordination) · **Permit.io**
PDP + Cloud API as the decision engine — do not rebuild it · **OIDC + WebAuthn**
(passkeys) · **Cloud KMS** envelope encryption, separate encryption context per tenant ·
**OpenTelemetry** (never log credentials or protected content) · **viem + ERC-4337**
(deferred until core SaaS authz is stable).

## Non-negotiable invariants — never violate these

1. **Fail closed.** Missing identity, unavailable Permit decision, invalid token,
   malformed action, or emergency lock → deny. No degraded "allow".
2. **Deny by default.** Deterministic allow/deny ships before any anomaly detection.
3. **Permit is not the sole authority.** Emergency lock, credential expiry, argument
   inspection, transaction simulation, and prompt-injection checks run in Veto, before
   and/or after `permit.check` — never inside Permit alone.
4. **Tenant isolation everywhere.** Every query, cache key, encryption context, and
   policy fact is scoped by `workspace_id`. Assume cross-tenant tests will run.
5. **No secrets or protected content in logs or audit events.** Not refresh tokens,
   auth headers, document bodies, or passkey challenges.
6. **Approvals are single-use and bound to the exact action digest.** A changed argument
   set requires a new approval. Reject replayed or expired approvals.
7. **Only the original delegating user can approve their challenge.**
8. **The gateway is the only enforcement point.** Return only Veto-controlled URLs to
   clients. Never claim to protect credentials granted directly to another provider.
9. **Authorize at `call_tool` time**, even for previously listed tools. Validate tool
   arguments against a strict schema before policy evaluation.
10. **Never accept credentials via prompts or tool arguments.**

## Build order (§13) — do not build ahead of it

1. Threat model, schemas, identity model, Permit environment, basic dashboard
   → exit: human + agent identities can be modeled and revoked.
2. MCP gateway + Permit checks + Google Drive connection → exit: allow/deny end to end.
3. Presence states + passkey challenge + audit timeline → exit: away-state sensitive
   action requires correct user approval.
4. Gmail + Calendar read + alerts + emergency lock → exit: revocation across all sessions.
5. Adversarial testing + observability + docs → exit: security acceptance tests pass.
6. Pilot with design partners → exit: 5+ active integrations, no critical findings.

## Testing bar

Write the **adversarial tests in §12.1 before** the features they target. A milestone is
not done until its attack tests pass:

- Email instructs the agent to search Drive for tax records (indirect prompt injection)
- Agent authorized for one file requests the whole folder
- Approved action replayed after expiry
- Blocked bulk request split into many small requests
- Approval link opened by a different user
- Emergency lock during an active session
- Permit unavailable during a sensitive request
- Request targets a private / metadata network address (SSRF)

Also cover OAuth CSRF, token replay, IDOR, and cross-tenant access. Test groups per §12:
unit (normalization, reason codes, action digests, expiry, state transitions) · contract
(Permit SDK, Google token lifecycle, MCP schemas, webhook signatures) · integration
(client → gateway → Permit → Google across all three results) · security · resilience
(Permit timeout, Redis loss, DB failover, upstream rate limit, duplicate events).
Security tests are first-class, not optional.

## Conventions

- OAuth: PKCE + exact redirect URI validation, incremental/narrowest scopes. Do not
  request Gmail + Drive + Calendar together before the user activates each.
- Internal service calls use short-lived capability tokens carrying audience, resource,
  action, expiry, nonce, human, and agent claims.
- One correlation id spans request → Permit decision → approval → upstream call → audit.
- Webhooks: HMAC signatures, timestamp tolerance, replay protection, event ids,
  exponential-backoff retry, idempotent consumers.
- Rate limits are availability controls — never a substitute for authorization.
- Performance target: authz overhead P95 < 200 ms (excludes human approval + upstream).
- Revocation takes effect on the next protected request, targeted within five seconds.
- Separate Permit environments with separate keys for dev / staging / production.

## Out of scope for the MVP — do not build

- Utility/transferable token, staking, decentralized operators
- General-purpose AI model hosting
- Broad write or destructive actions at launch (reads first)
- Public onchain storage of private access logs
- Continuous biometric surveillance
- The Robinhood Chain / ERC-4337 PoC is **design-ready but must not delay the MVP** —
  do not start it until core SaaS authorization is stable.

## When in doubt

Prefer the more restrictive behavior, surface the ambiguity in a comment or PR note, and
do not invent policy semantics that aren't in `veto-protocol-spec.md`. External API
references live in §15 — use them rather than recalling API shapes from memory.
