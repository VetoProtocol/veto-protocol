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

The v1.0 developer specification is authoritative and is **not kept in this
repository**. Section references (§3.3, §12.1) point into it. Everything
below is derived from it; when this file and the spec disagree, **the spec wins**.
Section references (§3.3, §12.1) point there. An older version of this file called it
`SPEC.md` — that filename does not exist.

**Stage 1 is done.** Identities can be modelled and revoked, over HTTP, behind OIDC
sign-in, with tenant isolation enforced in three places.

**Stage 2 is done.** Allow/deny works end to end: an MCP client asks for a Drive
file, the nine-step pipeline decides, and either the file comes back or a reason
code does. All twelve §12.1 adversarial scenarios are implemented
(`packages/core/src/adversarial.ts`).

**Stage 3 is done.** Presence is a real state machine, approvals require a WebAuthn
assertion over the approval's own challenge, the audit timeline is readable and
independently verifiable, and all four are usable in the browser.

The Google connect flow is complete in the browser: `/connections` runs PKCE and
the state cookie, the API builds the consent URL and exchanges the code, and
`docs/google-setup.md` covers the console side.

**Stage 4 is done.** Revocation reaches everything it should — a lock or an
agent revocation kills outstanding grants and live sessions, not only future
requests (`packages/decisions/src/revocation.ts`). All eight §5.4 webhook events
are emitted, delivered, retried and manageable from `/alerts`
(`docs/webhooks.md`). Gmail and Calendar are read-only and live. The §13 exit
condition — revocation across all sessions — is asserted in
`apps/gateway/test/revocation.test.ts`.

`/v1/policies` and its dashboard screen exist. Until stage 4 they did not, and
the only way to write a rule was raw SQL — the engine was tested and the door
was missing. Deny-by-default hid it: a workspace with no rules refuses
everything, which looks identical to working correctly.

`/v1/grants` closes the other half. Permit now has a `reader` role, and granting
an agent a folder or file flips a real `permit.check` from deny to allow —
verified against the hosted PDP, not only the fake. See `docs/grants.md` for why
a grant and a rule are deliberately not derived from each other.

Gmail and Calendar are read-only and live. Four tools —
`google_gmail.search_messages`, `google_gmail.read_message`,
`google_calendar.list_events`, `google_calendar.read_event` — with one
`gmail_mailbox` and one `google_calendar` resource per human. No send tool, no
create or update tool, and no scope for either. §12.1's first scenario is now
tested with an actual poisoned email rather than a Drive file standing in.

**Passkeys work in the browser, enrolment included.** `EnrolPasskey` and
`ResolveApproval` are both on `/approvals`, and `tools/e2e/passkey-enrol.ts`
drives them with a Chromium virtual authenticator: enrol, get challenged by an
away-state read, resolve with a signature over that approval's own challenge.
§13 stage 3's exit condition, verified end to end rather than in parts. Three
earlier notes here said enrolment had no browser half; it had one all along.

**Webhook delivery is scheduled.** The API starts a five-second loop
(`@veto/webhooks/scheduler`, off with `WEBHOOK_SCHEDULER=off`). Every instance
runs one: `drainDeliveries` claims rows `for update skip locked`, so two split
the queue rather than both sending an event. The `/alerts` button stays as an
explicit trigger. Finding which workspaces have work is the **second**
deliberate cross-tenant read — `due_delivery_workspaces()`, migrations 0018 and
0019 — and `security definer` alone was not enough, because `FORCE` row-level
security applies to the table owner too.

**Folder grants inherit.** `POST /v1/grants/sync` walks a folder with the
workspace's own Google credential and writes a `parent` tuple per child, so one
grant on a folder reaches every file and subfolder beneath it — verified against
the hosted PDP, two levels deep, on a real Drive. Bounded by depth, entry count
and a cycle guard (`apps/api/src/hierarchy.ts`), and it reports `truncated`
rather than quietly stopping. One known gap remains inside what is built: Permit
resource-instance keys must match `^[A-Za-z0-9\-_]+$`, which real Drive ids do
and the repo's path-shaped test fixtures do not.

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
curl -XPOST localhost:4000/v1/webhooks/drain -H "authorization: Bearer $TOK" -d '{}'  # deliver queued alerts
curl -XPOST localhost:4000/v1/grants/sync -H "authorization: Bearer $TOK" -d '{"folder_id":"root"}'  # teach Permit where files live
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
| `packages/decisions` | The §3.3 pipeline and sensitivity labels. Decides; never executes. |
| `packages/vault` | Envelope encryption. The encryption context is a tenant boundary. |
| `packages/connections` | Credential vault and broker. Never returns a refresh token. |
| `packages/presence` | §7.2 state machine. A signal, never proof of intent. |
| `packages/webhooks` | §5.4 alerts. Enqueue is transactional; delivery is a worker. |
| `packages/passkeys` | WebAuthn enrolment and assertion. Public keys only. |
| `packages/health` | Startup probes. Reachability only — never validates a credential. |
| `apps/api` | Fastify control plane (§5). Manages objects; not an enforcement point. |
| `apps/gateway` | **The** MCP enforcement point (§3.1). Calls the pipeline in process. |
| `apps/dashboard` | Next.js dashboard: agents, policies, connections, presence, labels, approvals, audit, alerts. Dark only. |

Sign-in is OIDC against any conformant provider (`docs/auth-setup.md`).

**Signing up and being let in are different things** (`docs/signup.md`). A
verified subject nobody knows is offered a **personal** workspace of their own —
§1.3's individual professional, whose first release is a "self-service dashboard
and personal policies". Joining an *existing* workspace is never automatic:
`provisionPersonalWorkspace` refuses any subject that already belongs anywhere,
and the request has no field in which to name a tenant. Invitations stay an
operator action (`inviteSubject`).

An earlier version of this file said there was "no auto-provisioning" and
justified it on security grounds. That was an implementation shortcut described
as a principle — the schema has carried `type in ('personal','organization')`
since migration 0001 and nothing created the first kind until stage 4.

### Conventions this repo already commits to

- **Relative imports carry `.ts` extensions**, not `.js`. `node --experimental-strip-types`
  cannot resolve `.js` specifiers, and `allowImportingTsExtensions` is on.
- **No TypeScript parameter properties.** `node --experimental-strip-types` only
  erases types, and a parameter property emits an assignment, so such a file compiles
  under vitest and then fails whenever anything runs it directly. Assign fields in the
  constructor body instead.
- **Every service reports what it can reach before it serves a request.**
  `@veto/health` probes Postgres, Redis, the PDP and Google's token endpoint at
  boot and logs one line each. Only Postgres is fatal — invariant 1 is fail
  closed at request time, not refuse to boot, and a gateway that will not start
  cannot be restarted into a recovering system. A probe answers "can this be
  reached" and never "is this key valid": validating a credential means using a
  real secret on a path whose whole output is a log line.
- **Every entry point that leaves the machine prefers IPv4 and does not race
  IPv6.** `--dns-result-order=ipv4first --no-network-family-autoselection`, in
  the `start` scripts of `apps/api`, `apps/gateway` and `apps/dashboard`. Node
  races both address families by default; on a host whose IPv6 route to Google
  is black-holed it keeps choosing the dead one, and roughly two calls in three
  fail with `ETIMEDOUT` after a second or two. What reaches the user is
  `CONNECTION_EXPIRED` — "the connected account could not be used" — which reads
  as a credential problem and is not one. `curl` does not race, which is why
  every hand-run check looks healthy. Do not remove these flags because the
  network looks fine today.
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
- **The consent URL is built by the API, never by the dashboard.** The process
  that assembles it is the one that exchanges the code, and Google requires
  `redirect_uri` to match across both — so there is only one copy of it. The
  dashboard supplies `state` and `code_challenge`, keeps the PKCE verifier in a
  signed five-minute cookie, and never holds the client secret. `ConsentConfig`
  is the narrowed type that crosses that line.
- **The connect cookie is domain-separated from the sign-in cookie.** Both are
  signed with `DASHBOARD_SESSION_SECRET`, but one ends in a session and the
  other in a stored credential, so a value minted for either must not satisfy
  the other. `packages`-style reuse would have made them interchangeable.
- **The vault never returns a refresh token.** `Connection` has no field that could
  carry one; the broker hands back a short-lived access token instead. Keep it
  unrepresentable rather than remembering not to.
- **The pipeline decides and never fetches.** Step 8 lives in
  `apps/gateway/src/execute.ts`, downstream of the decision — the pipeline returns
  `allow` and something else acts on it.
- **An approval is resolved only by a passkey assertion over that approval's stored
  challenge.** Not a fresh challenge, not one the client chose. A user with no
  enrolled passkey cannot resolve anything — that is a refusal, not a fallback.
- **A grant and a rule answer different questions, and neither derives the
  other.** Permit says whether the agent is connected to the resource at all and
  its answer inherits; Veto says under what conditions, and its answer can only
  narrow. If a rule wrote its own grant, Permit would agree with Veto by
  construction and invariant 3's second opinion would be a mirror.
- **A file's parent comes from Drive, never from a caller.** `POST /v1/grants/sync`
  walks the folder over the workspace's own credential and writes the `parent`
  tuples Permit derives from. An agent able to assert "this file's parent is the
  folder you granted me" could read any file in Drive by saying so — privilege
  escalation by argument, the same shape invariant 10 refuses for credentials.
  The walk is bounded and off the decision path: it writes where things are, not
  who may read them, so an edge under a folder nobody was granted reaches nobody.
- **Permit resource-instance keys are `^[A-Za-z0-9\-_]+$`.** Real Drive ids fit;
  paths do not. `/v1/grants` enforces it so the failure is a 400 that explains
  itself rather than an upstream 422. Same shape of surprise as `agent|` in
  `model.ts` — the API's grammar is narrower than §4.2's examples.
- **A rule outside its time window does not match; it does not deny.** FR-06's
  time dimension is a `schedule` condition read in the workspace's own IANA zone
  (`workspaces.timezone`, migration 0020). Narrowing by non-match is what makes
  it compose with precedence — a windowed `deny` still outranks an `allow` while
  open, and stops mattering when shut — and it needs no twenty-sixth reason
  code, because "every rule's window is shut" genuinely is `TOOL_NOT_ALLOWED`.
  A malformed or unreadable window is treated as shut: a broken rule must
  narrow, never widen.
- **Policy rules are created and deleted, never edited.** Every decision records
  the `policy_version` that produced it, so editing a rule in place would leave
  old decisions pointing at a version whose text has since changed. Each rule
  gets its own version at creation.
- **A grant must not outlive the authority it was granted under.** A lock or an
  agent revocation moves outstanding approvals to `revoked` — a distinct status
  from `expired`, because "nobody acted in time" and "somebody pulled the plug"
  are different facts and a revoked grant keeps its `resolved_at`. Unlocking is
  not the inverse: killed grants stay killed.
- **A webhook is enqueued in the caller's transaction and never sent from it.**
  An event cannot exist for something that rolled back, and a receiver that
  hangs cannot spend the §11 200 ms budget. `@veto/webhooks` sits below
  `@veto/decisions` in the graph, so the SSRF check arrives as a port rather
  than an import.
- **A sensitivity label can only narrow an answer.** `public` is not permission: a
  resource no rule allows stays denied whatever it is labelled. Labels add a presence
  or intent requirement on top of a rule; they never grant. Most specific wins, and
  specificity is longest match.
- **Presence can only narrow an answer.** It never grants; a policy names which
  states allow, absence means `away`, and a source cannot assert more assurance than
  it can witness. There is no field anywhere for an IP address or a location.
- **A mail or calendar tool's resource is the session's human, never an
  argument.** The mailbox and the calendar belong to the delegating user and are
  read from `GatewaySession`, so there is no field an agent could put somebody
  else's id in. The message or event id stays in `arguments`, where the digest
  covers it.
- **A bounded read is bounded in step 8, not only in the schema.** A schema can
  check that two timestamps are timestamps; only `execute.ts` can check that
  they are not two years apart. `MAX_WINDOW_DAYS` is the calendar's version of
  a volume limit.
- **A `'use server'` module may export only async functions.** Every export
  becomes a callable endpoint, so a constant beside the actions is refused at
  runtime — `next build` does not catch it, and the page fails on first render.
  Shared state types live in their own file (`action-state.ts`, `alerts/state.ts`)
  and `test/use-server.test.ts` is the guard.
- **The gateway's AJV runs `strict: true` with no format vocabulary.** A
  `format` keyword throws at schema-compile time rather than validating
  anything, so tool schemas use `pattern` — see `RFC3339` in `tools.ts`.
- **Step 8 mints per *tool*, not per connection.** An account that has activated
  both Drive and Gmail still gets a Drive-only token for a Drive read
  (`SCOPE_FOR_TOOL` in `apps/gateway/src/execute.ts`).
- **Retrieved content never reaches the authorization path.** Whatever a model does
  after reading a poisoned file arrives as a new tool call and gets a new decision.
  Never feed a tool response back into normalization, policy, or the digest.
- **Every route asserts its credential scope** (`requireScope`). A sign-in credential
  cannot reach the agent routes and vice versa.
- New HTTP routes get a closed request schema (`additionalProperties: false`) and a
  response schema. Fastify's AJV defaults (`removeAdditional`, `coerceTypes`) are
  disabled in `createApp` — do not re-enable them. Query parameters are therefore
  declared as strings and converted in the handler; see `routes/audit.ts`.

### Open items

- `docs/threat-model.md` §8 was signed off and the owner accepted the four residual
  risks on 2026-09-18, which lifted the §16 gate on storing credentials. Acceptance
  covers those four as written; a new trust boundary or a second cross-tenant read
  brings the document back for review.
- **§9 is reviewed and not yet accepted.** The §8 authorization server added
  Boundary 6 — an anonymous caller who can register a client and begin an
  authorization — which is exactly the trigger above. The technical review is done
  (T18–T27, each naming its test) and four further residual risks are written up.
  **The owner's acceptance is outstanding**, and the four are: registration is open
  by necessity, a client may call itself anything, `oauth-server` is a
  tenant-unbounded credential inside T6, and nothing has been established outside
  this machine.
- **The local key wrapper is not a KMS.** `VAULT_MASTER_KEY` sits in the process
  environment, so anything that can read the environment can unwrap every data key.
  Production swaps the `KeyWrapper` implementation, not its callers.
- **The PDP runs locally, and must.** Hosted was measured at min 211 ms, p50 ~225 ms,
  p95 293–739 ms per check — the fastest single check exceeded the whole §11 200 ms
  P95 budget, and roughly one call in four hit the 5 s ceiling and failed closed with
  `POLICY_UNAVAILABLE`. Local (`podman`, `permitio/pdp-v2`, host port 7766) measures
  p50 6.8 ms / p95 8.9 ms, and authorization overhead on a real gateway call went from
  ~1967 ms average to ~11 ms. An earlier note here said there was no container runtime
  on this machine; Podman was already installed and nobody had checked. See
  `docs/permit-setup.md`.
- **`latency_ms` on a `decisions` row is steps 1–7 only.** The pipeline decides and
  never fetches, so the upstream call is not in that number. It is the §11 figure
  directly, not an end-to-end one.
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
- Broad write or destructive actions at launch (reads first). `docs/writes-plan.md`
  is a **plan, not a licence**: §13's twelve weeks are read-only end to end, so
  building it needs the spec amended or the deferral made explicit, and the
  threat model re-opened — a write path is a new trust boundary and the §8
  sign-off covered a system that only reads.
- Public onchain storage of private access logs
- Continuous biometric surveillance
- The Robinhood Chain / ERC-4337 PoC is **design-ready but must not delay the MVP** —
  do not start it until core SaaS authorization is stable.

## When in doubt

Prefer the more restrictive behavior, surface the ambiguity in a comment or PR note, and
do not invent policy semantics that aren't in the specification. External API
references live in §15 — use them rather than recalling API shapes from memory.
