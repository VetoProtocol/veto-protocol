# Veto Protocol

A continuous-consent authorization gateway that sits between AI agents and the
accounts they act on.

An MCP client asks to read a file. Veto decides — **allow**, **challenge**, or
**deny** — then either forwards exactly that operation or returns a reason code.
Nothing reaches Google Workspace that was not decided on first.

> Correctness of authorization *is* the product. A wrong `allow` is a security
> incident, not a bug.

---

## The problem

You connect an AI agent to your Google account. It gets a token. The token is
broad, long-lived, and from that moment the agent can do anything the token
permits, whenever it likes, whether or not you are there.

Most systems stop at "the user consented once." Veto treats consent as something
that has to still be true at the moment of the action.

## What it does instead

| | |
| --- | --- |
| **Every call is authorized** | Not just the connection. Not just the first call. Each `call_tool`, at call time, even for a tool that was listed and allowed a second ago. |
| **Presence narrows permission** | `active` allows low-risk work in scope. `away` makes sensitive reads and every write wait for your approval. `locked` denies everything. One switch, no policy rewriting. |
| **Approvals need a passkey** | A challenge is resolved by a WebAuthn assertion over *that approval's own* stored challenge. Single-use, bound to the exact action. Change one argument and you need a new approval. |
| **Revocation reaches backwards** | A lock or an agent revocation kills outstanding approvals and live sessions, not only future requests. Unlocking does not give back what the lock took. |
| **The audit log is tamper-evident** | Each event is hashed with its predecessor. Remove or edit a row and the chain check turns red. Names only — never a document body, token, or challenge. |
| **Two engines must agree** | Permit.io answers *whether the agent is connected to the resource at all*. Veto answers *under what conditions*, and can only narrow. Neither derives the other. |

---

## The one flow that matters

Everything in this repository exists to serve one ordered pipeline. Every
protected request runs all nine steps, in order:

```
AI client/agent --MCP--> Veto Gateway --> Credential broker --> Google Workspace
                              |
       identity · presence · Permit decision · risk · approval · audit
```

1. Authenticate the client; resolve **human + tenant + agent**.
2. Normalize into action, resource, arguments, declared intent, destination.
3. Check session status, presence, expiry, **emergency lock**.
4. Deterministic prechecks — tool allowlist, resource scope, rate, volume.
5. `permit.check` — the relationship decision, and **only** that.
6. Veto-side risk checks Permit cannot express — intent mismatch, argument
   inspection, SSRF/destination checks.
7. Emit `allow` / `deny` / `challenge`.
8. On allow: mint the **narrowest** upstream token and call upstream.
9. Write the audit event.

Steps 3, 4 and 6 are Veto's own authority and sit deliberately **outside** the
policy engine. A component that skips its position in this pipeline is a
security defect regardless of what its tests say.

The pipeline decides and never fetches. Step 8 lives downstream of the decision,
in `apps/gateway/src/execute.ts`, so that a retrieved document can never reach
the authorization path. Whatever a model does after reading a poisoned file
arrives as a new tool call and gets a new decision.

---

## Invariants

These are not guidelines. Code that violates one is wrong even if it passes.

1. **Fail closed.** Missing identity, unavailable policy decision, invalid
   token, malformed action, or emergency lock → deny. There is no degraded
   "allow".
2. **Deny by default.** A workspace with no rules refuses everything.
3. **The policy engine is not the sole authority.** Emergency lock, credential
   expiry, argument inspection and injection checks run in Veto.
4. **Tenant isolation everywhere.** Every query, cache key, and encryption
   context is scoped by `workspace_id`. Postgres row-level security is `FORCE`d,
   because the application role owns the tables.
5. **No secrets or protected content in logs or audit events.** The audit event
   type has no field that could carry a body, a token, or a challenge. The type
   is the control.
6. **Approvals are single-use and bound to an exact action digest.**
7. **Only the original delegating user can approve their own challenge.**
8. **The gateway is the only enforcement point.**
9. **Authorize at `call_tool` time**, against a strict argument schema.
10. **Never accept credentials via prompts or tool arguments.**

---

## Layout

A pnpm workspace. Packages hold the rules; apps hold the I/O.

| Package | Holds |
| --- | --- |
| `packages/core` | Branded ids, the reason codes, the action digest. No I/O. |
| `packages/db` | Pool, `withWorkspace`, migration runner, SQL migrations |
| `packages/permit` | Policy ports, real adapters, and test fakes |
| `packages/identity` | Agent registration, revocation, sessions, audit writer |
| `packages/tokens` | Short-lived internal capability tokens |
| `packages/decisions` | The pipeline and sensitivity labels. Decides; never executes. |
| `packages/vault` | Envelope encryption. The encryption context is a tenant boundary. |
| `packages/connections` | Credential vault and broker. Never returns a refresh token. |
| `packages/presence` | The presence state machine. A signal, never proof of intent. |
| `packages/webhooks` | Alerts. Enqueue is transactional; delivery is a worker. |
| `packages/passkeys` | WebAuthn enrolment and assertion. Public keys only. |
| `packages/health` | Startup probes. Reachability only — never validates a credential. |
| `apps/api` | Fastify control plane. Manages objects; not an enforcement point. |
| `apps/gateway` | **The** MCP enforcement point. Calls the pipeline in process. |
| `apps/dashboard` | Next.js dashboard: agents, policies, connections, presence, approvals, audit, alerts. |

---

## Running it

Needs Node 22+, pnpm, PostgreSQL, Redis, and a Permit.io PDP.

```bash
pnpm install
cp .env.example .env          # then fill it in
pnpm --filter @veto/db migrate
```

Run the three services, each in its own terminal:

```bash
pnpm --filter @veto/api start        # control plane on :4000
pnpm --filter @veto/gateway start    # MCP gateway on :4100
pnpm --filter @veto/dashboard dev    # dashboard on :3000
```

**Run the policy decision point locally.** Hosted was measured at p50 ~225 ms
per check, which alone exceeds the whole 200 ms authorization budget, and
roughly one call in four hit the timeout and failed closed. Local measures p50
6.8 ms. See `docs/permit-setup.md`.

```bash
podman run -p 7766:7000 -e PDP_API_KEY=... permitio/pdp-v2
```

### Checks

```bash
pnpm -r typecheck     # tsc --noEmit everywhere
pnpm lint             # no-explicit-any and no-non-null-assertion are errors
pnpm -r test          # all packages
pnpm verify           # all three
```

The `db`, `identity` and `api` suites need a live Postgres and Redis.

---

## Testing

Adversarial tests are written **before** the features they target. A milestone
is not done until its attack tests pass. Among those covered:

- An email instructs the agent to go and search Drive for tax records
  (indirect prompt injection — tested with a real poisoned email)
- An agent authorized for one file asks for the whole folder
- An approved action replayed after expiry
- A blocked bulk request split into many small ones
- An approval link opened by a different user
- An emergency lock thrown during an active session
- The policy engine unavailable during a sensitive request
- A request aimed at a private or cloud-metadata address (SSRF)

Plus OAuth CSRF, token replay, IDOR, and cross-tenant access. Security tests are
first-class, not optional.

---

## Documentation

| Document | Covers |
| --- | --- |
| `CLAUDE.md` | Repository state, conventions, and the reasoning behind decisions that look arbitrary |
| `docs/deploy.md` | Deploying to a server |
| `docs/permit-setup.md` | The policy decision point, and why it runs locally |
| `docs/google-setup.md` | Google Cloud console configuration |
| `docs/grants.md` | Why a grant and a rule are deliberately not derived from each other |
| `docs/webhooks.md` | The eight alert events, signing, and retry |
| `docs/threat-model.md` | Trust boundaries and accepted residual risks |

---

## Status

Reads only, across Drive, Gmail and Calendar. No send tool, no create or update
tool, and no OAuth scope for either — a write path is a new trust boundary, and
the threat model that was signed off covers a system that only reads.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
