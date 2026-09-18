# Stage 2 plan — MCP gateway, Google Drive, allow/deny end to end

**Exit condition (§13):** a real AI client asks to read a Drive file, Veto
decides, and either it happens or it does not with a stable reason code.

Read `enforcement.md` first for why none of this exists yet.

## Scope

In:

- MCP gateway as a separate service — the only enforcement point (invariant 8)
- OAuth 2.1 client identity for MCP, binding each session to a human and agent
- Google OAuth connection, Drive read only, tokens in a credential vault
- The §4.2 Permit policy model for Drive resources, and `permit.check` at step 5
- Pipeline steps 2–9, including the controls Permit must not own (invariant 3)
- Decisions and approvals persisted and audited

Out, deliberately:

- Gmail and Calendar (§9.1: do not request scopes before the integration exists)
- Any write or destructive action — reads first
- Passkey challenge ceremony. Stage 2 emits `challenge` and records the
  approval; **stage 3** builds WebAuthn and the approval UI
- Presence beyond a stored state. The state machine is stage 3
- Web3 anything

## Blocker to clear first

§16 gates storing production credentials on a completed threat-model review, and
phase 4 below stores Google refresh tokens. `docs/threat-model.md` §8 is
unticked. **Phases 0–3 can proceed; phase 4 cannot start until it is signed off.**

## Phases

### Phase 0 — Threat model review and sign-off

Walk §7.3 and §12.1 against what stage 1 actually built, correct what has
changed since it was written (migration 0007 widened invariant 4; the hosted-PDP
latency finding), and tick §8. Nothing else is blocked by it, and everything
after phase 3 is.

**Exit:** signed-off threat model, with the stage-1 deltas recorded.

**Done 2026-09-18**, except the owner's acceptance of residual risk (§8.1) —
four items, listed there, that are not the implementer's call to make.

### Phase 1 — Adversarial tests first

Write the §12.1 scenarios as failing tests before the features they target,
which CLAUDE.md requires and which is cheapest to do while there is no code to
retrofit them to.

| Scenario | Proves |
| --- | --- |
| Email tells the agent to search Drive for tax records | Indirect prompt injection — retrieved content is hostile input, and the model never self-approves |
| Agent authorized for one file requests the folder | Scope widening between decision and upstream call |
| Approved action replayed after expiry | Single-use, time-bound approvals |
| Blocked bulk request split into many small ones | Volume limits across a window, not per request |
| Approval link opened by a different user | Only the original delegator may approve (invariant 7) |
| Emergency lock during an active session | Lock beats an in-flight session |
| Permit unavailable during a sensitive request | Fail closed, `POLICY_UNAVAILABLE`, never a degraded allow |
| Request targets a private or metadata address | SSRF on the destination check |

Plus the standing four: OAuth CSRF, token replay, IDOR, cross-tenant.

**Exit:** all red, each naming the pipeline step it exercises.

**Registry done 2026-09-18**: `packages/core/src/adversarial.ts` holds all twelve
scenarios with the threat each maps to, the pipeline step it exercises, and —
the important field — what the test must actually assert. Four are already
green from stage 1; the eight §12.1 scenarios are pending and stage 2 closes
them. A test reads the count of §12.1 bullets out of the spec itself, so an
amended spec fails the build rather than leaving us quietly under-covered.

### Phase 2 — The gateway skeleton

New `apps/gateway`. Fastify, streamable HTTP, strict JSON-RPC validation, strict
timeouts (§3.4). MCP OAuth 2.1 discovery and protected-resource metadata (§8).
Session binding: every runtime session resolves to a human **and** an agent, or
the connection is refused.

Authorization happens at `call_tool`, never at `list_tools` — §8 is explicit
that a previously listed tool is not a previously authorized one.

Returns only Veto-controlled URLs (invariant 8).

**Exit:** a real MCP client connects, lists tools, and every `call_tool` is
denied with `TOOL_NOT_ALLOWED`. Deny-by-default before anything can allow.

**Done 2026-09-18**, 23 tests. The session check reads the agent's row on every
request rather than trusting the token, which is what makes §11's five-second
revocation real — a test flips an agent to revoked mid-session and the next call
is refused. Nine distinct ways of being unauthenticated all return one identical
body, so a revoked agent learns exactly as much as a stranger.

### Phase 3 — The decision pipeline

`POST /v1/decisions/evaluate` with the §5.1 request and §5.2 response, and the
gateway calling it in-process. Steps in the order §3.3 fixes them:

1. Identity — done in phase 2
2. Normalize into action, resource, arguments, declared intent, destination
3. Session, presence, expiry, **emergency lock**
4. Deterministic prechecks — tool allowlist, resource scope, rate, volume
5. `permit.check` — and only the relationship/attribute question
6. Veto-side risk — intent mismatch, sensitive arguments, SSRF, destination
7. Emit allow / deny / challenge with a reason code
8. *(phase 5)*
9. Audit event

Steps 3, 4 and 6 sit outside Permit and must stay there (invariant 3). Both
`permit_result` and `veto_result` are recorded — the columns already exist and
the CHECK constraint already forbids an unavailable Permit producing an allow.

Needs the Drive resource model in Permit: `bootstrap` extended with
`google_file`, `google_folder`, the §4.2 actions, and the `parent` relation for
folder-to-file inheritance.

**Exit:** `/v1/decisions/evaluate` returns all three results against seeded
policy, with decisions persisted and audited. Permit-unavailable and
emergency-lock tests from phase 1 go green.

### Phase 4 — Google connection and credential vault

*Blocked on phase 0.*

`/v1/connections/google` — OAuth with PKCE and exact redirect URI validation,
Drive read-only scope only. Envelope encryption with a separate encryption
context per tenant (§3.4), and a broker that mints the narrowest upstream token
per call and **never returns root credentials** (§3.2).

Connection expiry and revocation are Veto's own checks, not Permit's
(invariant 3). Revocation deletes local tokens and calls Google's revocation
endpoint (§9.1).

**Exit:** a connection is established, stored encrypted, and revocable; the
credential never appears in a log, an audit event, or an API response.

### Phase 5 — Upstream call and the full loop

Step 8: on allow, mint the narrowest token and call Drive, forwarding *exactly*
the approved operation and resource. The action digest binds the decision to the
call, so a widened request between decision and execution is a new decision.

One correlation id spans request → decision → approval → upstream → audit.

**Exit:** stage 2's exit condition. Ask for a file, get it or get a reason code.

### Phase 6 — Challenge without the ceremony

Emit `challenge`, create the approval bound to the action digest, single-use and
expiring. **No passkey UI** — that is stage 3. What lands here is the state
machine and its refusals: replayed, expired, digest-mismatched, and
approver-is-not-the-delegator all deny with their existing reason codes.

**Exit:** the replay, expiry and wrong-approver tests from phase 1 go green.

## Decisions to make before phase 3

| # | Question | Leaning |
| --- | --- | --- |
| D1 | Local PDP for development? | **Blocked on the operator.** podman 5.4.2 is in apt but needs sudo, which is password-gated here. `sudo apt install podman` unblocks it. Until then, development runs against the hosted PDP and local stays a deployment requirement |
| D2 | Gateway in-process with the API, or separate? | Separate. Different trust boundary, different traffic, and invariant 8 reads better when there is exactly one thing that can enforce |
| D3 | Where do volume limits live? | Redis, per (workspace, agent, window). Postgres cannot take per-request write load, and §12.1's split-bulk-request test needs a shared counter |
| D4 | KMS for envelope encryption in development? | Deferred to phase 4 — depends on whether a cloud KMS is available or a local key wrapper stands in |

## Risks

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| Hosted PDP latency makes the §11 budget unreachable in dev | **High — already measured** | Build against it, measure per step, keep the local-PDP switch to one env var |
| Google verification required for Drive scopes | Medium | Start with the narrowest read-only scope; testing accounts do not need verification |
| Prompt-injection test is unfalsifiable if written loosely | Medium | Assert on the *decision*, not on model behaviour: retrieved content must never widen the action digest |
| Pipeline steps drift back inside Permit for convenience | Medium | Each of steps 3, 4 and 6 gets a test proving it denies while Permit says allow |
| Scope creep into Gmail/Calendar | Low | §9.1 and this document both say no |

## Complexity

Large. Phase 3 is the product; phases 4 and 5 are where credentials start
existing and the security bar rises accordingly.
