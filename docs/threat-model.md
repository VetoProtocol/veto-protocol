# Veto Protocol — Threat Model

**Status:** reviewed 2026-09-18, awaiting owner acceptance of residual risk · **Stage:** 1 complete (spec §13) · **Covers:** Veto Protocol v1.0 MVP

> **Gate.** Spec §16 requires this document to be complete and reviewed **before any
> production credential is stored**. The credential vault (stage 2) does not start
> until this is signed off.

---

## 1 Scope

In scope: the MCP gateway, identity and delegation, presence, the Permit policy
adapter, approvals, the credential vault, audit, and the Google Workspace adapter.

Out of scope for v1.0: the Web3 adapter (design-ready, spec §10), anomaly detection
beyond deterministic limits (CLAUDE.md invariant 2), and any traffic that does not
traverse the gateway (see §7, Residual risk).

Method: asset- and boundary-driven. Each threat below names the component that owns
the mitigation and the test that proves it, so the model stays executable rather than
aspirational.

---

## 2 Assets

| Asset | Why an attacker wants it | Worst case |
|---|---|---|
| Google refresh tokens | Long-lived access to mail, files, calendar | Full mailbox/Drive exfiltration, survives Veto |
| Permit API keys | Rewrite policy to allow anything | Silent, workspace-wide authorization bypass |
| Approval grants | Convert a `challenge` into an `allow` | Step-up authentication defeated |
| Audit log | Erase evidence | Undetectable breach |
| Protected content (docs, mail) | The data itself | Confidentiality loss |
| Session/capability tokens | Impersonate a human or agent | Authorization bypass for the token's lifetime |

---

## 3 Trust boundaries

```
┌─ UNTRUSTED ─────────────────────────────────────────────────┐
│  Human user  →  AI client / agent  →  retrieved content      │
└──────────┬───────────────────────────────┬───────────────────┘
           │  browser        BOUNDARY 4 ►  │  MCP / HTTPS  ◄── BOUNDARY 1
┌─ VETO CONTROL PLANE ─────────────────────┴───────────────────┐
│  Dashboard ─capability token─► Control API                    │
│  Gateway · Identity · Presence · Policy adapter · Risk        │
│  Approval · Credential vault · Audit                          │
└───┬──────────────────┬────────────────────┬──────────────────┘
    │ ◄── BOUNDARY 2   │ ◄── BOUNDARY 5     │ ◄── BOUNDARY 3
 Permit PDP        OIDC provider       Google Workspace APIs
```

**Boundary 1 (client → gateway)** is the primary enforcement point (spec §3.1).
**Boundary 4 (browser → dashboard)** carries a signed session cookie; the dashboard
holds the capability signing key and is inside the control plane, not outside it.
**Boundary 5 (dashboard → OIDC provider)** decides who a person is and nothing else:
an id token proves identity, never membership or authority.
**Boundary 2 (gateway → Permit)** must fail closed and must never carry secrets or
protected content. **Boundary 3 (gateway → upstream)** is where the narrowest possible
token is minted per allowed action.

### 3.1 Principals and how far each is trusted

| Principal | Authenticated by | Trust level | Note |
|---|---|---|---|
| Human user | OIDC, WebAuthn for step-up | Trusted when freshly verified | Presence is a signal, never proof of intent (§7.2) |
| Agent | Registered agent identity, bound session | **Authenticated but NOT trusted** | See 3.2 |
| MCP client | Client registration | Semi-trusted | Identifies software, not intent |
| Retrieved content | — | **Hostile input** | See 3.2 |
| Permit PDP | Server-side API key | Trusted for its one answer | Not trusted to be available |
| OIDC provider | TLS + JWKS signature | Trusted to say *who*, nothing more | A valid id token confers no membership; see T15 |
| Dashboard | Holds the capability key | Inside the control plane | Compromise equals control-plane compromise, not a lesser event |
| Google APIs | OAuth | Trusted as data source | Not trusted for availability or latency |

### 3.2 The central assumption

**An authenticated agent may be acting against the user.** Indirect prompt injection
means a correctly-authenticated agent, with a valid session and a legitimate
delegation, can be executing instructions an attacker embedded in an email or
document it was asked to read. Content crossing Boundary 3 *inbound* is attacker-
controlled input, not data.

Three consequences that constrain every design decision downstream:

1. **The model never self-approves.** Nothing the agent asserts — including
   `declared_intent` — may be the sole basis for an allow. Intent is a risk *signal*
   only (spec §7.3, FR-11).
2. **Controls must be deterministic.** A compromised agent can make its requests look
   plausible; it cannot make them satisfy a static resource scope it was never granted.
3. **Authorization happens at `call_tool` time, every time** (spec §8, invariant 9).
   A tool listed earlier proves nothing about the call being made now.

---

## 4 Threats and mitigations (spec §7.3)

| # | Threat | Mitigation | Owning component | Proven by |
|---|---|---|---|---|
| T1 | Indirect prompt injection | Deterministic tool/resource policy; intent-mismatch as signal only; no model self-approval | Gateway precheck, Risk engine | §12.1 "email instructs agent to search Drive for tax records" |
| T2 | Stolen OAuth token | KMS envelope encryption, per-tenant context; token never leaves the vault; narrowest scopes; revocation | Credential vault | Vault unit tests; revocation test |
| T3 | Compromised AI account | Agent identity independent of human; presence rules; step-up; resource limits | Identity, Presence, Approval | §12.1 "approval link opened by a different user" |
| T4 | Privilege accumulation | Expiring delegation, deny-by-default, relationship cleanup on revoke | Identity, Policy adapter | §12.1 "agent authorized for one file requests the whole folder" |
| T5 | Approval replay | Single-use grants, action-digest binding, nonce, expiry, approver binding | Approval | §12.1 "approved action replayed after expiry" |
| T6 | Gateway compromise | KMS, least privilege, network segmentation, secret rotation, incident runbook | Platform | Ops review (not a unit test) |
| T7 | Policy outage | Fail closed; explicit degraded-mode message | Policy adapter | §12.1 "Permit unavailable during a sensitive request" |
| T8 | Audit tampering | Append-only storage, restricted writers, hash chain, export controls | Audit | RLS + append-only migration tests |

### 4.1 Additional threats (spec §12 security row)

| # | Threat | Mitigation | Proven by |
|---|---|---|---|
| T9 | Cross-tenant access | `workspace_id` on every query, cache key, and encryption context; Postgres RLS as defence in depth | Cross-tenant tests at query *and* RLS layer — **green** |
| T10 | IDOR | Every resource lookup scoped by workspace before authorization | `/v1/agents/{id}` IDOR test — **green**, asserts the 404 is byte-identical to a nonexistent id |
| T11 | OAuth CSRF | PKCE S256, exact redirect URI match, signed single-use `state` in a 2-minute cookie | Dashboard sign-in — **green**; gateway OAuth is stage 2 |
| T15 | **Identity-resolution read spans tenants** | One SECURITY DEFINER function, one exact subject, two columns, active users only, SELECT-only policy. No prefix, pattern or pagination reaches it | Enumeration test in `apps/api/test/auth.test.ts` — **green** |
| T16 | **Capability token misuse** | Audience pinned per service; scope asserted per route; 15-minute ceiling enforced on mint *and* verify; no algorithm field to confuse | Scope and audience tests — **green** |
| T17 | **Sign-in grants membership** | No auto-provisioning. An unknown subject is refused; membership is an operator action | Callback refuses unknown subject — **green** |
| T12 | SSRF / metadata access | Destination allowlist; private and link-local ranges denied | §12.1 "request targets a private / metadata network address" |
| T13 | Bulk-splitting | Cumulative volume as an *authorization* limit, not a rate limit; digest covers arguments | §12.1 "blocked bulk request split into many small requests" |
| T14 | Emergency lock race | Lock checked at step 3 of every request, before policy | §12.1 "emergency lock during an active session" |

### 4.2 Two distinctions that are easy to collapse, and must not be

- **Rate limit ≠ volume limit.** Rate limiting is an availability control and must
  never stand in for authorization (spec §7.1). Cumulative volume
  (`maximum_volume`, §4.2) is an authorization attribute. They are separate code
  paths with separate failure behaviour: exceeding a rate limit throttles;
  exceeding a volume limit **denies**.
- **Permit's answer ≠ the decision.** Permit answers one question. Emergency lock,
  credential expiry, argument inspection, and destination checks are Veto's, and run
  around the check (invariant 3). A component that treats `permit.check === true` as
  an allow is a defect regardless of its tests.

### 4.3 The deliberate exception to tenant isolation

Invariant 4 says every query is scoped by `workspace_id`. Migration 0007 makes one
exception, and it is recorded here rather than buried in SQL.

Sign-in has a bootstrapping problem: at the moment an OIDC callback arrives, the only
thing known is a subject. The workspace is what is being looked *for*, so a
tenant-scoped query cannot answer the question. Reading `users` with no tenant set
returns zero rows — correct, and useless here.

The exception is `resolve_identity_subject()`:

| Property | Why |
|---|---|
| One exact subject, no pattern or prefix | Nothing can enumerate; a test asserts `%`, `oidc\|`, and an injection string all return empty |
| Returns two columns, ids only | It is a lookup, not a profile endpoint |
| `active` users only | A suspended person cannot sign in, and the check cannot be forgotten by a caller |
| SELECT-only policy, named `identity_resolution` | Nothing writes through this path |
| GUC set inside the function, transaction-local | Gone before the connection returns to the pool |
| Reachable only with the `identity-resolve` scope | A dashboard session credential is refused; a leak of either token does not reach the other |

**Accepted residual:** anything that can execute arbitrary SQL as the `veto` role can
set the GUC itself and read `users` across tenants. That is true of every RLS policy
in this schema — RLS is defence in depth behind application scoping, not a substitute
for it. A `BYPASSRLS` role would be cleaner and the `veto` role cannot create one
(recorded in 0005 as a deployment item).

---

## 5 Data handling

| Class | Rule |
|---|---|
| Credentials, auth headers, passkey challenges | Never logged, never in audit events, never in Permit calls, never returned to an agent (invariant 5) |
| Protected content | Never stored in audit events by default (spec §11 data minimisation); resource **references** only |
| Identifiers | Safe to log and audit |
| Decision context | `permit_result` and `veto_result` both recorded — they are distinct (spec §6) |

Every request carries one correlation id across request → Permit decision → approval
→ upstream call → audit event (spec §8).

---

## 6 Fail-closed inventory

Each of these must deny, and each needs an explicit test:

| Condition | Result | Code |
|---|---|---|
| Identity unresolved | deny | `IDENTITY_UNRESOLVED` |
| Session expired | deny | `SESSION_EXPIRED` |
| Emergency lock active | deny | `WORKSPACE_LOCKED` |
| Permit unreachable or timed out | deny | `POLICY_UNAVAILABLE` |
| Malformed arguments | deny | `ARGUMENT_SCHEMA_INVALID` |
| Approval expired / reused / digest mismatch | deny | `APPROVAL_*` |
| Approver is not the delegator | deny | `APPROVER_NOT_DELEGATOR` |
| Unrecognised reason code | deny | fallback |

---

## 7 Residual risk

**Veto protects only what passes through Veto.** A user who connects Google directly
to another AI provider is unprotected, and the product must say so plainly rather than
imply otherwise (spec §14, invariant 8). This is a product and distribution risk, not
a control we can add.

Also accepted for v1.0:

- **Gateway compromise is catastrophic** (T6). Defence is operational — KMS, least
  privilege, segmentation, rotation — not architectural. Revisit with an HSM-backed
  signing boundary if the threat profile changes.
- **Presence can be wrong.** It is a policy signal derived from device activity, never
  proof the human intended this action (spec §7.2). Fresh passkey verification is the
  only strong signal, and it is required exactly where the policy demands it.
- **Intent mismatch is heuristic.** It can raise a challenge; it may not authorise.
- **Permit is a dependency with its own availability.** Outage degrades to deny, which
  is correct but user-visible. §11 targets 99.9% and accepts this.
- **The hosted PDP cannot meet the latency budget** (measured 2026-09-18: minimum
  211 ms, p50 ~225 ms, p95 293–739 ms, against §11's 200 ms P95 for the *whole*
  nine-step pipeline). A local PDP beside the gateway is a production requirement.
  Two consequences for this model: development runs against numbers that will not
  hold, and the hosted PDP cannot confirm fact writes at all — `proxyFactsViaPdp` is
  a local-PDP capability. What holds the line meanwhile is that revocation flips
  agent status in Postgres first and the gateway checks that status on every request,
  so a lagging PDP cannot re-grant anything.
- **The dashboard holds the capability signing key.** It is inside the control plane,
  so its compromise is control-plane compromise (T6), not a lesser event. Scoping and
  the 15-minute ceiling limit blast radius; they do not change the classification.

---

## 8 Review

Reviewed **2026-09-18**, against stage 1 as built rather than as planned.

| Item | Status |
|---|---|
| Every §7.3 threat mapped | ✅ T1–T8 |
| Additional threats mapped | ✅ T9–T17 |
| Every §12.1 scenario has an owning test | ✅ 8/8 — registered in `packages/core/src/adversarial.ts`, 0 implemented, 8 pending stage 2 |
| Stage-1 deltas incorporated | ✅ boundaries 4 and 5, T15–T17, §4.3, PDP latency |
| Controls claimed as green actually run in CI | ✅ verified against the suite, not against intent |
| Reviewed by the implementer | ✅ |
| **Residual risk accepted by the project owner** | ☐ **pending — see below** |
| Production credentials may now be stored | ☐ blocked on the line above |

### 8.1 What the owner is being asked to accept

The technical review is done. What remains is a judgement call that is not the
implementer's to make. Four residual risks, each unfixable within v1.0's scope:

1. **Veto protects only what passes through Veto.** A user who connects Google
   directly to another AI provider is unprotected, and the product must say so
   plainly rather than imply otherwise.
2. **Gateway compromise is catastrophic**, and the defence is operational — KMS,
   least privilege, segmentation, rotation — not architectural.
3. **The identity-resolution read spans tenants** (§4.3), narrowly and deliberately.
4. **Presence and intent are signals, never proof.** Both can be wrong; only fresh
   passkey verification is strong, and it is required exactly where policy says so.

Accepting these unblocks the credential vault (§16). Nothing else is waiting on it.
