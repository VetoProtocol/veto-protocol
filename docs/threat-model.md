# Veto Protocol — Threat Model

**Status:** draft for review · **Stage:** 1 (spec §13) · **Covers:** Veto Protocol v1.0 MVP

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
└──────────────────────────┬───────────────────────────────────┘
                           │  MCP / HTTPS        ◄── BOUNDARY 1
┌─ VETO CONTROL PLANE ─────┴───────────────────────────────────┐
│  Gateway · Identity · Presence · Policy adapter · Risk        │
│  Approval · Credential vault · Audit                          │
└───────┬───────────────────────────────┬──────────────────────┘
        │  ◄── BOUNDARY 2               │  ◄── BOUNDARY 3
   Permit PDP / Cloud API          Google Workspace APIs
```

**Boundary 1 (client → gateway)** is the primary enforcement point (spec §3.1).
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
| T9 | Cross-tenant access | `workspace_id` on every query, cache key, and encryption context; Postgres RLS as defence in depth | Cross-tenant tests at query *and* RLS layer |
| T10 | IDOR | Every resource lookup scoped by workspace before authorization | `/v1/agents/{id}` IDOR test |
| T11 | OAuth CSRF | PKCE, exact redirect URI match, single-use `state` | OAuth flow tests (stage 2) |
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

---

## 8 Review

| Item | Status |
|---|---|
| Every §7.3 threat mapped | ✅ T1–T8 |
| Every §12.1 scenario has an owning test | ✅ 8/8 |
| Reviewed and signed off | ☐ **pending** |
| Production credentials may now be stored | ☐ blocked on sign-off |
