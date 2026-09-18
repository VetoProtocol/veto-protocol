# Permit.io setup (stage 1, phase 5)

What a developer — or the account owner — has to do by hand, and what is
automated. Spec §4 defines the integration; §16 items 1 and 2 are the handoff
checks this document closes.

## 1. Account and project

1. Create an account at <https://app.permit.io>.
2. Create a project. Name it whatever you like; nothing in the code reads it.
3. Permit creates `development` and `production` environments for a new project.
   **Create `staging` as well** — §16 requires three, with separate keys.

## 2. API keys

Settings → API Keys → copy the **environment-level** key for `development`.

- One key per environment. A key is a tenant boundary as much as a credential:
  a staging key that can write to production makes every isolation guarantee in
  this repo moot for policy facts.
- Put it in `.env` as `PERMIT_API_KEY`. `.env` is gitignored and must stay that
  way. The key never reaches the dashboard bundle — `@veto/permit` is
  server-side only (§3.2).
- If a key is ever pasted into a chat, a log, or a commit, rotate it. It grants
  write access to the policy model, which means it grants the ability to author
  allows.

## 3. Create the resource model

```bash
pnpm --filter @veto/permit bootstrap
```

Idempotent, and run once per environment with that environment's key in
`PERMIT_API_KEY`. It creates:

| Object | Why |
| --- | --- |
| Resource `veto_human` | Relation endpoint for a delegating user |
| Resource `veto_agent` | Relation endpoint for an agent identity |
| Relation `veto_agent.delegator` | Binds an agent to the human who delegated to it |

It deliberately does **not** create `google_file`, `mailbox`, `calendar` or the
other §4.2 resource types. Those are modelled in the stage that enforces them.
Policy that nothing reads is policy nobody notices is wrong.

### The direction of `delegator`

Permit defines a relation *on the object resource* and names the other end as
`subject_resource` — the shape of its own "Folder is parent of File" example,
where `parent` belongs to `File`. So `delegator` belongs to `veto_agent`, and a
tuple reads **subject = human, object = agent**: "this agent's delegator is
that human".

This is the one modelling decision in phase 5 that was made from the SDK's type
signatures rather than from a live environment. **Confirm it with the live
contract test before building §7.1 approval routing on top of it** — that edge
is what decides who is allowed to approve a challenge, and a reversed edge would
be a silent authorization bug rather than an error.

## 4. Verify

```bash
pnpm --filter @veto/permit test
```

All three scripts read the key from the repo-root `.env`; a value set in the
shell takes precedence over the file.

Three tests in `test/permit-facts.live.test.ts` skip without a key and run with
one. They sync an agent, assert the delegator fact is readable back, remove it,
and assert nothing referencing that agent remains. That last assertion is the
FR-08 property: revocation is not complete until Permit holds nothing.

## 5. Measure PDP latency

```bash
pnpm --filter @veto/permit latency
```

Reports min / p50 / p95 / p99 / max for `permit.check` round trips and compares
P95 against a budget slice.

**Read the number carefully.** §11 budgets P95 < 200 ms for the *whole*
authorization path — nine pipeline steps, of which the PDP call is one. The
harness defaults to 100 ms for the PDP slice; that split is an assumption, not a
spec value, and is the thing to argue about rather than the 200.

### Measured result — 2026-09-18

Two runs from this development machine against `cloudpdp.api.permit.io`:

| | 50 samples | 30 samples |
| --- | --- | --- |
| min | 210.75 ms | 211.67 ms |
| p50 | 227.29 ms | 221.44 ms |
| p95 | 738.59 ms | 293.00 ms |
| p99 / max | 1080.56 ms | 663.02 ms |

One warm-up call timed out at the 5 s ceiling.

**The hosted PDP does not fit §11, and not by a little.** The *fastest single
check observed* — 211 ms — already exceeds the 200 ms P95 budget for the entire
nine-step pipeline, before identity resolution, presence, prechecks, risk
checks, or the audit write have done anything. p95 is three to four times the
whole budget. No tuning of the timeout or the budget split changes that; it is
network round trips to a cloud service on the hot path.

Consequences to carry into stage 2:

- **A local PDP is a production requirement, not an optimisation.** Plan for the
  container beside the gateway, and revisit these numbers from there.
- The p95/p99 spread across the two runs (293 ms vs 739 ms) is wide enough that
  the tail is dominated by network conditions rather than by Permit. Measure
  again from the deployment environment before treating any figure as a
  baseline.
- A local PDP also restores the fact-sync guarantee described in `config.ts`,
  which the hosted PDP cannot provide at all.

This measurement is from one machine on one network. It is decisive about
hosted-being-too-slow *here*; it is not a benchmark of Permit.

### Why hosted, not local

Permit's recommended production topology is a PDP container beside the
application, which removes the internet from the hot path. **There is no
container runtime on this machine** — no Docker, no Podman — so the hosted PDP
at `cloudpdp.api.permit.io` is the only option here, and it is the one being
measured.

That is a development constraint, not an architecture decision. If the hosted
P95 does not fit, the fix is a local PDP in the deployment environment, not a
change to the code: `PERMIT_PDP_URL=http://localhost:7766` is the whole
difference.

## 6. Findings from the first live run

Four things only a real environment could have told us. All are fixed in code;
they are recorded because each was a wrong assumption, not a typo.

1. **Principal keys cannot contain a colon.** §4.2 suggests `agent:{agentId}`,
   but Permit validates user keys against `^[A-Za-z0-9|@+\-._]+$` and answers
   422. Keys are now `agent|{agentId}` and `human|{userId}`. A unit test holds
   the pattern so this cannot regress without a live call.
2. **`proxyFactsViaPdp` is local-PDP-only.** It posts to `/v2/facts/...`, which
   the hosted PDP answers with 404. The flag is now derived from the PDP URL.
3. **The permitio SDK inverts its own logging flag.** `log.json: true` makes it
   pass `prettyPrint` to pino 8, which throws on any truthy value — so `true`
   crashes the constructor and `false` yields JSON. A construction test now
   covers this without needing credentials.
4. **The `delegator` direction was right.** Subject is the human, object is the
   agent. Confirmed by the live contract test, which writes the tuple and reads
   it back. This was the open risk flagged when the adapter was written.

## 7. What is still open

- **§16 item 1 — approval and gateway administration on stable APIs.** Not yet
  answered. It needs the account's plan page and the Access Requests API
  (<https://docs.permit.io/api/elements/access-requests/>), which stage 3 builds
  against. Nothing in stage 1 depends on it.
- **The threat model sign-off** (`threat-model.md` §8) is still unticked, and
  §16 gates storing production credentials on it. That blocks stage 2's vault
  work, not this.
