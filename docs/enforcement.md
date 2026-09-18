# How an agent actually gets connected

Written because "I registered an agent — now how do policies get enforced?" is
the right question to ask after stage 1, and the answer is **not yet**. This
records what registration does, what is still missing, and why the pieces are in
this order.

## What registering an agent does

Exactly two things:

1. Writes a row in `agents`: this agent belongs to this user in this workspace.
2. Tells Permit the same, as a principal `agent|agt_…` with a `delegator`
   relation to the human.

That is an identity, not an access grant. The agent has a name. It has no way to
reach anything, and nothing to reach.

This is deliberate — invariant 2, deny by default. A freshly registered agent
holding zero access is the design, not a gap in it. It is also why the
"permanently burn a revoked `client_id`" rule was dropped in migration 0006:
registration alone grants nothing, so refusing re-registration was guarding the
wrong door.

## What is missing

As of the end of stage 1, `agents` is the only table with code behind it.
`connections`, `policies`, `sessions`, `presence`, `decisions` and `approvals`
exist in the schema with no writers. `permit.check` — the call that actually
decides anything — appears only in the latency harness.

Four things have to exist before a policy can be enforced.

### 1. The gateway

Nothing listens for agent traffic today.

`apps/api` is the **control plane**: the thing the dashboard talks to, for
managing objects. It is not an enforcement point and must not become one.

The gateway is a separate MCP server that an AI client connects to *instead of*
connecting to Google directly. Spec §3.1 is blunt about why this matters:
protection exists only for traffic that passes through it, and the product must
never claim to control credentials a user granted directly to another provider.

```
You  ->  AI client  ->  Veto Gateway  ->  Google Workspace
                             |
        identity · presence · Permit · risk · approval · audit
```

Today the middle box does not exist.

### 2. A way for the agent to prove who it is

There is no mechanism for a client to assert "I am `agt_…`". That is OAuth 2.1
discovery and protected-resource metadata (§8), binding each runtime session to
a human and an agent identity.

The `fingerprint` field on the register form is the beginning of this. Nothing
consumes it yet.

### 3. A connection

An agent has to act *on* something. That means an OAuth grant to Google, with
the tokens held in a credential vault — `/v1/connections/google`.

§9.1 requires incremental, narrowest-first scopes: Drive before Gmail before
Calendar, read before write, and never all three requested up front.

### 4. Policies

Rules of the form "this agent may read files in this folder, while the user is
present, up to N per day". Permit does not yet model the resource types this
needs — `bootstrap` deliberately created only the two types stage 1 required,
because policy that nothing reads is policy nobody notices is wrong.

## Why this order

Identity had to be real and revocable before anything could be granted to it.
Revocation that does not work is worse than no revocation, because it is
believed.

Everything in stage 1 exists to make step 1 of the §3.3 pipeline trustworthy.
Stage 2 builds steps 2 through 9 on top of it.

## What "enforced" will mean

A tool call from the agent arrives at the gateway. Before anything reaches
Google, the pipeline runs in order, and the result is one of exactly three
things (§5.3):

| Result | What the gateway does |
| --- | --- |
| `allow` | Forwards *exactly* the approved operation and resource — no widening |
| `deny` | Never contacts Google; returns a stable reason code |
| `challenge` | Pauses; resumes only with an unexpired, single-use, digest-bound approval |

The 25 reason codes in `@veto/core` were written before any of this, so the
vocabulary of refusals already exists and the approval screens have something
stable to render.

## The one thing blocking stage 2

`docs/threat-model.md` §8 sign-off is unticked, and §16 gates *storing
production credentials* on that review. Stage 2 builds the credential vault.

That is a review, not a build.
