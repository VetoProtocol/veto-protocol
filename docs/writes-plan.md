# Writes — a plan, and a decision to make first

## This is outside the spec's build order

§13's twelve weeks are read-only end to end. §1.4 lists **"broad write and
destructive actions at launch"** as out of scope. §9.1 says Drive begins with
read patterns, Gmail keeps sending out of the MVP, and Calendar
"create/update requires step-up approval in later releases".

So nothing below is stage 5 or stage 6. It is v1.1, and CLAUDE.md's rule —
*build order (§13), do not build ahead of it* — means executing this before the
pilot is a decision somebody makes on purpose, not a thing that happens because
a plan exists.

**Two things must happen before phase 1:**

1. **The spec is amended, or this is explicitly deferred.** Writes are not a
   detail §13 forgot; they are a scope line it drew.
2. **The threat model comes back for review.** `docs/threat-model.md` §8 was
   signed off on 2026-09-18 covering four residual risks *for a system that only
   reads*. CLAUDE.md records that acceptance as covering "those four as
   written", and that a new trust boundary brings the document back. A write
   path is a new trust boundary: the failure mode changes from *disclosure* to
   *destruction*, and destruction is not undone by revoking a credential.

## The one property that makes writes different

Everything else in this product is recoverable by refusing faster. A wrong
`allow` on a read leaks something that was already there. A wrong `allow` on a
write **changes the world**, and no amount of subsequent denying puts it back.

That has a concrete consequence for the design: for reads, the approval question
is *"may this agent see that?"*. For writes it is *"do you understand what is
about to happen?"* — and the second cannot be asked without simulation.

## Phase 1 — Transaction simulation, before anything can write

§3.3 step 6 names "transaction simulation" as one of the Veto-side risk checks.
Nothing implements it. Build it **first**, and build it against the read tools
that already exist, so it is proven before a write depends on it.

A simulation is a statement, derived from the validated arguments, of what the
call will change:

> Create a file named `Q3 summary.md` in folder `Engineering`.
> Send a reply to 3 recipients on thread `Board review`.

Three rules it has to hold:

- **Derived from the request, never from the model.** The agent's own
  description of what it is doing is `declared_intent`, which is a risk signal
  and never authorization (FR-11). A simulation the agent could word is a
  simulation an attacker can word.
- **A summary, not the content.** Invariant 5 forbids protected content in
  audit events, and an approval row is stored. "A file of 4 KB named X" is a
  classification; the file body is not. The approval screen shows the summary
  and the digest, not the payload.
- **A wrong simulation is worse than none.** It makes the approval screen lie,
  and a human who approves on the strength of it has been misled by us rather
  than by the attacker. If a tool cannot be simulated accurately, it does not
  ship.

**Exit:** every existing tool has a simulation, the approval screen shows it,
and a test asserts the simulation matches what step 8 actually sends.

## Phase 2 — Create-only, nothing else

| Service | Tool | Scope | Why this one |
| --- | --- | --- | --- |
| Drive | `create_file` | `drive.file` | Narrower than `drive`: reaches only files this app created. An app that cannot see your existing Drive cannot overwrite it. |
| Calendar | `create_event` | `calendar.events` | New events only. No updating somebody else's meeting. |
| Gmail | `create_draft` | `gmail.compose` | **A draft, not a send.** A draft is reversible by deleting it; a sent mail is not reversible by anything. |

No update. No delete. No share. No move. Permit learns the single action
`create` and nothing else — an action it does not know cannot be granted by
accident, which is already how the read model works.

**Presence already gates this correctly and needs no new semantics.** §7.2:
`away` challenges "sensitive reads and **all writes**", and the pipeline already
emits `USER_AWAY_WRITE_ACTION`. `write` is already a value `/v1/policies`
accepts.

**Exit:** an agent can create a file, and every path to doing so is visible —
rule, grant, presence, simulation, approval, audit.

### The open question this phase forces

`active` presence plus an `allow` rule is an **unattended write**. §7.2 says
active means "allow low-risk in scope", and it is not obvious a write is ever
low-risk.

Three options, and this is the owner's call rather than something to invent:

1. Writes always challenge, regardless of presence. Safest, and makes
   unattended automation impossible.
2. Writes challenge unless the rule names `automation` presence with an explicit
   workflow — which §7.2 already scopes to "the named workflow, tools,
   resources and limits".
3. Writes behave like reads and a rule may allow them outright.

I would ship (2). It is the only one that uses a mechanism the spec already
defines rather than adding a fourth.

## Phase 3 — Update, behind a stricter gate

Update overwrites. The previous content is gone unless the provider keeps
versions — Drive does, Gmail drafts do not.

Requirements beyond phase 2:

- The simulation shows **what is being replaced**, not only what is arriving.
- The approval binds the *target's current state*, so approving "update file X
  as it is now" cannot be redeemed after X has changed. The action digest covers
  arguments; this needs the target version in the digest too.
- A rule must name `update` explicitly. `write` as a wildcard does not reach it.

## Phase 4 — Delete: my recommendation is not to

If it is built at all: **trash only, never permanent**. Drive's trash is
recoverable for thirty days; `files.delete` is not recoverable by anyone,
including Google. Gmail and Calendar are similar.

Bulk and recursive operations — empty trash, delete folder, delete thread —
should not exist at any point. §12.1 already has a scenario about a blocked bulk
request split into many small ones; a recursive delete is that attack with the
product's own help.

## Phase 5 — Reversal

Not in the spec, and worth naming as a gap rather than pretending the audit
trail covers it. The audit trail records *that* something was created; it does
not put it back. If writes ship, "undo the last thing this agent did" is the
first thing somebody will ask for, and the honest answer today is that nothing
here can do it.

## Risks

| Risk | Handling |
| --- | --- |
| A wrong allow destroys instead of leaking | Create-only first; delete last or never; every write simulated and approved |
| `gmail.send` is Google's heaviest verification tier | Drafts need only `gmail.compose`. Sending can wait for a customer who asks |
| Simulation drifts from what step 8 sends | Same test asserts both; a tool with no simulation does not ship |
| An approval outlives the state it was granted against | Phase 3 puts the target version in the digest |
| Scope creep from `drive.file` to `drive` | `drive.file` cannot reach pre-existing files. Widening it is a separate consent and a separate decision |
| Writes make the threat model's sign-off stale | Phase 0. Not optional |

## What I would refuse to build

- Permanent delete.
- Any bulk or recursive mutation.
- A write tool with no simulation.
- A write that an agent can perform with nobody ever having approved anything —
  unless option (2) above is chosen deliberately and the automation window is
  named, bounded and audited.

## Rough size

Phase 1 is the real work — a week, because it is a new step in the pipeline and
it touches the approval screen. Phases 2 and 3 are a few days each once
simulation exists: scopes, tools, Permit actions and tests are shapes this
codebase already has four examples of. Phase 0 is a conversation.
