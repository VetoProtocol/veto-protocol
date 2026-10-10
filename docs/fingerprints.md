# Agent fingerprints

Which software has been connecting as each agent — and, honestly, how little
that can be made to prove.

## What was measured

On 2026-10-09 a throwaway loopback listener spoke just enough MCP for a real
client to complete its handshake, and recorded every header and body it was
sent. Claude Code 2.1.293, HTTP transport. Nothing in the repository, the
database or the deployed service was involved.

The result that decided the design:

```
user-agent: claude-code/2.1.293 (sdk-cli)
```

That header was present on **every request in the connection** — the
`server/discover` probe, `initialize`, `notifications/initialized`, the SSE
`GET`, and `tools/list`, and therefore on `tools/call`.

This matters because the gateway is stateless per HTTP request. MCP's richer
`clientInfo` object arrives only with `initialize`:

```json
{ "name": "claude-code", "title": "Claude Code", "version": "2.1.293",
  "description": "Anthropic's agentic coding tool",
  "websiteUrl": "https://claude.com/claude-code" }
```

Anything keyed to that would need shared state between two unrelated HTTP
requests, and would be missing entirely for a client that never handshakes —
which nothing in the protocol obliges it to do. The `User-Agent` arrives with
the protected action itself, so no shared state is needed and there is no
window in which a tool call carries no identification.

## What it is worth

**Every value here is a string the client chose to send.** Somebody who steals
a gateway token can send the same string. The parser strips control characters
and bounds the length, which stops a header forging a log line; it does nothing
about a header that simply lies.

So this is **change detection, not authentication.** A matching fingerprint is
not evidence of anything. A *changed* one is a fact worth putting in front of
an operator. The honest claim is that it raises the cost of using a stolen
credential from zero to slightly above zero, and the screens that show it have
to say so rather than implying a check that is not happening.

Nothing downstream may read a fingerprint as proof of identity. It is the same
rule presence lives under: a signal, never proof of intent.

## Why the version is not hashed

`product` and `channel` survive a release. The version does not — `2.1.293` is
a patch number on a tool that updates often.

Hashing the whole header would make every routine Claude Code update
indistinguishable from a different program arriving on the same credential. The
control would fire on every upgrade, somebody would switch it off, and a
control that is off protects nothing.

So the digest covers the stable half and the version rides alongside as a
recorded fact:

| Part | Example | Hashed | On change |
| --- | --- | --- | --- |
| product | `claude-code` | yes | the alarm |
| channel | `sdk-cli` | yes | the alarm |
| version | `2.1.293` | no | a dated note |

`FINGERPRINT_VERSION` is inside the hashed payload. Changing what goes into a
digest invalidates every stored one, so that becomes a visible migration rather
than a silent mass re-pinning an operator would read as "everything changed at
once".

## What is built

Migration 0026 adds `agent_fingerprints` and records what connects. Migration
0027 adds `agents.fingerprint_mode` and lets it matter.

- `observeClient` parses a `User-Agent`. No I/O, no verdict.
- `recordSighting` writes one row per distinct fingerprint per agent, bumping
  counters on a repeat.
- `GatewaySession.client` carries the observation. `resolveSession` performs no
  write.
- The gateway records on `initialize` and on `tools/call`. Not on `ping` or
  `tools/list`: neither is an action, and a write per keepalive is cost for
  nothing.

`agents.fingerprint` is **not** the field being read. It has existed since
migration 0002 as free text an operator typed at registration, and nothing ever
compared anything to it. It is deliberately not consumed as a constraint on the
first sighting either: it is unvalidated, nobody has filled it in with a real
digest, and turning a stale guess into a lockout is a worse failure than leaving
a dead field alone. Its column comment now says so.

## Three modes, per agent

| Mode | An unpinned client | A client an operator refused |
| --- | --- | --- |
| `observe` | nothing changes | nothing changes |
| `challenge` | the delegating human must approve | refused |
| `deny` | refused | refused |

**`observe` is the default**, so applying both migrations changed no decision
anywhere. That is not timidity: a gateway in production is being used right now
by a client nobody has pinned, and a default that enforced would have refused
the operator's own session the moment the migration ran.

**`observe` means observe.** In that mode the fingerprint cannot change an
outcome at all — not even for software explicitly marked `refused`. Letting a
refusal bite in every mode reads as the safer choice and is worse: it makes the
mode's meaning conditional, and a control whose effect depends on two settings
at once is one nobody can reason about. The screen therefore offers **Refuse**
only where enforcement is on, so the button never promises something the mode
will ignore.

It also makes the default free. Step 3 skips the lookup entirely under
`observe`, so a workspace that has not turned this on spends no part of the §11
budget on it.

### Trust on first use

The first software an agent ever uses is recorded as `pinned`; everything after
it is `seen`. Without this, raising the mode to `challenge` would immediately
challenge the client the operator is sitting in front of, which is how a control
gets switched straight back off again.

What it costs, stated rather than discovered later: whoever connects first is
trusted, so an attacker who beats the legitimate client to a freshly registered
agent is pinned instead of it. In practice registration and first use are the
same person minutes apart, the row is visible on the screen, and an operator can
refuse it.

Turning enforcement **on** pins nothing. It is a statement about what happens
next, not a blessing of everything already on file — and anything beyond the
first arrived afterwards, which is exactly what the operator is turning this on
to catch.

## Where the check sits

**Step 3 of the §3.3 pipeline**, with session standing — the agent's own status,
the emergency lock, the consent check. Not step 6, which judges the *request*
(arguments, destination, intent); this judges *who is calling*. It also means
Permit is never consulted about a client this workspace has refused, the same
reasoning the lock already uses.

A `deny` returns immediately. A `challenge` is **held** and the pipeline
continues, so a later denial still wins — challenge is the least permissive
answer that is not a refusal, and anything stricter replaces it. One consequence
worth knowing: in `challenge` mode the fingerprint code is only ever the
*surviving* reason on an action that would otherwise have been allowed. On
anything else, step 4's `TOOL_NOT_ALLOWED` is the answer, and that is correct
precedence rather than the check failing to run.

### Two new reason codes

| Code | Result |
| --- | --- |
| `AGENT_FINGERPRINT_UNRECOGNISED` | `challenge` |
| `AGENT_FINGERPRINT_REJECTED` | `deny` |

A twenty-sixth and twenty-seventh code, and the bar for that is real — the
schedule work argued its way *out* of a new code because "every rule's window is
shut" genuinely is `TOOL_NOT_ALLOWED`. These earn one. Identity resolved
perfectly: the human, the tenant and the agent are all known and active, and
what changed is the software. `IDENTITY_UNRESOLVED`'s message would be plainly
untrue on screen, and a reason code whose text lies is worse than a longer list.

Approving a challenge authorises **that action** and does not pin the software —
pinning stays an explicit act on the screen. So an unpinned client keeps asking
until somebody decides about it, which is the intended pressure rather than an
oversight.

### A request that named no client

`clientFingerprint` is `null` for the control plane's own
`/v1/decisions/evaluate`, which has no client behind it and cannot invent one.
Absence narrows, the same rule presence and schedules already follow: under
enforcement a preview cannot promise an allow it has no way to stand behind.

## The alert

A **new** fingerprint — software that is not the first thing this agent ever
used — writes an `agent.fingerprint_changed` audit event and enqueues
`risk.anomaly_detected`. §5.4's set stays closed at eight, and "something
unusual was spotted in a request" is exactly what a second program on an
existing credential is.

Not on `first`: an agent's very first request is it starting to be used, not its
client changing, and an alert there would fire once per agent forever and teach
an operator to ignore the channel. Not on `repeat`, and not on a version bump,
which is the same fingerprint.

This fires in **every** mode, `observe` included. Observe must not change an
*answer*, but it would be a strange kind of observation that declined to mention
what it saw.

The payload names the agent and stops there. The product string is
attacker-chosen text, and a receiver that wants the detail asks the API with its
own credentials — which is where authorization happens again.

## The screen

`/fingerprints`, and it is a **Pro** screen. `GET /v1/agents/fingerprints`
answers **402** before reading anything, exactly as `/v1/grants/consent` does:
the sidebar hiding a link is not a control, because anybody can type a URL, and
a gate applied after the queries have run has already spent them. Both
mutations are gated too.

| Route | Does |
| --- | --- |
| `GET /v1/agents/fingerprints` | every agent, its mode, and what has connected |
| `POST /v1/agents/{id}/fingerprint-mode` | set `observe` / `challenge` / `deny` |
| `POST /v1/agents/{id}/fingerprints` | pin or refuse one client |

Only a fingerprint already on file can be judged. There is no way to pin a
digest nobody has seen: that would be a guess, and the value is not one anybody
can be expected to type correctly.

Under an emergency lock, **pinning and mode changes are refused; refusing a
client is not.** Pinning widens — it is what lets a client through an enforcing
mode — and an attacker who has triggered a lock response must not be able to
switch a control off while the operator is still dealing with it. Refusing only
narrows, and a lock is precisely when an operator needs to cut something off.

Revoked agents stay listed. What a now-dead agent was being used by is exactly
the question asked after an incident, and dropping the row would delete the
evidence along with the access.

### The copy is part of the feature

The page says, in plain words, that this spots a change and does not prove who
called. A screen implying a check it is not performing is the same mistake as a
comment claiming a control that does not exist, and this codebase has already
paid for that one once.

### Two bounds, both deliberate

**A failure to record must not fail the request.** `noteClient` catches and
logs. At this phase the row changes no outcome, and refusing a caller because a
bookkeeping insert failed would invent a denial no invariant asks for.
Invariant 1 is about failing closed on *authority* — missing identity, an
unreachable policy, an emergency lock — not on a statistic. The day this record
does decide something, that check belongs at step 3 of the §3.3 pipeline, where
a read failure *must* deny; that is a different call site from this one.

**`MAX_FINGERPRINTS_PER_AGENT` is 20.** The `User-Agent` is
attacker-controlled, and without a ceiling one token could mint a row per
request by varying it — unbounded table growth driven by a header. Past the
ceiling new rows are dropped and existing ones keep counting, which is why the
ceiling is a `where` clause inside the upsert rather than a count-then-insert:
counting first would have frozen the rows already on file as well.

`(absent)` and `(unparsable)` are sentinel products. Parentheses are not legal
in an HTTP token, so neither can collide with a real product name, and junk
collapses into one bucket instead of spending an agent's whole allowance.

## Cost

One extra statement per recorded request: **p50 2.68 ms, p95 4.90 ms** over 200
samples against local Postgres.

It does **not** appear in `decisions.latency_ms`, which covers steps 1–7 inside
`evaluate()`. This write happens in the gateway, outside the pipeline, so the
§11 figure is unchanged and the wall-clock cost is real but unrecorded. Worth
knowing before reading the two numbers as the same thing.

## Two incidental observations

Neither is a fault, and neither is this feature's job:

- Claude Code opens with `server/discover`, which the gateway does not
  implement. It answers `METHOD_NOT_FOUND` and the client proceeds; production
  connects fine today.
- The gateway advertises protocol `2025-06-18` (`PROTOCOL_VERSION` in
  `apps/gateway/src/app.ts`) while this client offers `2025-11-25` and
  discovers at `2026-07-28`. Negotiation works; the gateway is several
  revisions behind.
