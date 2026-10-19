# Alerts (webhooks)

Veto posts a signed JSON event to a URL you own when something happens that you
would want to know about without watching a dashboard.

## The eight events

| Event | Fires when |
| --- | --- |
| `decision.denied` | An agent asked for something and was refused |
| `approval.requested` | Someone needs to approve an action before it can happen |
| `approval.resolved` | A pending approval was approved or refused |
| `agent.revoked` | An agent was cut off |
| `workspace.locked` | The emergency lock was thrown |
| `connection.expired` | A connected account stopped working |
| `credential.revoked` | A stored credential was destroyed |
| `risk.anomaly_detected` | A request was refused by a risk check, not by a rule |

`risk.anomaly_detected` always arrives alongside a `decision.denied` for the same
request. It exists so you can alert on the small set of refusals that mean
somebody tried something — a credential-shaped argument, a private destination,
an intent that did not match the action — without drowning in the much larger
set that mean "no rule allows this", which is the system working as configured.

There is no `decision.allowed`. A webhook per successful read would bury
everything above it; the audit trail is where the complete record lives.

## What an event looks like

```json
{
  "id": "evt_60lhHQrX9Y1uVnNa",
  "type": "workspace.locked",
  "workspace_id": "ws_example",
  "occurred_at": "2026-09-19T09:24:18.117Z",
  "correlation_id": "req_a1b2c3",
  "data": { "human_id": "usr_example", "grants_revoked": 2, "sessions_dropped": 1 }
}
```

Every field is an identifier, a code, a count or a timestamp. **No document
content, no tool arguments, no tokens, no passkey challenges.** `resource_ref` is
a type and an id (`google_file:/Finance/payroll.csv`) — a classification, not the
thing itself. If you need more, ask the API with your own credentials, which is
the point where authorization happens again.

`correlation_id` is the same id that spans the request, the Permit decision, the
approval, the upstream call and the audit event.

## Registering an endpoint

```bash
curl -X POST https://your-veto/v1/webhooks \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"url":"https://hooks.example.com/veto","events":["workspace.locked","agent.revoked"]}'
```

The response carries a `secret`. **It is shown once.** There is no route that
reads it back — a secret you can re-read is a secret that ends up in every log of
every client that ever asked. If you lose it, register a new endpoint.

Two URLs are refused at registration:

- anything that is not `https`
- anything resolving to a private, loopback, link-local or metadata address

The second is checked again before **every** delivery, not only at registration,
because a hostname that resolved to the public internet last week can resolve to
`169.254.169.254` today.

## Verifying a delivery

Three headers arrive with every request:

```
veto-webhook-id:        evt_60lhHQrX9Y1uVnNa
veto-webhook-timestamp: 1789809858
veto-webhook-signature: v1=<base64url>
```

The signature is `HMAC-SHA256(secret, "<id>.<timestamp>.<raw body>")`, base64url.

Check, in this order:

1. The **timestamp** is within your tolerance — five minutes is the default the
   sender assumes. Without this, a captured request replays forever.
2. The **version prefix** is one you know. Refuse `v2=` rather than guessing.
3. The **signature** matches, compared in constant time.
4. The **event id** is one you have not already processed.

Step 4 is the one people skip. Retries reuse the event id and get a *fresh*
timestamp — they have to, or every attempt after the first would fail your
tolerance check. So the id, not the timestamp, is what tells you a delivery is a
duplicate.

Sign over the **raw request body**, before any JSON parse and re-serialise.
Re-serialising changes key order and whitespace, and the signature is over bytes.

`@veto/webhooks` exports `verifyDelivery`, which is the same function the tests
check the sender against. If your receiver is Node, use it rather than writing
the four steps again.

## Retries

Six attempts: immediately, then after 10s, 1m, 5m, 30m and 2h. Any 2xx is
success; anything else is retried.

Two failures are **not** retried, because waiting cannot fix them:

- the destination check refused the URL
- the signing secret could not be opened

After the last attempt the delivery is marked `failed` and stays in the table.
`GET /v1/webhooks/deliveries` shows what arrived, how many times it was tried,
and what the receiver said. "We tried to tell you and could not" is exactly the
fact you want after an incident, so it is kept rather than cleaned up.

## Delivery is not instant, on purpose

Events are written to a queue in the same transaction as the thing they describe,
and a worker drains it. Two consequences worth knowing:

- An event is **never** emitted for something that rolled back, and never missing
  for something that committed.
- A receiver that hangs cannot hold up a decision. The authorization budget is
  200 ms (§11); somebody else's downtime must not be spent out of it.

`POST /v1/webhooks/drain` runs the worker for your workspace, for a deployment
with no scheduler.

## Routing an endpoint to one person

An endpoint is workspace-wide by default: every active endpoint subscribed to
an event receives every one of them. That is right for `workspace.locked` and
`decision.denied`, which are facts about the tenant.

It is wrong for `approval.requested`. Only the delegating user can resolve
their own challenge (invariant 7), so that alert has exactly one correct
recipient — and a workspace-wide endpoint either reaches everybody or reaches a
channel nobody is watching. The event has carried `human_id` since it was
written, with the comment *"an alert about an approval nobody can route is
noise"*. Migration 0029 is the column that routes it.

```
POST /v1/webhooks   { "url": "...", "events": ["approval.requested"], "route_to": "me" }
```

**`route_to` can only say `"me"`.** There is no field for another person's id,
because the only safe answer to "send me somebody else's alerts" is a refusal —
so the request has no way to ask. The server substitutes the authenticated
user, the same shape as a mailbox tool taking its resource from the session
rather than an argument.

Selection happens in SQL, not by filtering afterwards, so an endpoint an event
is not for is never loaded and cannot be delivered to by a later edit that
forgets the check:

```sql
and (route_to_user_id is null or route_to_user_id is not distinct from $3)
```

An event carrying no `human_id` reaches **no** routed endpoint rather than all
of them. A routed endpoint is somebody asking for their own things; an event
about nobody in particular is not one, and failing to deliver is quieter than
failing to withhold.

`(workspace_id, route_to_user_id)` is a composite foreign key, so an endpoint
in one workspace cannot be routed to a user in another — unrepresentable rather
than merely untested.

### The link

`approval.requested` carries `approval_url`, built from `DASHBOARD_PUBLIC_URL`
— the same variable the dashboard builds its own origin from, so the two cannot
drift. It is configuration and never a request value: an origin a caller could
name is an origin a caller could put in an alert somebody is about to click.
Absent configuration means no link, which costs convenience and never safety.

**The link confers nothing.** It carries an approval id and nothing else — no
challenge, no arguments, no resource contents. Resolving still demands a
passkey assertion from the delegating user over that approval's own stored
challenge, and the API refuses anybody else with `APPROVER_NOT_DELEGATOR`. The
page highlights the linked row rather than reordering the list, so two people
looking at the same screen see the same thing.

### What this is not

A Slack **app**. Slack's incoming webhooks are ordinary HTTPS endpoints, so
pasting one in works today — but there is no in-Slack approve button, and the
message is a link that opens the dashboard. An interactive Slack approval is a
different piece of work.

Email is deliberately **not** a channel here. An approval lives five minutes
(`approvalTtlMs`, `pipeline.ts`), nothing in this system stores an email
address, and adding one is a data-minimisation decision rather than a build
task. A notification that lands after the approval expired is worse than none.

