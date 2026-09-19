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
