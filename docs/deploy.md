# Deploying Veto

One VPS, everything on it, serving a public SaaS. That is the shape this
document describes, and every choice below follows from it.

It is written for the person who has to do it, not for the person who decided
it. Where something is dangerous it says so; where something is missing it says
that too, rather than leaving you to find out on the box.

> **This deployment has no redundancy.** One machine runs the database, the
> cache, the decision point and all three services. That is a reasonable pilot
> (§13 stage 6 targets five design partners) and an unreasonable place to keep
> paying customers. Decide that on purpose.

## Before the box

Two things are not on the critical path of this document and are on the
critical path of the product:

1. **Google verification** (`docs/google-verification.md`). Public sign-up with
   `drive.readonly` and `gmail.readonly` needs a review measured in months. Start
   it before you provision anything.
2. **Publish the Google app today.** An app in *Testing* hands out refresh
   tokens that expire after seven days. Deployed, that means every connected
   account breaks weekly, surfacing as `CONNECTION_EXPIRED` — a message that
   reads like a revoked credential and is not one.

Also outstanding, and a decision rather than a task: `docs/threat-model.md` §9
is reviewed but **not accepted**. The §8 authorization server introduced
Boundary 6 and four residual risks that await the owner's sign-off. Putting
other people's mail behind an unaccepted threat model is a choice somebody
should make deliberately.

## What the server needs

| | |
| --- | --- |
| OS | Debian 12 or Ubuntu 22.04+ |
| RAM | 4 GB minimum. Postgres, Redis, the PDP container and three Node processes |
| Node | 22 or newer — the services run `--experimental-strip-types` |
| Also | `pnpm`, PostgreSQL 17, Redis, **podman or docker**, Caddy |

The container runtime is **not optional**. See the next section.

## 1. The PDP, and why it is first

The Permit decision point must run **on this machine**. This is the single most
consequential line in the file, so it comes before anything else.

Hosted was measured at p50 ~225 ms and p95 up to 739 ms per check, with roughly
one call in four hitting the 5 s ceiling and failing closed with
`POLICY_UNAVAILABLE`. The fastest single hosted check exceeded the whole §11
200 ms budget on its own. Local measures p50 6.8 ms / p95 8.9 ms, and end-to-end
authorization overhead on a real gateway call went from ~1967 ms to ~11 ms.

```bash
podman run -d --name veto-pdp --restart=always \
  -p 127.0.0.1:7766:7000 \
  -e PDP_API_KEY="$PERMIT_API_KEY" \
  docker.io/permitio/pdp-v2:latest
```

**`.env.example` still points at `https://cloudpdp.api.permit.io`.** That file is
what anyone will copy when writing the production environment, and copying it
reverts every number above. Set `PERMIT_PDP_URL=http://localhost:7766` and check
it twice.

Bind it to `127.0.0.1`. The PDP answers policy questions with no authentication
of its own; it must not be reachable from the internet.

## 2. Postgres and Redis

Both local, both bound to loopback.

```bash
sudo -u postgres createuser veto --pwprompt
sudo -u postgres createdb veto --owner veto
```

Row-level security is `FORCE`d because the `veto` role owns the tables. Do not
grant that role `BYPASSRLS`, and do not run the app as a superuser — either one
turns invariant 4 off everywhere at once, silently.

Redis needs no persistence. It holds nonces, challenges, rate counters and
session coordination; losing it costs in-flight challenges, not data.

## 3. Secrets

Generate fresh ones. Never carry a development secret onto a public box.

```bash
openssl rand -base64 32   # VAULT_MASTER_KEY
openssl rand -base64 32   # DASHBOARD_SESSION_SECRET
openssl rand -base64 32   # VETO_CAPABILITY_SECRET
```

**`VAULT_MASTER_KEY` has no recovery.** It wraps the data keys that encrypt every
stored Google credential. Lose it and every connection in the database becomes
unreadable — not revoked, unreadable. Back it up somewhere that is not this
machine, before you store the first credential.

It also sits in the process environment, which means anything that can read the
environment can unwrap every data key. That is a known, accepted residual risk
(`docs/threat-model.md`), and production is meant to swap the `KeyWrapper`
implementation for a KMS rather than change its callers. Until that happens,
treat shell access to this box as equivalent to access to every customer's mail.

## 4. The environment file

Every entry point loads the repo-root `.env`, and anything already in the
environment wins over it. These are the values that must change from their
development defaults — the rest of `.env.example` carries its own notes.

| Key | Development | Production |
| --- | --- | --- |
| `NODE_ENV` | `development` | `production` |
| `PERMIT_PDP_URL` | — | `http://localhost:7766` |
| `PERMIT_ENV` | `development` | a **separate** production environment, with its own key |
| `DASHBOARD_INSECURE_COOKIES` | `true` | **`false`** |
| `WEBAUTHN_RP_ID` | `localhost` | `veto.example.com` |
| `WEBAUTHN_ORIGINS` | `http://localhost:3000` | `https://veto.example.com` |
| `OIDC_REDIRECT_URI` | `http://localhost:3000/...` | the `https://` form |
| `GOOGLE_REDIRECT_URI` | `http://localhost:3000/...` | the `https://` form |
| `VETO_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:4100/mcp` | `https://veto.example.com/mcp` |
| `VETO_API_URL` | `http://localhost:4000` | unchanged — internal only |
| `API_HOST` | `127.0.0.1` | unchanged — see below |

Two of these break things in ways that are hard to recognise:

**WebAuthn is bound to the domain.** A passkey enrolled against one `RP_ID` is
worthless against another, and a passkey assertion is the *only* way to resolve
a challenge — there is no fallback, deliberately. Get `WEBAUTHN_RP_ID` or
`WEBAUTHN_ORIGINS` wrong and approvals do not degrade, they stop.

**`API_HOST` stays on loopback.** The control plane and the gateway sit behind
Caddy on the same machine. Changing it to `0.0.0.0` without a firewall exposes
the control plane directly; the API is not an enforcement point and was never
designed to face the internet.

Separately: the Permit **production** environment must be its own environment
with its own keys. Leaving `PERMIT_ENV=development` mixes paying customers with
whatever test data you have accumulated — and resource-instance keys are unique
per environment, not per tenant.

## 5. Migrations

```bash
pnpm install --prod=false
pnpm --filter @veto/db migrate
```

Migrations are immutable once applied: the runner records a checksum and refuses
to run if an applied file changed on disk. If it refuses, something edited
history — do not force it, write a new migration.

## 6. systemd

Three units. The critical detail is the `ExecStart` line.

```ini
# /etc/systemd/system/veto-api.service
[Unit]
Description=Veto control plane
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=veto
WorkingDirectory=/srv/veto
ExecStart=/usr/bin/pnpm --filter @veto/api start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The same shape for `@veto/gateway` and `@veto/dashboard`.

**Call `pnpm … start`, never `node` directly.** The `start` scripts carry
`--dns-result-order=ipv4first --no-network-family-autoselection`. Node otherwise
races IPv4 and IPv6, and on a host whose IPv6 route to Google is black-holed it
keeps choosing the dead one: roughly two calls in three fail with `ETIMEDOUT`,
and what reaches the user is `CONNECTION_EXPIRED` — "the connected account could
not be used" — which reads as a credential problem and is not one. `curl` does
not race, which is why every hand-run check looks healthy. A unit that invokes
`node` itself drops those flags and brings the whole failure back.

The dashboard serves a build. Rebuild before restarting it, or you will restart
into the previous version and debug a fix that is not running:

```bash
pnpm --filter @veto/dashboard build && systemctl restart veto-dashboard
```

Each service logs one line per dependency at boot — Postgres, Redis, the PDP and
Google's token endpoint. Read them. Only Postgres is fatal; a service that
cannot reach Permit denies every protected request, which is correct, while one
that refuses to boot cannot be restarted into a recovering system.

## 7. Caddy

```caddyfile
veto.example.com {
	encode gzip

	# The MCP enforcement point. Long-lived streaming responses.
	handle /mcp* {
		reverse_proxy 127.0.0.1:4100 {
			flush_interval -1
		}
	}

	handle /.well-known/oauth-protected-resource* {
		reverse_proxy 127.0.0.1:4100
	}

	handle {
		reverse_proxy 127.0.0.1:3000
	}
}
```

Caddy obtains and renews certificates itself. TLS is not optional here: cookies
are `Secure` in production, WebAuthn requires a secure context, and Google will
not accept a plaintext redirect URI.

The control plane on :4000 is **not** proxied. Nothing outside the box talks to
it.

## 8. Google console

Update both redirect URIs on the OAuth client to their `https://` forms. Google
matches them exactly — the API builds the consent URL and exchanges the code, so
there is only one copy of each, and a mismatch fails at exchange rather than at
redirect.

Enable each API you actually use, and add only the scopes for services you
actually ship. Every restricted scope you declare widens the assessment in
`docs/google-verification.md` and is something you must justify.

## 9. Prove it works

Ports listening is not the same as working. Check responses:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://veto.example.com/            # 307
curl -s https://veto.example.com/.well-known/oauth-protected-resource         # 200 + JSON
curl -s localhost:7766/healthy                                                # opa + horizon ok
```

A `401` from the API or the gateway is the correct answer to an unauthenticated
request, not a fault. Both should carry `IDENTITY_UNRESOLVED`.

Then drive the real thing: connect a Google account, register an agent, grant it
a folder, write a rule, and call a tool from an MCP client. Every significant bug
found in this system was found by using it like a person, not by reading it.

## 10. Backups

```bash
pg_dump "$DATABASE_URL" | gzip > /var/backups/veto-$(date +%F).sql.gz
```

Nightly, copied **off the machine**. A backup on the box it protects is not a
backup.

Test a restore before you need one. And keep `VAULT_MASTER_KEY` with the
backups' custodian but not in the same place as the dump: the dump without the
key is inert, which is the property you want, and the key without a copy is a
total loss.

## What this does not give you

Named so nobody discovers them later:

- **No redundancy.** One box. A reboot is an outage.
- **No KMS.** `VAULT_MASTER_KEY` is in the environment.
- **No telemetry export.** Per-step decision timings are measured and stored on
  each `decisions` row, and shown in the dashboard, but no OpenTelemetry
  collector receives them. `latency_ms` is steps 1–7 only — the pipeline decides
  and never fetches, so the upstream call is not in that number.
- **No privacy policy or terms pages.** Both are verification requirements and
  neither exists.
- **An unknown Permit tenant ceiling.** Unexplained 500s appeared around 93
  tenants and probing never established a clean limit. One workspace is one
  Permit tenant, so for a public SaaS this is a scaling question with a real
  answer somebody at Permit can give you. Ask in writing before you sell.

## Runbook

```bash
systemctl restart veto-api veto-gateway            # services run from source
pnpm --filter @veto/dashboard build && systemctl restart veto-dashboard
journalctl -u veto-gateway -f                      # follow one service
pnpm --filter @veto/db migrate                     # apply pending migrations
podman restart veto-pdp                            # decision point
curl -XPOST localhost:4000/v1/webhooks/drain -H "authorization: Bearer $TOK" -d '{}'
```

The webhook scheduler runs in-process in every API instance, on a five-second
tick. `drainDeliveries` claims rows `for update skip locked`, so two instances
split the queue rather than both sending the same event. `WEBHOOK_SCHEDULER=off`
disables it if you would rather drive delivery from outside.
