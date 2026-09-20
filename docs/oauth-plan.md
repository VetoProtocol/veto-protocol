# Plan: the OAuth authorization server

**Status:** plan, not a licence. Nothing here is built.
**Written:** 2026-09-20
**Blocks:** §13 stage 6 — pilot with design partners.

---

## The problem, stated exactly

Connecting an MCP client today means hand-editing a JSON file that names a
script on the server's own disk. The Agents screen generates that file, which
makes it copyable rather than folklore, but does not change what it is: the
bridge reads `VETO_CAPABILITY_SECRET` from the server's environment, so it only
runs on the machine running Veto.

Onboarding a customer therefore means giving them shell access to the host.

§8 asks for "OAuth 2.1-compatible discovery and protected-resource metadata".
Half of that exists. `apps/gateway/src/app.ts` serves
`/.well-known/oauth-protected-resource`, and a 401 carries
`WWW-Authenticate: Bearer resource_metadata="…"`, so a conforming client already
discovers where it should go.

Where it goes is `GATEWAY_AUTH_SERVER`, which defaults to `http://localhost:3000`
— the dashboard. The dashboard has no `/authorize`, no `/token`, and no client
registration, so a correct client follows the trail and finds nothing.

---

## The fact that makes this safe to build

**The gateway does not change.**

It already accepts a capability token: HMAC, audience-pinned to
`veto-gateway`, carrying workspace, human, agent and scope, with a
fifteen-minute ceiling. `session.ts` verifies it and reads the agent's row on
every request, so a revoked agent is refused whatever it holds.

This work builds a standards-compliant way to *obtain* that token. Nothing in
the decision path, the gateway, or the existing bridge is touched. The bridge
keeps working throughout, and is deleted at the end rather than migrated.

That is the whole risk posture: new routes, new tables, one new package. No
edits to code that currently serves a request.

---

## What a client actually needs

From the MCP authorization spec and RFC 9700, a conforming client will:

1. Get a 401 from the gateway, read `resource_metadata`, fetch it
2. Fetch `/.well-known/oauth-authorization-server` from the named server
3. **Register itself** — it has no client id, and nobody is going to issue one
   by hand to every customer's laptop (RFC 7591)
4. Open a browser at `/authorize` with PKCE and a `resource` indicator
5. Exchange the code at `/token`
6. Refresh when the access token expires

Steps 3 and 6 are the ones that are easy to skip and then discover.

---

## Design decisions, with the reasoning

### The access token is the capability token we already have

`/token` mints exactly what `gatewayToken` mints today. The gateway's verifier
is untouched, and a token obtained through OAuth is indistinguishable from one
the bridge made — which is the point.

**Consequence: fifteen minutes.** `MAX_TTL_MS` caps it, and raising that ceiling
to suit a client is the wrong direction. So refresh tokens are not optional —
without them a client dies mid-session, which is the failure the bridge already
works around by minting per request.

### Refresh tokens are stored hashed, and rotate

A refresh token is a long-lived credential for a workspace. It is stored as a
hash, never in plaintext, for the same reason the vault never returns a refresh
token for Google: a database read should not yield a working credential.

Rotation on use, with reuse detection. A refresh token presented twice means
either a race or a theft, and the safe response to both is to revoke the whole
chain. This is the one place where a false positive costs a re-authorization and
a false negative costs an account.

### Authorization codes live in Redis, single use, sixty seconds

Same store and same reasoning as approval challenges. A code that survives its
exchange is a replay; a code that outlives the browser redirect is a window
nobody needs.

### PKCE is required, not offered

S256 only. `plain` exists in the RFC and is refused here — a downgrade a server
accepts is a downgrade an attacker selects.

### Registration is open, and that is deliberate

RFC 7591 dynamic registration with no authentication, because a desktop client
on a customer's laptop has no credential to present and no way to get one.

**What stops that being a hole:** a registered client can do nothing. It can ask
a human to approve it, and the human sees what they are approving. Registration
creates a name, not an authority. The rate limit on the endpoint is an
availability control and never a substitute for that (§ conventions).

### The consent screen is the product

It names the agent, the workspace, and what the agent will be able to *ask* for
— not what it will be allowed to do, because that is a policy question answered
per request, later, by the pipeline. Saying "this app will read your Drive"
would be a lie: it will be able to ask, and every ask gets a decision.

Getting that sentence right matters more than the protocol work around it. It is
the screen a customer judges the product by, and the one place where the whole
"continuous consent" claim is either true or marketing.

### One human, one agent, one grant

`/authorize` runs as the signed-in dashboard human. The agent is either chosen
from their existing agents or registered there and then. The resulting token
carries that human and that agent, so §7.1's "only the original delegating user
may approve" holds by construction, and the delegator tuple Permit already
stores is written by the same path it is today.

### Resource indicators

`resource` (RFC 8707) is required and must name the gateway. The token's
audience is set from it. A token minted for the control plane must not be
accepted by the gateway, which is already true — this keeps it true when a
client is the one asking.

---

## Shape of the work

| Phase | What | Touches |
| --- | --- | --- |
| 1 | Migration: `oauth_clients`, `oauth_refresh_tokens` | new tables only |
| 2 | `packages/oauth`: codes, PKCE, token issuance, rotation, reuse detection | new package |
| 3 | `/.well-known/oauth-authorization-server` + `/register` | new routes |
| 4 | `/authorize` — the consent screen | new route, existing session |
| 5 | `/token` — code exchange and refresh | new route |
| 6 | Adversarial tests | new |
| 7 | Point `GATEWAY_AUTH_SERVER` at it, connect a real client end to end | config |
| 8 | Delete the bridge, and the CONNECT panel's caveat with it | removal |

Phases 1–6 change nothing that currently serves a request. Phase 7 is one
environment variable. Phase 8 is the only removal, and happens only after a real
client has connected without the bridge.

---

## The attack tests, before the features (§12.1 rule)

- Authorization code replayed after exchange
- Code redeemed by a different client than requested it
- PKCE verifier that does not match the challenge
- `plain` PKCE method offered and refused
- Redirect URI not exactly as registered — including a prefix match and an open
  redirect in the query
- Refresh token reused after rotation → whole chain revoked
- Refresh token from workspace A presented for workspace B
- Token minted for the control plane presented to the gateway
- `resource` omitted, or naming something that is not the gateway
- Consent approved by a human who is not the one signed in
- Registration flood — rate limited, and still never granting anything
- Agent revoked between consent and exchange
- Workspace locked between consent and exchange

Each of these is a test before the endpoint it targets exists.

---

## What could go wrong, honestly

**The consent screen is harder than the protocol.** Explaining "this agent can
ask; every ask is decided" in a sentence a person reads in two seconds is the
real work. Expect to rewrite it more than once.

**MCP client behaviour varies.** The spec is young. Claude Desktop, Cursor and
Codex may each want something slightly different, and the first real client will
find something this plan did not anticipate. Phase 7 is where that happens, and
it is deliberately before the bridge is deleted.

**Fifteen minutes is short.** If a client refreshes badly — no jitter, no
backoff — the token endpoint sees a stampede. Worth watching once a real client
is on it.

**This is a new trust boundary.** Anyone on the network can register a client
and start an authorization. The threat model was signed off on 2026-09-18 for a
system whose only front door was a config file. It does not cover this, and
`docs/threat-model.md` says a new trust boundary brings the document back for
review. **That review happens before phase 7**, not after — phases 1–6 build
something nothing points at yet, which is safe; turning it on is the change that
needs the sign-off.
