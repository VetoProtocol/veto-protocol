# Next steps

Written 2026-09-20, after a full walkthrough of the product from an empty
workspace to a revoked agent. Ordered by what unblocks whom, not by size.

Nothing here is started. `docs/writes-plan.md` is the model: a plan is not a
licence, and §13's build order still applies.

---

## 1. OAuth authorization server (§8) — blocks the pilot

**The front door does not exist.**

A customer connects an MCP client today by hand-editing a config file that names
a bridge script on the server's own disk. The Agents screen now generates that
config, which makes it copyable rather than folklore, but does not change what
it is: the bridge holds the capability signing key, so it only runs on the
machine running Veto.

§8 describes the supported path. Half of it is built — the gateway serves
`/.well-known/oauth-protected-resource` and names an authorization server. That
server has no `/authorize`, no `/token`, and no client registration, so a client
that follows discovery correctly gets as far as the document and stops.

Until it exists, onboarding a customer means giving them shell access to the
host. That is not a product, and it is the single thing standing between the
current state and §13 stage 6.

What it needs, roughly:

- `/authorize` with PKCE and exact redirect-URI validation, consenting as the
  signed-in human and naming the agent being authorized
- `/token`, issuing a credential the gateway already knows how to verify
- Dynamic client registration, or a registration screen — an MCP client arriving
  cold has no client id
- A consent screen that names the agent, the workspace, and what it will be able
  to ask for. This is the screen a customer judges the product by.

The existing capability tokens are the right shape already: audience-pinned,
scope-asserted, fifteen-minute ceiling. The work is the flow around them, not a
new token format.

**Leaves the desktop bridge as what it says it is** — a development stopgap that
should then be deleted rather than left as a second way in.

---

## 2. Sign in with a wallet (MetaMask) — asked for, not yet justified

**Possible, cheap, and pointing the opposite way to the spec.**

Every mention of wallets in `veto-protocol-spec.md` treats a wallet as something
Veto *protects*: "restrict automated wallet actions" (§1.3), "enforce wallet
limits through a smart-account integration" (FR-12), `wallet` and `contract` as
resource types (§4.2). Signing *in* with one is not in the spec at all — it is a
new idea, not a deferred one, and should not be filed under the Web3 deferral as
though the spec had already argued for it.

The mechanics are straightforward. EIP-4361 (Sign-In With Ethereum): a nonce, a
signed message, a signature verified server-side with viem. `identity_subject`
is free text and already namespaced — `eth|0xabc…` sits beside `oidc|usr_x`
without a migration. Half a day for the happy path.

Three reasons to hold it behind the OAuth server:

- **No recovery.** A lost key is a lost workspace, and that workspace holds a
  live OAuth grant to somebody's Drive. A security product whose accounts cannot
  be recovered is a strange thing to ship.
- **A signature proves key control, not identity.** OIDC establishes a verified
  address at a real provider, which is what a B2B tenant boundary is built on. A
  wallet establishes that somebody holds a key.
- **It unblocks nobody.** The OAuth server unblocks every customer. This
  unblocks no one who is currently blocked.

**When it becomes right:** a design partner who is crypto-native asks for it. At
that point build it alongside the wallet-*protection* work FR-12 describes,
because that is the half the spec argued for and the half that is differentiated.

---

## 2b. Availability, which §9 barely covered

The threat model reads confidentiality well and disruption badly. Three things
were checked on 2026-09-21; two turned out to be real and are fixed.

- **Unbounded tables.** Nothing removed a spent refresh token, a revoked chain
  or a client that registered once and never returned — 1,648 client rows after
  one day of testing, on a table an anonymous caller can add to.
  `POST /v1/oauth/prune` now clears both, conservatively: a spent token survives
  seven days because a rotated token is what makes a *reuse* recognisable, and a
  client is only removed if nothing ever descended from it.
- **Redis was a hard dependency of the token endpoint.** The rate-limit counter
  was unguarded, so a Redis blip meant a 500 and nobody could authenticate. It
  now fails **open**: a rate limit is an availability control and never
  authorization, and refusing everybody because the counter is unavailable is
  the flood winning without anybody flooding.
- **The Permit tenant ceiling was a guess, and the guess was wrong.** Yesterday's
  500s at 93 tenants were read as a quota because deleting 91 coincided with
  recovery. Probing found no ceiling below 43 with the account at 3, so the
  cause is unknown and "quota" should not be planned around. Worth settling with
  Permit directly before customer count depends on it.

## 3. Smaller, and found the same day

- **The live Permit suite leaks a tenant per run.** `permit-facts.live.test.ts`
  creates one and never deletes it. 91 accumulated and exhausted the account's
  quota, which surfaced as a 500 from Permit's tenants API and a
  `POLICY_UNAVAILABLE` on agent registration — a failure with no obvious
  connection to its cause. The suite should clean up after itself.
- ~~**Passkey enrolment has no browser half.**~~ **Wrong — it always had one.**
  `EnrolPasskey` sits on `/approvals` beside `ResolveApproval`, and
  `tools/e2e/passkey-enrol.ts` now proves both with a virtual authenticator:
  enrol a device, be challenged by an away-state read, resolve it with a
  signature. The claim survived three separate write-ups of this list because
  nobody opened the page.
- **Webhook delivery has no scheduler.** `/alerts` has a "deliver now" button,
  which is honest about there being no cron rather than draining on render.
- **Per-step timings are recorded and shown, not exported.** The decision trace
  reads them from the decision row. Emitting them as OpenTelemetry spans is
  deliberately not done — an exporter pointed at no backend adds a dependency
  and the auto-instrumentation risk of capturing URLs, for an answer nobody can
  read yet.
- **The CONNECT snippet says "paste this into your config"** without saying what
  to replace. Pasted into a file that already had one, it produces two JSON
  documents and a client that will not start.

---

## What is deliberately not here

Writes and CRUD. `docs/writes-plan.md` stands, and so does the reason it is
parked: §13's twelve weeks are read-only end to end, a write path is a new trust
boundary, and the §8 threat-model sign-off covered a system that only reads.
