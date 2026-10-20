# Microsoft 365 app setup

What the Microsoft side needs, and the three things that were measured rather
than assumed before any of this was written.

## What was measured first

Three questions decide the shape of the code, and guessing any of them wrong
costs a round of rework on a live connection. Each was settled against the
protocol reference, not from memory (§15).

### 1. Microsoft narrows at mint time. Like GitHub, unlike Google.

The refresh grant accepts a `scope` parameter, and the reference is explicit:

> The scopes requested in this leg must be equivalent to or a subset of the
> scopes requested in the original `authorization_code` request leg.

So `UPSTREAM_FOR_TOOL` is **real narrowing** here, not a bookkeeping check. A
calendar read receives a token that physically cannot read mail, the same way a
GitHub issue read receives one that cannot read a file. That is asserted in
`apps/gateway/test/microsoft.test.ts` against a connection holding both
scopes, so the narrowness is a choice rather than the only thing on offer.

One constraint comes with it: every scope in a single refresh must belong to
**one resource**. If they span two, Microsoft issues a token for whichever
resource the first scope names and silently ignores the rest. All scopes here
are Graph, so the rule is satisfied by construction — but a future non-Graph
scope cannot simply be added to an existing tool's list.

### 2. The refresh token rotates on every use, and the old one keeps working.

> Replace the old refresh token with this newly acquired refresh token to
> ensure your refresh tokens remain valid for as long as possible.

Slack already forced `AccessGrant.rotatedRefreshToken` and
`rotateRefreshToken()` into existence, so this costs nothing new. It would
have cost a great deal to discover: dropping the replacement does not fail on
the next call, it fails on the one after that, hours later, on a connection
nobody has touched.

Microsoft adds a wrinkle Slack does not have — it does **not** invalidate the
old refresh token when it issues a new one. The reference says to discard the
old one yourself. `rotateRefreshToken()` overwrites the ciphertext in place,
so there is no second copy to leak.

### 3. There is no way to revoke one refresh token. This is a real gap.

Google has a revocation endpoint. Slack has `auth.revoke`. GitHub has an
installation to delete. Microsoft has **neither** an RFC 7009 revocation
endpoint nor any per-token equivalent.

The nearest thing is Graph's `revokeSignInSessions`, and it is not usable here
for two reasons:

| Problem | Why it rules it out |
| --- | --- |
| It revokes **every** application's refresh tokens for that user | Revoking Veto's access would sign the person out of Outlook, Teams and everything else. A control with that blast radius is worse than the thing it fixes |
| It needs `User.RevokeSessions.All` | An administrator permission, on a connection that otherwise asks only to read |

So Microsoft is the first provider here where **revocation is local only**:

- the connection row moves to `revoked` and its ciphertext is destroyed,
- outstanding grants and live sessions die exactly as they do for every other
  provider (`packages/decisions/src/revocation.ts`),
- and **nothing is called upstream**, because there is nothing honest to call.

What that means in practice: after revoking in Veto, this server can no longer
use the credential and no agent can reach Microsoft through it. The *grant* on
the Microsoft side still exists until the person removes it at
<https://myapplications.microsoft.com> → the app → **Revoke permissions**. The
`/connections` screen says so rather than implying a reach it does not have.

`revoke()` therefore has no provider call and a comment saying why. A
best-effort call to a wildly broader endpoint would be worse than none: it
would read as a tighter control than it is.

## Which accounts can connect

The app is registered for **accounts in any organizational directory**
(`organizations` in the URL path), not `common`.

`common` also admits personal Microsoft accounts, whose Graph surface differs
enough to need its own testing, and whose mailbox is not a Microsoft 365
mailbox. The product says Microsoft 365; the registration says the same thing.

## Creating the app registration

Microsoft Entra admin center → **App registrations** → **New registration**.

| Field | Value |
| --- | --- |
| Name | anything — the consent screen shows it |
| Supported account types | **Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)** |
| Redirect URI | **Web** → `https://<your-origin>/connections/microsoft/callback` |

The redirect URI type must be **Web**, not **SPA**. A `spa` redirect gets a
refresh token that expires after 24 hours and cannot carry a client secret —
both fatal for a server-side connection that must keep working unattended.

### API permissions

**API permissions** → **Add a permission** → **Microsoft Graph** →
**Delegated permissions**:

| Scope | For | Admin consent needed |
| --- | --- | --- |
| `offline_access` | the refresh token itself | no |
| `User.Read` | reading the connected account's own identity | no |
| `Mail.Read` | searching and reading mail | no |
| `Calendars.Read` | listing and reading events | no |

`offline_access` is not optional. Without it Microsoft returns an access token
and no refresh token, the connection works for an hour and then dies — so the
code exchange **refuses** an install that comes back without one, the same way
Google's and Slack's do, and the message names the scope.

None of these require an administrator *by default*. A tenant that has turned
off user consent needs an administrator to approve the app once, and the
failure then reads as `consent_required` rather than as a bad secret.

There is no write scope here and no send scope. "Do not send mail" is not a
rule anybody has to write, because the capability was never requested.

### A client secret

**Certificates & secrets** → **New client secret**. Copy the **Value**, not
the Secret ID.

## Credentials

Three values, all on the API and never on the gateway:

```
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_REDIRECT_URI=https://<your-origin>/connections/microsoft/callback
```

Leave `MICROSOFT_CLIENT_ID` empty and Microsoft is disabled entirely: the
routes refuse to begin rather than taking a caller's word for anything.
Connections already on file are unaffected.

In production, set them with the helper script rather than by editing the file
by hand:

```bash
/srv/veto/set-microsoft.sh
```

It prompts silently, echoes nothing, and passes no value as a command-line
argument — a secret in `argv` is readable by every process on the box.

## Connecting it

`/connections` → **Microsoft 365** → **Mail** or **Calendar**.

Consent is **per service**, as it is for Google (§9.1). Activating calendar
after mail leaves the account holding both, which is the person's decision made
twice — what must not happen is one screen asking for both before either
feature exists.

Each service becomes its own connection row holding only its own scope, so a
mail read cannot borrow the calendar connection's token.

## What the tools can do

| Tool | Reads | Bound |
| --- | --- | --- |
| `microsoft_mail.search_messages` | message headers matching a query | page size |
| `microsoft_mail.read_message` | one message by id | — |
| `microsoft_calendar.list_events` | events in a window | `MAX_WINDOW_DAYS` |
| `microsoft_calendar.read_event` | one event by id | — |

The mailbox and the calendar belong to **the session's human**, read from
`GatewaySession` — there is no argument an agent could put somebody else's id
in. The message or event id stays in `arguments`, where the action digest
covers it.

## OneDrive and SharePoint are deliberately not here

A file is not yet a resource this system can key.

Permit resource-instance keys must match `^[A-Za-z0-9\-_]+$`. Drive item ids
and SharePoint drive ids do not reliably fit: ids of the form
`0123456789abcdef!123` and `b!…` carry a `!`, which the grammar refuses. That
is the same wall real Drive *paths* hit, and the honest answer is that a
measurement on a real tenant decides it, not an assumption here.

Mail and calendar have no such problem — their resource is the human, keyed by
a Veto user id — which is why they ship first and files wait for their own
phase with the measurement in hand.
