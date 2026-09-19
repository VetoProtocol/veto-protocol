# Connecting Google (Drive, Gmail, Calendar)

Signing in with Google and *connecting* Google are two different things, and the
difference is worth stating before the setup steps:

| | Sign-in (`docs/auth-setup.md`) | Connection (this file) |
| --- | --- | --- |
| Answers | who is at the keyboard | what Veto may reach on their behalf |
| Scopes | `openid email profile` | `drive.readonly` |
| Stored | nothing | a refresh token, encrypted |
| Redirect | `/auth/callback` | `/connections/google/callback` |

They can share one Google Cloud project and even one OAuth client, provided
**both** redirect URIs are registered on it. They are configured separately —
`OIDC_*` and `GOOGLE_*` — because they are separately revocable, and because a
deployment that signs users in without storing any credential is a valid one.

## 1. Enable the Drive API

<https://console.cloud.google.com> → **APIs & Services → Library** → *Google
Drive API* → **Enable**. The consent flow succeeds without this and every
subsequent call returns 403, which is a confusing place to discover it.

## 2. Add the scopes to the consent screen

**OAuth consent screen → Data access → Add or remove scopes**:

| Scope | For | Google's class |
| --- | --- | --- |
| `.../auth/drive.readonly` | Drive | sensitive |
| `.../auth/gmail.readonly` | Gmail | **restricted** |
| `.../auth/calendar.readonly` | Calendar | sensitive |

On an **Internal** consent screen both cost nothing. On an **External** one, an
app in *Testing* works for the users listed as testers; publishing needs
verification, and `gmail.readonly` is *restricted*, which is the heavier review
— Google may ask for a security assessment. For a pilot, Internal or Testing is
the right answer.

Add only the scopes for the services you will actually use. §9.1 is explicit
that scopes are requested when a feature activates, and a grant Veto cannot
police is worse than no grant.

**Enable each API you want** in APIs & Services → Library: Google Drive API,
Gmail API, Google Calendar API. Consent succeeds without this and every call
then returns 403, which is a confusing place to find out.

## 3. Register the redirect URI

**Credentials → your OAuth 2.0 Client ID → Authorized redirect URIs**:

```
http://localhost:3000/connections/google/callback
```

Exact match, including the port and the absence of a trailing slash. Google
compares the string; there is no normalization to rely on.

## 4. Fill in `.env`

```bash
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:3000/connections/google/callback
```

`GOOGLE_REDIRECT_URI` is read by the **API**, not the dashboard. That is
deliberate: the same process that builds the consent URL is the one that
exchanges the code afterwards, and Google requires the value to be identical in
both. One copy cannot drift out of step with itself.

Restart the API — it reads this at boot, and an unconfigured server answers
`/v1/connections/google/authorize-url` with 503 rather than a broken URL.

## 5. Connect

Dashboard → **connections**. One button per service, and they are separate on
purpose: connect only what you need, when you need it.

Google merges grants on the same OAuth client, so activating Gmail after Drive
leaves the account holding both. That is your decision made twice, which is the
point — what must not happen is one screen asking for everything up front.

What happens, in order:

1. `/connections/google/start` makes a PKCE verifier and a state, seals both in
   a five-minute signed cookie, and asks the API for the consent URL.
2. Google shows the scope list. `access_type=offline` and `prompt=consent` are
   what make it return a refresh token rather than an hour-long access token.
3. `/connections/google/callback` checks the cookie and the state, then hands
   the code and the verifier to the API. The browser never sees what comes back.
4. The API exchanges the code, encrypts the refresh token, and stores it.

The connections table then lists **what Google actually granted**, which is not
always what was asked for — a partial grant shows as a short scope list rather
than being recorded as a full one.

Each upstream call still mints its own narrow token: a Drive read from an
account holding both scopes produces a Drive-only token, never a combined one.

## What Calendar can and cannot do

Two tools: **list** events in a time window — titles, times, locations and how
many people are invited, never the guest list and never the description — and
**read** one event, with its description only when the call asks for it.

The window is capped at 90 days and both ends are required. "Everything from
the beginning of time" is not a request the tool can express.

Only the **primary** calendar. A Google user can often see colleagues'
calendars; there is no calendar argument anywhere, so reaching one is not a
mistake that can be made later.

There is **no create, update or delete**. §9.1 defers writes to a later release,
behind a step-up approval.

## What Gmail can and cannot do

Two tools: **search** returns ids, senders, subjects and dates — never bodies —
and **read** returns one message, with its body only when the call asks for it.

There is **no send tool and no send scope**. Sending is not something the
product declines to do; it is something it has no way to do (§9.1).

An agent can only ever reach the mailbox and calendar of the person who
delegated to it. Both are taken from the session, not from a tool argument, so
"read someone else's mail" is not a request that can be expressed.

## One note about the first call

The first check against a resource type Permit has only just learned about can
come back as *unavailable* rather than *deny* while the PDP catches up. Both
refuse the request; the reason code differs (`POLICY_UNAVAILABLE` rather than
`POLICY_DENIED`). Re-run the bootstrap before a pilot rather than during one.

## Things that go wrong

| Symptom | Cause |
| --- | --- |
| `redirect_uri_mismatch` at Google | Step 3, or `GOOGLE_REDIRECT_URI` differs from what is registered |
| "Google is not set up on this server yet" | `GOOGLE_CLIENT_ID` empty, or the API was not restarted |
| "That authorization could not be completed" | Usually no refresh token came back — a stale consent. Remove the app at <https://myaccount.google.com/permissions> and connect again |
| "That attempt timed out" | More than five minutes on the consent screen |
| "That response did not match the attempt that started here" | The callback did not come from a flow this browser started. This is the CSRF refusal (§12.1) working |

## Disconnecting

**disconnect** destroys the stored credential here *first*, then asks Google to
revoke it. The order matters: an outage at Google leaves the credential already
unusable in Veto rather than live while something retries. If the second step
fails the dashboard says so and points at
<https://myaccount.google.com/permissions>, because silence would be the
misleading version.
