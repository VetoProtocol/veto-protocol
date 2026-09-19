# Connecting Google Drive (stage 2, browser half)

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

## 2. Add the scope to the consent screen

**OAuth consent screen → Data access → Add or remove scopes** →
`https://www.googleapis.com/auth/drive.readonly`.

Google classifies this as a *sensitive* scope. On an **Internal** consent screen
that costs nothing. On an **External** one, an app in *Testing* works for the
users listed as testers, and publishing it needs Google's verification review.
For a pilot, Internal or Testing is the right answer.

Do not add Gmail or Calendar scopes. §9.1 is explicit that scopes are requested
when a feature activates, and nothing here enforces rules on either yet — a
grant Veto cannot police is worse than no grant.

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

Dashboard → **connections** → *Connect Google Drive*.

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
