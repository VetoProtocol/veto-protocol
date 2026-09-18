# Sign-in setup (stage 1, phase 6)

The dashboard signs users in with OIDC. It discovers everything from the
issuer's `.well-known/openid-configuration`, so **any conformant provider works
with three environment variables and no code change**.

## 1. Which provider

**Use Google, unless you already have a reason not to.**

The argument is not that Google is the best identity provider — it is that §16
already requires you to register Google OAuth applications for the Workspace
integration (§9). Choosing Google for sign-in means one cloud console, one
consent screen, and one pair of credentials to look after instead of two. It is
free, and it adds no vendor.

Reasons to choose otherwise:

| Situation | Provider |
| --- | --- |
| You need logins that are not Google accounts | Auth0 or Okta — generous free tiers, same three variables |
| You are selling to enterprises that demand their own SSO | WorkOS — built for exactly that, paid |
| You want no third party at all | Keycloak, self-hosted — needs a container runtime, which this machine does not have |

Nothing in the code prefers any of them.

## 2. Register the application (Google)

1. <https://console.cloud.google.com> → create a project.
2. **APIs & Services → OAuth consent screen.** Choose *Internal* if everyone
   signing in is in your Google Workspace organisation, *External* otherwise.
   Fill in an app name and a support email.
3. **Credentials → Create credentials → OAuth client ID → Web application.**
4. Add an authorised redirect URI. It must match `OIDC_REDIRECT_URI` exactly —
   scheme, host, port and path, no trailing slash (§12.1 covers exact redirect
   URI validation):
   ```
   http://localhost:3000/auth/callback
   ```
5. Copy the client ID and client secret.

## 3. Configure

In `.env`:

```bash
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=...apps.googleusercontent.com
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback

# openssl rand -base64 48
DASHBOARD_SESSION_SECRET=...
VETO_CAPABILITY_SECRET=...

VETO_API_URL=http://localhost:4000
DASHBOARD_INSECURE_COOKIES=true   # local HTTP only — never set this in deployment
```

Only `openid` is requested. The dashboard needs a stable subject and nothing
else, and an email address it does not use is one it would have to protect
(§11 data minimisation).

## 4. Invite yourself

**There is no auto-provisioning, on purpose.** If completing a sign-in created a
workspace, every account at your identity provider would be a member of this
system. An unknown subject is refused.

So the first sign-in has to fail once, to tell you your subject:

1. Run both services, open <http://localhost:3000/login>, sign in.
2. You land on "that account is not a member of any workspace here".
3. The API-side log line names the subject:
   ```
   [auth] no workspace for subject oidc|1078...
   ```
4. Create the membership:

```bash
pnpm --filter @veto/identity invite -- --subject "oidc|1078..." --workspace "Your workspace"
```

It prints the workspace and user ids it created. Idempotent on the subject, so
running it twice returns the existing membership rather than forking a second
identity for the same person.

Sign in again and you are in.

## 5. Run it

```bash
pnpm --filter @veto/api start        # control plane on :4000
pnpm --filter @veto/dashboard dev    # dashboard on :3000
```

## How the flow is protected

| Attack | Defence |
| --- | --- |
| CSRF on the callback (§12.1) | `state`, random per attempt, in a signed cookie, compared on return |
| Authorization-code interception | PKCE S256; the verifier never leaves the server |
| Token replay across sessions | `nonce`, bound into the id token and checked on return |
| Forged id token | Signature verified against the provider's JWKS, with issuer, audience and expiry — by `openid-client`, not by hand |
| Open redirect | The redirect URI comes from configuration; no request parameter influences it |
| Session forgery | HMAC over the payload, expiry inside the signed region, constant-time compare |
| Stolen session cookie | `httpOnly`, `secure`, `sameSite=lax`; the credential inside expires in 10 minutes |
| Sign-out by third-party link | `/logout` is POST only |

## Two credentials, two scopes

The dashboard holds the capability signing key and mints its own tokens. There
are exactly two kinds, and the API refuses each at the other's routes:

| Scope | Used for | Lifetime |
| --- | --- | --- |
| `identity-resolve` | One call: subject → user and workspace | 60 s |
| `control-plane` | Everything a signed-in user does | 10 min |

So a leak in either direction is contained: a sign-in credential cannot register
or revoke an agent, and a session credential cannot look up other people's
subjects.

Neither token authorizes anything. They say who is asking; what that person may
do is decided by the pipeline on every request (invariant 8).

## Known gaps

- **One workspace per subject.** If an account belongs to several, sign-in is
  refused with "belongs to more than one workspace" rather than guessing. A
  workspace picker is not built.
- **No invitation flow.** Membership is inserted by hand, as above.
- **No refresh.** After ten minutes the session expires and you sign in again.
  Silent renewal needs a refresh token, which means storing one, which §16 gates
  behind the threat-model sign-off.
