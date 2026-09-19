# Signing up, and being let in

Two different things. Confusing them is how authorization products grow holes.

| | Sign up | Be invited |
| --- | --- | --- |
| Creates | a new workspace, yours, empty | nothing — you join one that exists |
| Who decides | you | whoever runs that workspace |
| Reaches | nothing that existed before | everything that workspace holds |
| Automatic | **yes** | **never** |

Self-service signup is §1.3's first persona — the individual professional, whose
first release is a "self-service dashboard and personal policies". §4.2 says a
tenant is an organization *or a personal workspace*, and the schema has carried
`type in ('personal','organization')` since migration 0001.

## What happens when a stranger signs in

1. Google proves who they are. `openid-client` checks the id token's signature,
   issuer, audience, nonce and expiry.
2. The dashboard asks the API which workspaces that subject belongs to.
3. One of three endings:

| Result | Where they land |
| --- | --- |
| exactly one workspace | straight in |
| none | `/welcome` — name a workspace, get one |
| more than one | `/choose` — pick |

The third used to be a dead end reading *"choosing between them is not built
yet"*. Self-signup makes it reachable on day one: the first person with both a
personal workspace and an employer's invitation hits it.

## The line that keeps signup safe

`provisionPersonalWorkspace` **refuses any subject that already belongs
anywhere.** Without that, "sign up" is a way to collect a second membership, and
the picker starts offering a workspace nobody let you into.

The request also has no field in which to name a tenant:

```json
{ "subject": "oidc|1071308...", "workspace_name": "Ada's workspace" }
```

No workspace id, no user id, no workspace *type*. `additionalProperties: false`,
so adding one is a 400 rather than something quietly ignored.

## How the subject travels

It does not travel in the URL. `/welcome?subject=oidc|<the boss>` would create a
workspace in somebody else's name, and `/choose?workspace=ws_theirs` would hand
out a session for a tenant the visitor was never in.

Instead the OIDC callback — the one place that has verified anything — writes a
signed, ten-minute cookie holding the subject and the candidate list. The pages
read the cookie and never trust their own URL. On `/choose`, the posted
workspace id is *matched against* the sealed list rather than used; an id nobody
offered finds nothing.

That cookie is domain-separated from the sign-in and Google-connect cookies, so
one sealed value cannot be renamed into another. Same key, three meanings.

## Two at once

Uniqueness on `users` is `(workspace_id, identity_subject)` — **not** the subject
alone. So two simultaneous signups would each create their own workspace and
both inserts would succeed, leaving one person with two identical workspaces and
a picker that offers the same thing twice.

The check and the insert therefore run in one transaction behind
`pg_advisory_xact_lock` keyed on the subject. There is a test that fails without
it.

## Operating this

**Inviting somebody to an existing workspace** is still a command:

```bash
pnpm --filter @veto/identity invite -- \
  --subject "oidc|<from the auth log>" \
  --workspace "Acme"
```

**Costs.** Permit bills per tenant. Open signup means strangers creating billable
tenants, which is a real operational cost and the usual reason products put a
waitlist or a domain check in front of it. Nothing here does that yet — if you
open this to the public, that is the next decision, and it is a business one
rather than a security one.

**A new workspace has no rules**, so every request an agent makes is refused.
That is the correct starting state and `/policies` says so on arrival.
