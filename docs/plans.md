# Plans

Which tier a workspace is on, and the command that sets it.

## What a plan is

One column, `workspaces.plan`, with two values: `free` and `pro`. New workspaces
default to `free`.

There is no billing behind it. No payment provider, no subscription table, no
invoices, no dates. A plan is a flag an operator sets, and what decides to set it
is a question for whenever this is actually sold. If real entitlements arrive
later they write to this column rather than replacing every reader.

## Setting it

```bash
pnpm --filter @veto/db plan -- --workspace ws_rpOTIgJbIG91E8Kc --plan pro
```

Both flags are required. `--plan` takes `pro` or `free`.

Output:

```
ws_rpOTIgJbIG91E8Kc (LiveWorkspace1)
free -> pro
Takes effect on the next request; nobody needs to sign in again.
```

It prints the previous value as well as the new one on purpose. The usual
mistake with a command like this is running it against the wrong workspace, and
`free -> pro` under a name you did not expect is the only warning there is.

Setting a plan that is already set changes nothing and says so, rather than
writing a no-op row and reporting a change.

## Finding the workspace id

It is in the path line at the top of every dashboard screen:

```
~/ws_rpOTIgJbIG91E8Kc/policies
```

It is also on every audit and decision row.

**The command cannot list workspaces, and does not try.** Row-level security is
`FORCE`d, so a query with no tenant set reads tenant tables as empty —
`withoutTenant` does not help either, because it does not bypass RLS. A listing
would need a third `security definer` cross-tenant read, and the second one
already brings `threat-model.md` back for review. That is too much to spend on
saving a glance at a URL.

An earlier version of the command did list, and printed `no workspaces` against a
database with three in it. It was failing closed, which was right, and reporting
that as a fact about the database, which was not.

## What `pro` unlocks

**Consent Grants** (`/consent`) — one page for every grant in the workspace:
which agent, what it reaches, who granted it, when it was last actually used, and
what a policy rule permits for it today. Revoke from the same row.

`Agent Fingerprints` and `Shadow Agents` sit in the sidebar under the same badge
and are **not built**. They are labels, not features.

## How the gate works

`GET /v1/grants/consent` returns **402** before it lists, queries or joins
anything. 402 rather than 403: the caller is permitted to ask, and the workspace
is simply not on the tier that answers.

The sidebar hides the link on a free workspace and the page renders an
explanation rather than an error, but neither of those is a control — anybody can
type a URL. The route is the control. `apps/api/test/grants.test.ts` asserts the
refusal happens before any work, because a gate applied afterwards still spends
the Permit call.

The plan is read on every request, never sealed into the session cookie. A plan
in a signed cookie is a plan the server cannot revoke until that cookie expires,
and an upgrade should be visible on the next page rather than the next sign-in.
That is what lets the command say "nobody needs to sign in again" and mean it.

## Running it on the server

```bash
cd /srv/veto
sudo -u veto env PATH=$PATH pnpm --filter @veto/db plan -- --workspace ws_... --plan pro
```

As the `veto` user, because that is the role the application connects as and the
one the RLS policies are written for. Running it as `postgres` would bypass RLS
and work for the wrong reason.
