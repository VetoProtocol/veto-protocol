# Grants — connecting an agent to a resource

A grant and a policy rule are different things, and the difference is the one
most likely to cost somebody an afternoon.

| | Grant | Rule |
| --- | --- | --- |
| Answers | is this agent connected to that folder at all | under what conditions may it be used |
| Owned by | Permit | Veto |
| Runs at | §3.3 step 5 | §3.3 step 4 |
| Can it grant access | yes, that is its job | no — it can only narrow |
| Inherits | yes, folder to file | no |

**Both must say yes.** An allow rule for a folder nobody granted is refused at
step 5, correctly, and the dashboard says so on the policies screen.

## Why they are not derived from each other

It would be convenient if writing an allow rule also wrote the matching grant.
It would also make Permit agree with Veto by construction, and the second
opinion invariant 3 asks for would be a mirror of the first. Two engines that
cannot disagree are one engine with extra latency.

## Resource ids, not paths

Permit validates resource-instance keys against `^[A-Za-z0-9\-_]+$`. A Google
Drive id is exactly that alphabet:

```
https://drive.google.com/drive/folders/1a2B3c-_9zYxQwErTy   →  1a2B3c-_9zYxQwErTy
https://docs.google.com/document/d/1XyZ_fileId42q/edit      →  1XyZ_fileId42q
```

A path like `/Work/plan.txt` is refused with a 400 that says so. This is the
same class of surprise as the colon in Permit user keys (see
`packages/permit/src/model.ts`) — the API's grammar is narrower than the spec's
examples suggest.

> **Note on the rest of the system.** Veto's own policy filters (`prefix`,
> `ids`) and sensitivity labels match on whatever string the tool call names as
> the resource. Today's test fixtures use path-like strings; production will use
> Drive ids, and a prefix match over opaque ids means much less than a prefix
> match over paths. That is a real tension and it is not resolved yet.

## Folder to file

The bootstrap declares that a reader of a folder is a reader of every file whose
`parent` is that folder. One direction only: being granted a file says nothing
about the folder it sits in, so §12.1's "authorized for one file, asks for the
whole folder" stays a denial.

**The inheritance does not fire yet**, because nothing writes the `parent`
tuple. Drive knows which folder a file is in; Veto learns that only when it
reads the file, and step 8 does not currently record it. Until it does:

- granting a **folder** works for folder actions (`list_folder`)
- granting a **file** works for that file
- granting a folder does **not** yet reach the files inside it

## Using it

```bash
# connect
curl -X POST https://your-veto/v1/grants \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"agent_id":"agt_...","resource_type":"google_folder","resource_key":"1a2B3c-_9zYx"}'

# see what is connected
curl https://your-veto/v1/grants -H "authorization: Bearer $TOKEN"

# disconnect
curl -X DELETE https://your-veto/v1/grants \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"agent_id":"agt_...","resource_type":"google_folder","resource_key":"1a2B3c-_9zYx"}'
```

Or the **connected resources** panel on the policies screen.

## What is refused

| | |
| --- | --- |
| An agent from another workspace | 404 — a caller must not learn an id exists elsewhere |
| A revoked agent | 409 — handing back what somebody took away is never an accident |
| A resource type no tool asks about | 400 |
| A key that is not a Drive id | 400, naming the reason |

## Inheritance, and the walk that makes it real

A grant on a folder reaches everything under it. Permit derives that through the
`parent` relation, and the derivation has been declared since the folder role
existed — but a derivation needs edges, and nothing wrote any. Granting a folder
therefore allowed the folder and denied every file in it: a grant that looks
correct until somebody opens a file.

`POST /v1/grants/sync` writes those edges.

```
POST /v1/grants/sync   { "folder_id": "root" }
  → { "folders": 24, "links": 198, "truncated": true, "depth": 3 }
```

### Where the parent comes from

Drive, over the workspace's own credential. Never a tool argument, never a tool
response. An agent that could state *"this file's parent is the folder you
granted me"* could read any file in Drive by saying so — privilege escalation by
argument, the same shape invariant 10 refuses for credentials and the injection
rule refuses for retrieved content.

### Why it is a separate call

A grant is a decision somebody made and needs only Permit. A walk needs Drive to
be up and a live Google connection. Folding them together would mean a Drive
outage blocks a grant that has nothing to do with Drive, and would leave a
half-finished walk behind whenever a credential expired mid-sync.

### It grants nothing

Every edge says where a file *is*, not who may read it. Running the walk against
a folder nobody was granted changes nobody's access, which is what makes it safe
as an operation of its own — and is asserted directly in
`apps/api/test/grants-sync.test.ts`.

### Bounds

| Bound | Value | Why |
| --- | --- | --- |
| Depth | 3 levels | Covers real Drives without turning one request into a crawl |
| Entries | 500 | A Drive is arbitrarily large |
| Page | 100 per folder | `listFolder` takes no page token |
| Cycles | visited set | A shortcut can point at an ancestor |

Every one of them sets `truncated`. A walk that stopped early and reported
success would leave an operator believing a grant reaches files it does not —
the exact failure this feature exists to remove. Re-run it after Drive changes;
it is idempotent, so a re-run costs nothing but time.

## Revocation

Revoking an agent removes **every** role assignment it holds, which includes
every grant. §7.3's privilege-accumulation case is that a revocation which
leaves facts behind is not a revocation, and `removeAgent` sweeps them in one
pass before deleting the principal.

There is no local grants table. The only record is Permit's, so there is nothing
to drift out of step during the incident where it matters.

## Setup

`pnpm --filter @veto/permit bootstrap` creates the `reader` role on
`google_folder` and `google_file`, the folder-to-file derivation, and the
folder-to-folder one that makes containment transitive. It is idempotent — run
it once per environment (§16), and again after any change to the resource model.

The folder role is **upserted**, not created. An environment bootstrapped before
folder nesting existed already holds that role without its `granted_to`, and a
plain create would 409, be filed as "existing", and leave the derivation
silently absent — which is the failure the step is there to fix.
