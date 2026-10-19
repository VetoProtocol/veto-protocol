# Shadow Agents

What reaches your connected accounts **without passing through Veto**.

## The gap this names

Veto decides everything that comes through the gateway, and nothing else. An AI
tool wired straight into the company Drive is invisible on every other screen
in this product — and those screens stay green while it happens, because every
request Veto *can* see is being decided correctly.

A green dashboard is not evidence of coverage. This is the screen that looks
the other way.

## Standing access, not activity

v1 lists who **can** act, not who **did**.

The activity version — diffing a provider's audit log against Veto's
`decisions` rows — is a harder problem and a later one. There is no shared
identifier between the two records, so matching is by actor and timestamp, and
Veto's own upstream calls appear in that log as the same actor doing the same
thing. An inventory has no such ambiguity: an app is on the list or it is not.

Both are worth having. Inventory first because it is exact and shippable;
activity second, once there is a customer with the access to validate it
against.

## The property everything else is shaped around

> **"I could not look" is not "I looked and found nothing."**

Reading an inventory needs administrative access a connection may not have.
Google's is a Workspace-admin report and does not exist for a personal account.
GitHub's is organisation-scoped, so a personal account has none.

A reader that answered `[]` when it lacked permission would render as **"no
shadow agents found"** — the most dangerous sentence this product could print,
because it is the reassurance somebody acts on and then stops checking.

So:

- `InventoryResult` is a union: `read` with apps, or `unavailable` with a reason
- `shadow_count` is **null**, never 0, when any provider could not be read — a
  number is a claim about the whole estate and cannot be made from a partial look
- a thrown source becomes `unavailable`, never an empty list
- the screen renders `unavailable` in the deny tone, headed *"Nobody looked —
  this is not a clean bill of health"*

It is the same shape as deny-by-default being indistinguishable from a broken
workspace, and it has the same fix: make the two states different things rather
than the same empty one.

## What is built, and what is not

| Piece | State |
| --- | --- |
| `AppInventorySource` port, result union, filtering | built |
| `GET /v1/shadow`, Pro-gated before any provider call | built |
| `/shadow` screen, including every unavailable reason | built |
| Test fake (`createFakeInventorySource`) | built |
| **Google adapter** | **not built** — see below |
| **GitHub adapter** | **not built** — see below |

The adapters are deliberately absent rather than speculative. Neither provider
can be called from any account this project currently has, so writing them now
would mean shipping code nobody has ever run against the API it claims to call
— which is how a control comes to exist only in prose, a mistake this codebase
has already paid for three times.

With no source wired up, every provider reports `not_configured` and the screen
says so plainly. That is the honest state, and it is visibly different from
"all clear".

## What a customer has to provide

| Provider | Needs | Today |
| --- | --- | --- |
| Google | A **Workspace admin** account, plus an admin scope that can read the account's authorised applications | Connected scopes are `gmail.readonly` and `calendar.readonly` — no admin surface, and the account is personal |
| GitHub | The App installed on an **organisation** with audit access | Installed on a personal account, which has no organisation audit surface |

Neither is build work. Both are worth confirming before the adapters are
scheduled, because without them this screen has nothing to read.

## What counts as a shadow agent

An app counts when it is **not Veto** and **reaches protected data**.

Not Veto is decided by comparing client ids, never by display name — an app may
call itself anything, and one calling itself "Veto Protocol" is exactly what
somebody hiding would do. There is a test for that.

Reaching protected data is a substring match over scope strings. Deliberately
loose: a provider's scope names change shape between products and versions, and
a false positive costs one extra row on a screen while a false negative is an
agent nobody was told about. An app holding only a sign-in scope is listed but
not counted — it cannot read a file or a message, and burying the three that
matter under thirty that do not makes a list nobody reads.
