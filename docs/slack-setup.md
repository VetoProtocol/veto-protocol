# Slack app setup

What the Slack side needs, and why one of its settings is not optional.

## Why a bot, not a user token

A Slack app can act as the installing *person* or as a *bot*.

A user token reaches everything that person can reach — usually every channel
they are in. There is no narrowing available and no way to grant one
conversation without granting all of them.

A bot reads only the conversations it has been **invited to**. That is Slack's
own mechanism, and it happens to be exactly the boundary this product sells:
you grant a channel by adding the bot to it, in the place you already manage
channel membership, one channel at a time.

So the grant has two halves, and both are required:

| Half | Where | What it does |
| --- | --- | --- |
| Invite the bot to a channel | Slack | makes the channel reachable at all |
| Grant the agent that channel | `/policies` | permits an agent to read it |

Neither alone is access. A Slack install on its own reaches no conversation.

## Creating the app

api.slack.com/apps → **Create New App** → From scratch.

**OAuth & Permissions → Bot Token Scopes:**

| Scope | For |
| --- | --- |
| `channels:read` | listing public channels |
| `channels:history` | reading messages in public channels |
| `groups:read` | listing private channels *(optional)* |
| `groups:history` | reading messages in private channels *(optional)* |

Public and private are **separate consents** in Veto, with separate buttons on
`/connections`. "Read our public channels" and "read our private channels" are
different conversations to have, and bundling them would make the second
invisible.

**Redirect URL:** `https://<your-origin>/connections/slack/callback`

Do not add user token scopes. This app never acts as the installing person.

## The setting that is not optional

> ☑ **Token Rotation** — OAuth & Permissions → Advanced token security

Without it, **the install is refused** with *"slack install returned no refresh
token — enable token rotation on the app"*.

That refusal is deliberate. A classic Slack bot token never expires. Stored in
the vault it would be a permanent bearer credential sitting in the column that
promises a rotating one, and the broker's whole shape says "trade a long-lived
secret for a short-lived one". Returning the same string forever would be lying
about which kind it is.

With rotation on, the install returns a refresh token plus a 12-hour access
token — exactly what the credential broker already expresses.

One consequence worth knowing: **the refresh token itself changes on every
use.** The broker persists the replacement inside the same operation, before
the access token is handed out. Nothing had ever needed that before Slack —
Google's refresh token is stable and GitHub's durable value is an installation
id — so the credential column had no writer until this integration added one.

## Credentials

Three values on the server, from **Basic Information → App Credentials**:

```
SLACK_CLIENT_ID=
SLACK_CLIENT_SECRET=
SLACK_REDIRECT_URI=https://<your-origin>/connections/slack/callback
```

The redirect must match the app's configured value exactly.

Leave `SLACK_CLIENT_ID` empty and Slack is disabled: every Slack route refuses
and every Slack tool answers `TOOL_NOT_ALLOWED` rather than half-working.

## Connecting it

From the dashboard: **Connections → Connect Slack**. That round trip is the
only supported path, because the `state` it issues is what ties the callback to
the browser that began it — and the control plane mints that state, never the
browser.

There is no equivalent of the GitHub `F-01` ownership check here, and the
reason is worth recording: Slack returns an authorization **code**, which
cannot be forged, and exchanging it with the client secret is itself proof that
whoever completed the flow holds the workspace. GitHub was the odd provider —
an installation id is a small integer anybody can type.

## Then invite the bot

Installing the app grants Veto nothing to read. In each channel you want an
agent to reach:

```
/invite @<your app name>
```

`slack_channel.list_channels` shows every channel the installation can see and
whether the bot is in each one — a channel the bot is not in is listed, so you
can tell the difference between "not granted" and "not there".

## What the tools can do

| Tool | Reads |
| --- | --- |
| `slack_channel.list_channels` | names and ids, never a message |
| `slack_channel.read_history` | messages in one channel, bounded window |

A history read is bounded by count **and** by window — 31 days, checked in step
8 rather than only in the schema, because a schema can check two timestamps are
timestamps and only the executor can check they are not a year apart.

Author ids are returned, never names. Resolving a Slack id to a person is
personal data this feature does not need.
