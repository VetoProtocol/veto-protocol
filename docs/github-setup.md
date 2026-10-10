# GitHub App setup

What the GitHub side needs, and why one of its settings is not optional.

## Why an App and not an OAuth App

An OAuth App acts *as the user*, and its `repo` scope is read **and** write
across every repository that user can reach, with no read-only form. A product
whose position is "reads first, and a write path is a new trust boundary"
cannot ask for a credential that can push.

A GitHub App acts as itself, is installed per account, and holds only the
repositories and permissions the installer picked.

## Creating it

GitHub → Settings → Developer settings → **GitHub Apps** → New GitHub App.

| Field | Value |
| --- | --- |
| Name | anything; its **slug** is what the install URL uses |
| Homepage URL | your dashboard origin |
| Setup URL | `https://<your-origin>/connections/github/callback` |
| Redirect URL | `https://<your-origin>/connections/github/callback` |
| Webhook | not needed — uncheck Active |

Repository permissions, read-only, and nothing else:

- **Metadata** — read (GitHub requires it for nearly every other read)
- **Contents** — read
- **Issues** — read
- **Pull requests** — read

## The setting that is not optional

> ☑ **Request user authorization (OAuth) during installation**

Without it GitHub sends no `code` back after an install, and **nothing can be
connected** — the callback refuses with "GitHub did not confirm who owns that
installation".

That refusal is deliberate. Here is what the setting is actually for.

The post-install redirect carries an `installation_id`. On its own it is a
number somebody typed, and installation ids are small sequential integers.
Asking GitHub what that installation *is* does not help: the lookup
authenticates with the App's own JWT, which can read **any** installation of
this App, including one on an account the caller has never touched. It answers
"does this exist", never "is this yours".

The install `state` does not close the gap either. It proves a flow began in
this workspace, as this user, recently — CSRF protection — and says nothing
about which installation that flow ended at.

So without user authorization, any signed-in user could start an install, never
visit GitHub, post a stranger's installation id, and have this server mint real
tokens for that stranger's repositories using the App private key it holds.

With the setting on, GitHub returns a `code` alongside the installation id. It
exchanges for a **user** access token, and `GET /user/installations` with that
token lists only the installations *that person* can reach. An id absent from
that list was claimed rather than owned, and is refused.

There is no other mechanism. This is the one GitHub provides.

## Credentials

Five values on the server, from the App's settings page:

```
GITHUB_APP_ID=
GITHUB_APP_SLUG=
GITHUB_PRIVATE_KEY_PATH=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

**The private key is a path, not the key.** A PEM is multi-line, and a
multi-line secret in a `.env` invites pasting it with the newlines mangled —
which fails at JWT signing, on the first real call, pointing nowhere useful.
Generate it at the bottom of the App settings page, put the file somewhere the
service user can read, and point at it:

```bash
sudo install -o veto -g veto -m 400 ~/Downloads/<app>.private-key.pem /etc/veto/github-app.pem
```

The directory needs to be traversable by that user too — a `700 root:root`
parent is the usual reason a correctly-placed key still reads `EACCES`.

**`GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` belong to the API only.** The
gateway mints installation tokens and takes no part in the install round trip,
so that secret has no business reaching it.

Leave `GITHUB_CLIENT_ID` empty and new GitHub connections are refused at the
*start* — before anybody picks repositories on GitHub's screen — rather than
completed on trust. Connections already on file keep working, because minting a
token for one needs the private key and nothing here.

Leave `GITHUB_APP_ID` empty and GitHub is disabled entirely.

## Installing it

From the dashboard: **Connections → GitHub → connect**. That round trip is the
only supported path, because the `state` it issues is what ties the callback to
the browser that began it.

Installing from GitHub's own page instead — `github.com/apps/<slug>` → Install —
lands on the callback without that state and is refused. Nothing is broken; it
just has to start from the dashboard.

On the install screen you choose **which repositories**. "All repositories"
grants the App everything in that account; picking them individually is the
whole reason this is an App, so pick them individually.

## Checking it worked

`/connections` lists the installation with the permissions GitHub reported —
not the ones we asked for. An installer who granted only issues is recorded as
having granted only issues.

A grant still has to exist before an agent can read anything: `/policies` for
the rule, and `POST /v1/grants/github/sync` so a grant on the account reaches
the repositories under it.
