-- The authorization server's own storage (spec §8, docs/oauth-plan.md).
--
-- Two tables with deliberately different tenancy, which is the only surprising
-- thing here and the thing most worth reading before changing either.
--
-- ## Why a client belongs to no workspace
--
-- A client registers (RFC 7591) *before* any human is involved: a desktop app on
-- somebody's laptop, arriving cold, with no credential to present and no way to
-- obtain one. There is no workspace to scope it to at that moment, and inventing
-- one would mean a client is bound to whoever happened to install it first.
--
-- So `oauth_clients` has no `workspace_id` and no row-level security, which is a
-- deliberate exception to invariant 4 and the second one in this schema after
-- `resolve_identity_subject()`. It is safe for exactly one reason: **a
-- registered client holds no authority whatsoever.** It is a name and a set of
-- redirect URIs. It cannot read, cannot decide, and cannot be granted anything.
-- All it can do is ask a human to approve it, and the human sees what they are
-- approving.
--
-- Authority lives in the refresh token below, which is tenant-scoped like
-- everything else.
--
-- If a future change gives a client any attribute that grants, narrows, or
-- identifies a tenant, that change needs this exception re-argued and the
-- threat model re-opened — it does not get to inherit this reasoning.

create table oauth_clients (
  id              text        primary key check (id ~ '^oac_[A-Za-z0-9_-]{1,64}$'),

  -- Self-declared, shown on the consent screen, and never trusted for anything
  -- else. A client that calls itself "Veto Admin" is a phishing attempt, which
  -- is a problem for the consent screen's wording and not for this column.
  client_name     text        not null check (length(client_name) between 1 and 200),

  -- Exact-match only at /authorize. Stored as given, compared whole: prefix
  -- matching is how an open redirect gets into an otherwise correct server
  -- (RFC 9700).
  redirect_uris   text[]      not null check (cardinality(redirect_uris) between 1 and 10),

  created_at      timestamptz not null default now()
);

comment on table oauth_clients is
  'Dynamically registered OAuth clients (RFC 7591). Intentionally not tenant-scoped: a client registers before any human is involved and holds no authority — see the migration for why that is safe.';

-- ## Refresh tokens
--
-- The access token is the capability token the gateway already accepts, capped
-- at fifteen minutes by MAX_TTL_MS. Refresh is therefore not optional: without
-- it a client dies mid-session, which is the failure the desktop bridge works
-- around today by minting one per request.
--
-- A refresh token is a long-lived credential for a workspace, so it is stored
-- as a hash and never in plaintext — the same rule that stops the vault ever
-- returning a Google refresh token. A database read must not yield a working
-- credential.

create table oauth_refresh_tokens (
  id            text        primary key check (id ~ '^oar_[A-Za-z0-9_-]{1,64}$'),

  workspace_id  text        not null references workspaces (id) on delete restrict,
  user_id       text        not null,
  agent_id      text        not null,
  client_id     text        not null references oauth_clients (id) on delete restrict,

  -- SHA-256 of the token. Unique, so a presented token is found by hash or not
  -- at all, and a stolen database yields nothing usable.
  token_hash    text        not null unique check (token_hash ~ '^[a-f0-9]{64}$'),

  -- Every token descended from one authorization shares a chain id. Rotation
  -- replaces a token within its chain; reuse of a rotated one revokes the whole
  -- chain, because a token presented twice is either a race or a theft and the
  -- safe answer to both is the same.
  chain_id      text        not null check (chain_id ~ '^oac_[A-Za-z0-9_-]{1,64}$'),

  -- active  — the one live token in its chain
  -- rotated — spent normally, kept so that reuse is detectable
  -- revoked — the chain was killed, by reuse detection or deliberately
  status        text        not null default 'active'
                            check (status in ('active', 'rotated', 'revoked')),

  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  -- When it was spent. Null while active; set on rotation, which is what makes
  -- a second presentation recognisable rather than merely unexpected.
  used_at       timestamptz,

  constraint used_only_when_spent
    check ((status = 'active' and used_at is null) or (status <> 'active')),

  unique (workspace_id, id)
);

-- One live token per chain, enforced rather than assumed. Two active tokens in
-- a chain would mean rotation produced a fork, and either branch would work —
-- which is what single-use is supposed to prevent.
create unique index oauth_refresh_one_active_per_chain
  on oauth_refresh_tokens (chain_id)
  where status = 'active';

create index oauth_refresh_by_agent
  on oauth_refresh_tokens (workspace_id, agent_id)
  where status = 'active';

alter table oauth_refresh_tokens enable row level security;
alter table oauth_refresh_tokens force row level security;
create policy tenant_isolation on oauth_refresh_tokens
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

comment on column oauth_refresh_tokens.token_hash is
  'SHA-256 of the refresh token. The token itself is returned once, at issue, and never stored.';
