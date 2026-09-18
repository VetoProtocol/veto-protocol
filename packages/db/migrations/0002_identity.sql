-- Stage 1, phase 3. Identity model: humans, agents, connections, sessions, presence.

create table users (
  id               text        primary key check (id ~ '^usr_[A-Za-z0-9_-]{1,64}$'),
  workspace_id     text        not null references workspaces (id) on delete restrict,
  identity_subject text        not null check (length(identity_subject) between 1 and 255),
  status           text        not null default 'active' check (status in ('active', 'suspended', 'revoked')),
  passkey_enrolled boolean     not null default false,
  created_at       timestamptz not null default now(),
  revoked_at       timestamptz,

  -- Target for the composite foreign keys below; this is what makes a
  -- cross-tenant parent reference unrepresentable rather than merely untested.
  unique (workspace_id, id),
  unique (workspace_id, identity_subject)
);

create table agents (
  id            text        primary key check (id ~ '^agt_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  provider      text        not null check (length(provider) between 1 and 100),
  client_id     text        not null check (length(client_id) between 1 and 200),
  owner_user_id text        not null,
  status        text        not null default 'active' check (status in ('active', 'suspended', 'revoked')),
  fingerprint   text,
  created_at    timestamptz not null default now(),
  revoked_at    timestamptz,

  unique (workspace_id, id),

  -- An agent in workspace A cannot be owned by a user in workspace B.
  foreign key (workspace_id, owner_user_id) references users (workspace_id, id) on delete restrict,

  -- Re-registering a revoked agent's client_id is refused rather than silently
  -- creating a second live identity. A burned client_id stays burned: the
  -- restrictive reading of FR-08.
  unique (workspace_id, provider, client_id),

  constraint revoked_has_timestamp
    check ((status = 'revoked') = (revoked_at is not null))
);

create table connections (
  id                      text        primary key check (id ~ '^con_[A-Za-z0-9_-]{1,64}$'),
  workspace_id            text        not null references workspaces (id) on delete restrict,
  user_id                 text        not null,
  provider                text        not null,
  scopes                  text[]      not null default '{}',
  -- Populated in stage 2 only, and only after the threat model is signed off (§16).
  encrypted_refresh_token bytea,
  encryption_key_id       text,
  encryption_context      jsonb,
  status                  text        not null default 'active' check (status in ('active', 'expired', 'revoked')),
  expires_at              timestamptz,
  created_at              timestamptz not null default now(),

  unique (workspace_id, id),
  foreign key (workspace_id, user_id) references users (workspace_id, id) on delete restrict,

  -- Ciphertext without its key reference is unrecoverable and its encryption
  -- context is what binds it to this tenant (spec §7.1). Never allow a partial row.
  constraint ciphertext_requires_key_and_context
    check (encrypted_refresh_token is null
           or (encryption_key_id is not null and encryption_context is not null))
);

create table sessions (
  id            text        primary key check (id ~ '^ses_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  human_id      text        not null,
  agent_id      text        not null,
  connection_id text,
  trust_level   text        not null default 'standard' check (trust_level in ('standard', 'elevated')),
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  revoked_at    timestamptz,

  unique (workspace_id, id),
  foreign key (workspace_id, human_id) references users (workspace_id, id) on delete restrict,
  foreign key (workspace_id, agent_id) references agents (workspace_id, id) on delete restrict,
  foreign key (workspace_id, connection_id) references connections (workspace_id, id) on delete restrict,

  constraint expiry_after_creation check (expires_at > created_at)
);

create table presence (
  workspace_id text        not null references workspaces (id) on delete restrict,
  user_id      text        not null,
  -- Spec §7.2. Presence is a policy signal, never proof of user intent.
  state        text        not null check (state in ('active', 'away', 'locked', 'automation')),
  source       text        not null,
  assurance    text        not null default 'low' check (assurance in ('low', 'medium', 'high')),
  changed_at   timestamptz not null default now(),
  expires_at   timestamptz,

  primary key (workspace_id, user_id),
  foreign key (workspace_id, user_id) references users (workspace_id, id) on delete restrict
);

comment on column presence.assurance is
  'How strongly presence is evidenced. Only fresh passkey verification is high (spec §7.2).';

-- Tenant-leading composite indexes: every lookup filters by workspace first.
create index users_workspace_status_idx       on users (workspace_id, status);
create index agents_workspace_owner_idx       on agents (workspace_id, owner_user_id);
create index agents_workspace_status_idx      on agents (workspace_id, status);
create index connections_workspace_user_idx   on connections (workspace_id, user_id);
create index sessions_workspace_agent_idx     on sessions (workspace_id, agent_id);
create index sessions_expiry_idx              on sessions (workspace_id, expires_at);
