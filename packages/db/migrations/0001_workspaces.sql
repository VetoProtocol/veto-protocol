-- Stage 1, phase 3. Tenant root.
--
-- Every tenant-scoped table below carries workspace_id even where spec §6 does not
-- list it (connections, presence, sessions, decisions, approvals). §6 gives required
-- fields, not an exhaustive set, and CLAUDE.md invariant 4 requires *every* query,
-- cache key, and policy fact to be workspace-scoped. The narrower reading loses.

create extension if not exists pgcrypto;

create table workspaces (
  id             text        primary key check (id ~ '^ws_[A-Za-z0-9_-]{1,64}$'),
  name           text        not null check (length(name) between 1 and 200),
  type           text        not null check (type in ('personal', 'organization')),
  -- Checked at step 3 of every request, before policy evaluation (spec §3.3).
  emergency_lock boolean     not null default false,
  locked_at      timestamptz,
  created_at     timestamptz not null default now(),

  constraint lock_timestamp_consistent
    check ((emergency_lock and locked_at is not null) or (not emergency_lock and locked_at is null))
);

comment on column workspaces.emergency_lock is
  'Spec §7.2 locked state. True => deny every protected action in this workspace.';
