-- Stage 1, phase 3. Policy facts, decisions, approvals.

create table policies (
  id              text        primary key check (id ~ '^pol_[A-Za-z0-9_-]{1,64}$'),
  workspace_id    text        not null references workspaces (id) on delete restrict,
  subject         text        not null,
  action          text        not null,
  resource_filter jsonb       not null default '{}'::jsonb,
  conditions      jsonb       not null default '{}'::jsonb,
  effect          text        not null check (effect in ('allow', 'deny', 'challenge')),
  version         text        not null check (version ~ '^polv_[A-Za-z0-9_-]{1,64}$'),
  created_at      timestamptz not null default now(),

  unique (workspace_id, id)
);

create table decisions (
  id            text        primary key check (id ~ '^dec_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  request_id    text        not null check (request_id ~ '^req_[A-Za-z0-9_-]{1,64}$'),
  human_id      text        not null,
  agent_id      text        not null,
  tool          text        not null,
  action        text        not null,
  resource_ref  text,
  policy_version text,

  -- Deliberately two columns, never one. Permit answers one question; the final
  -- decision is Veto's (CLAUDE.md invariant 3). Collapsing these would hide the
  -- case where Permit allowed and Veto denied — exactly what must stay auditable.
  permit_result text        not null check (permit_result in ('allow', 'deny', 'unavailable', 'not_evaluated')),
  veto_result   text        not null check (veto_result in ('allow', 'deny', 'challenge')),

  reason_code   text        not null,
  latency_ms    integer     check (latency_ms >= 0),
  created_at    timestamptz not null default now(),

  unique (workspace_id, id),
  foreign key (workspace_id, human_id) references users (workspace_id, id) on delete restrict,
  foreign key (workspace_id, agent_id) references agents (workspace_id, id) on delete restrict,

  -- Permit being unreachable can never produce an allow (invariant 1, §7.3 policy outage).
  constraint unavailable_policy_never_allows
    check (permit_result <> 'unavailable' or veto_result <> 'allow')
);

create table approvals (
  id            text        primary key check (id ~ '^apr_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  decision_id   text        not null,
  -- The user who must resolve this. Verified against the original delegating
  -- user at resolve time (invariant 7, §12.1 approval-link scenario).
  approver_id   text        not null,
  -- Binds the grant to the exact action (spec §7.1, invariant 6). Produced by
  -- @veto/core actionDigest(); format `sha256:<64 hex>`.
  action_digest text        not null check (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  -- WebAuthn challenge. Held for verification only; never copied into audit
  -- events or logs (invariant 5).
  challenge     bytea       not null,
  status        text        not null default 'pending'
                            check (status in ('pending', 'approved', 'denied', 'expired', 'consumed')),
  expires_at    timestamptz not null,
  resolved_at   timestamptz,
  consumed_at   timestamptz,
  created_at    timestamptz not null default now(),

  unique (workspace_id, id),
  foreign key (workspace_id, decision_id) references decisions (workspace_id, id) on delete restrict,
  foreign key (workspace_id, approver_id) references users (workspace_id, id) on delete restrict,

  constraint resolved_has_timestamp
    check ((status in ('approved', 'denied')) = (resolved_at is not null)),
  -- Single-use: a grant reaches 'consumed' exactly once, and only from 'approved'.
  constraint consumed_has_timestamp
    check ((status = 'consumed') = (consumed_at is not null)),
  constraint expiry_after_creation check (expires_at > created_at)
);

-- One live grant per action digest per approver: a second pending approval for
-- the same action cannot be created while one is outstanding.
create unique index approvals_one_live_grant_idx
  on approvals (workspace_id, approver_id, action_digest)
  where status = 'pending';

create index decisions_workspace_created_idx on decisions (workspace_id, created_at desc);
create index decisions_workspace_agent_idx   on decisions (workspace_id, agent_id, created_at desc);
create index approvals_workspace_status_idx  on approvals (workspace_id, status, expires_at);
