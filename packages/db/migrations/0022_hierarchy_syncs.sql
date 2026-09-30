-- A folder walk that outlives the request that asked for it.
--
-- The walk reads Drive and writes one parent fact per entry to Permit's Cloud
-- API. Measured from a deployed host, a write takes about 1.7 s; even run eight
-- at a time a large folder is a minute's work, and it used to be fourteen. No
-- browser, proxy or fetch waits that long, so the request died while the server
-- was still working and the operator was told only that something went wrong
-- talking to the control plane — with no way to learn whether any of it landed.
--
-- So the walk gets a record. The request starts it and returns immediately; the
-- record says what happened, including when it is still happening.
--
-- Counts only, never names. What a walk finds is a map of somebody's Drive and
-- file names are protected content — invariant 5 keeps them out of here as
-- firmly as it keeps them out of the audit trail.
create table hierarchy_syncs (
  id           text        primary key check (id ~ '^hsy_[A-Za-z0-9_-]{1,64}$'),
  workspace_id text        not null references workspaces (id) on delete cascade,
  -- Who asked. A walk spends the workspace's credential, so the person who
  -- started it is part of what happened.
  started_by   text        not null,
  folder_id    text        not null,
  status       text        not null default 'running'
                 check (status in ('running', 'done', 'failed')),
  folders      integer     not null default 0,
  links        integer     not null default 0,
  truncated    boolean     not null default false,
  -- A reason a person can act on, not a stack. Null while running and on success.
  error        text,
  started_at   timestamptz not null default now(),
  finished_at  timestamptz,

  foreign key (workspace_id, started_by) references users (workspace_id, id) on delete cascade,
  -- Finished exactly when it is no longer running.
  constraint finished_when_settled check ((status = 'running') = (finished_at is null))
);

-- One walk per workspace at a time. A second request while one is running
-- returns the one already going rather than opening a rival that would write
-- the same facts twice, more slowly, against the same rate limit.
create unique index hierarchy_syncs_one_running_idx
  on hierarchy_syncs (workspace_id)
  where status = 'running';

create index hierarchy_syncs_recent_idx
  on hierarchy_syncs (workspace_id, started_at desc);

alter table hierarchy_syncs enable row level security;
alter table hierarchy_syncs force row level security;
create policy tenant_isolation on hierarchy_syncs
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

comment on table hierarchy_syncs is
  'One folder walk. Started by a request, outlives it, and reports counts — never file names.';
