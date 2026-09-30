-- Which containment edges Permit has already been told about.
--
-- The folder walk writes one parent fact per entry to Permit's Cloud API. On a
-- second walk of the same Drive those writes are all duplicates: Permit answers
-- 409 and the fact was already true. Observed on a real deployment — 648 of 676
-- calls were 409s, and the remaining 28 were 429s, because the whole rate
-- budget had gone on re-stating things Permit already knew. The walk then
-- failed, having achieved nothing it had not achieved the first time.
--
-- So the edges are remembered here. A walk loads them once, skips what is
-- already recorded, and spends its calls on what is new. A re-run of an
-- unchanged folder costs one local query and no upstream calls at all, which is
-- what makes syncing a large Drive incrementally possible rather than a thing
-- that must succeed in one go or not at all.
--
-- This is a cache of what was sent, not a source of truth. Permit remains the
-- authority on containment; if this table is wrong the worst case is a write
-- that is skipped and should not have been, which the operator fixes by
-- clearing the rows for that workspace and walking again. It is deliberately
-- not consulted at decision time — nothing here can make a request allowed.
create table hierarchy_edges (
  workspace_id text        not null references workspaces (id) on delete cascade,
  -- `google_file` or `google_folder`, as Permit knows them.
  child_type   text        not null,
  child_key    text        not null,
  parent_key   text        not null,
  written_at   timestamptz not null default now(),

  primary key (workspace_id, child_type, child_key, parent_key)
);

alter table hierarchy_edges enable row level security;
alter table hierarchy_edges force row level security;
create policy tenant_isolation on hierarchy_edges
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

comment on table hierarchy_edges is
  'Containment edges already sent to Permit, so a repeat walk does not spend its rate budget re-stating them. A cache of what was written, never consulted at decision time.';
