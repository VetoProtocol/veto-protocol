-- Stage 1, phase 3. Row-level security as defence in depth for invariant 4.
--
-- Application queries are already workspace-scoped. RLS exists so that a query
-- which *forgets* that scope returns nothing instead of leaking another tenant.
-- The application must still filter explicitly; this is the second lock.
--
-- Two details that decide whether this works at all:
--
--  * FORCE. A table owner bypasses its own RLS policies by default, and the
--    `veto` role owns these tables. Without FORCE, every policy here is
--    decorative. A separate non-owner application role is the better production
--    posture and is a deployment-hardening item, not a schema one.
--
--  * `current_setting(..., true)` returns NULL when the GUC is unset, and
--    `workspace_id = NULL` is NULL, not true. So a connection that never set the
--    tenant sees zero rows and can insert nothing: unset fails closed
--    (invariant 1). Callers set it per transaction via set_config(..., true),
--    never at session level — session scope would leak across pooled checkouts.

create or replace function current_workspace_id() returns text
  language sql
  stable
  set search_path = pg_catalog
as $$
  select nullif(current_setting('veto.workspace_id', true), '')
$$;

comment on function current_workspace_id() is
  'Tenant for the current transaction. NULL when unset, which denies every row.';

-- workspaces is keyed by id rather than workspace_id.
alter table workspaces enable row level security;
alter table workspaces force row level security;
create policy tenant_isolation on workspaces
  using (id = current_workspace_id())
  with check (id = current_workspace_id());

do $$
declare
  t text;
begin
  foreach t in array array[
    'users', 'agents', 'connections', 'sessions', 'presence',
    'policies', 'decisions', 'approvals', 'audit_events'
  ] loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format(
      'create policy tenant_isolation on %I
         using (workspace_id = current_workspace_id())
         with check (workspace_id = current_workspace_id())', t);
  end loop;
end;
$$;
