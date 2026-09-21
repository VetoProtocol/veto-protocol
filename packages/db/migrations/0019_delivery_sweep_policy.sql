-- Let the sweep actually see the queue.
--
-- 0018 added `due_delivery_workspaces()` as `security definer`, on the
-- assumption that definer rights would let it read across tenants. They do not:
-- row-level security is `FORCE`d on these tables, and FORCE applies to the table
-- owner too. The function ran as the owner, RLS applied exactly as it does to
-- everyone else, and it returned nothing — silently, which is the worst way for
-- a sweep to fail.
--
-- The mechanism that works is the one migration 0007 already uses for
-- `resolve_identity_subject()`: a policy that opens only while a
-- transaction-local flag is set, and a function that sets it. Nothing outside
-- that function can set it and have it mean anything, because `set_config(...,
-- true)` is transaction-local and the function is the only thing that sets it.
--
-- Two policies, because the sweep joins two tables, and both are narrow:
-- `for select` only, so nothing can be written through them.

create policy delivery_sweep on webhook_deliveries
  for select
  using (current_setting('veto.delivery_sweep', true) = 'on');

comment on policy delivery_sweep on webhook_deliveries is
  'Scheduler only. Readable via due_delivery_workspaces(), which returns workspace ids and nothing else.';

create policy delivery_sweep on webhook_endpoints
  for select
  using (current_setting('veto.delivery_sweep', true) = 'on');

comment on policy delivery_sweep on webhook_endpoints is
  'Scheduler only. Joined to find due deliveries; the function returns no endpoint data.';

-- The function, now setting the flag. Still one column, still no arguments,
-- still SELECT-only. What changed is that it works.
create or replace function due_delivery_workspaces()
  returns table (workspace_id text)
  language plpgsql
  security definer
  volatile
  set search_path = public, pg_catalog
as $$
begin
  -- Transaction-local, so it is gone before the connection returns to the pool.
  perform set_config('veto.delivery_sweep', 'on', true);

  return query
    select distinct d.workspace_id
      from webhook_deliveries d
      join webhook_endpoints e
        on e.workspace_id = d.workspace_id and e.id = d.endpoint_id
     where d.status = 'pending'
       and d.next_attempt_at <= now()
       and e.status = 'active'
     limit 1000;
end;
$$;

comment on function due_delivery_workspaces() is
  'Workspaces with webhook deliveries due. One column, no arguments — the second deliberate cross-tenant read after resolve_identity_subject(). See migrations 0018 and 0019, and threat-model §4.3.';

revoke all on function due_delivery_workspaces() from public;
grant execute on function due_delivery_workspaces() to veto;
