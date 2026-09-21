-- Which workspaces have webhook deliveries due (spec §5.4).
--
-- ## Why this is a function and not a query
--
-- `drainDeliveries` works on one workspace. A scheduler has to find the
-- workspaces with work waiting, and `webhook_deliveries` has FORCEd row-level
-- security — so nothing can see across tenants to ask. Without this, delivery
-- stays what it is today: a button somebody presses, per workspace, by hand.
--
-- ## This is the second deliberate exception to invariant 4
--
-- The first is `resolve_identity_subject()` (migration 0007), which reads across
-- tenants because sign-in must find the workspace before it can scope to one.
-- `docs/threat-model.md` says a second cross-tenant read brings the document
-- back for review, and it has — §4.3 records this one.
--
-- It is built to the same shape, deliberately:
--
--   * **One column.** A workspace id and nothing else. No payload, no endpoint,
--     no event type — nothing that says what is being delivered or to whom.
--   * **SELECT-only**, `stable`, and it writes nothing.
--   * **No argument.** There is no input to smuggle a filter through, and no way
--     to ask it about a workspace rather than let it answer about all of them.
--   * **Existence, not contents.** The answer is "there is work here", which is
--     the least a scheduler can be told and still function.
--
-- What it does *not* grant: the caller still has to enter each workspace
-- normally to drain it, and row-level security applies to every row it then
-- touches. This says where to look, never what is there.
--
-- Do not extend it. A column added here is a column that crosses tenants.

create or replace function due_delivery_workspaces()
  returns table (workspace_id text)
  language sql
  security definer
  stable
  set search_path = public, pg_catalog
as $$
  select distinct d.workspace_id
    from webhook_deliveries d
    join webhook_endpoints e
      on e.workspace_id = d.workspace_id and e.id = d.endpoint_id
   where d.status = 'pending'
     and d.next_attempt_at <= now()
     and e.status = 'active'
   limit 1000;
$$;

comment on function due_delivery_workspaces() is
  'Workspaces with webhook deliveries due. One column, no arguments, SELECT-only — the second deliberate cross-tenant read after resolve_identity_subject(). See migration 0018 and threat-model §4.3.';

revoke all on function due_delivery_workspaces() from public;
grant execute on function due_delivery_workspaces() to veto;
