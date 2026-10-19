-- Who an endpoint's events are for.
--
-- Endpoints have been workspace-wide since migration 0012: every active
-- endpoint subscribed to an event receives every one of them. That is right for
-- `workspace.locked` and `decision.denied`, which are facts about the tenant.
--
-- It is wrong for `approval.requested`. Only the delegating user can resolve
-- their own challenge (invariant 7), so an approval alert has exactly one
-- correct recipient — and a workspace-wide endpoint either reaches everybody or
-- reaches a channel nobody is watching. The event has carried `human_id` since
-- it was written, with the comment "an alert about an approval nobody can route
-- is noise". This is the column that routes it.
--
-- ## Why null is the default, and what it means
--
-- Null means "everyone in the workspace", which is exactly today's behaviour.
-- Every existing row gets it, so applying this changes no delivery anywhere. A
-- routed endpoint is opt-in, created deliberately by somebody who wants their
-- own approvals somewhere they will see them.
--
-- ## The composite foreign key is the tenant boundary
--
-- `(workspace_id, route_to_user_id)` rather than a plain reference to
-- `users (id)`. An endpoint in workspace A cannot be routed to a user in
-- workspace B — not "is not", but cannot be represented. The same move the
-- rest of the schema makes for agents and connections (invariant 4).
--
-- ## What this does not do
--
-- It does not make a routed endpoint a credential, a second approval path, or
-- an authority. The notification carries a link; resolving still demands a
-- passkey assertion from the delegating user over that approval's own stored
-- challenge, and `routes/approvals.ts` refuses anybody else with
-- `APPROVER_NOT_DELEGATOR`. A routed endpoint decides where a message goes. It
-- decides nothing about who may act on it.

alter table webhook_endpoints
  add column route_to_user_id text,
  add constraint webhook_endpoints_route_fk
    foreign key (workspace_id, route_to_user_id)
    references users (workspace_id, id) on delete restrict;

-- The selection `enqueue` makes on every event: active endpoints for a type,
-- narrowed by who the event is about. Partial, because a disabled endpoint is
-- never a candidate and indexing one wastes the write.
create index webhook_endpoints_routing_idx
  on webhook_endpoints (workspace_id, route_to_user_id)
  where status = 'active';

comment on column webhook_endpoints.route_to_user_id is
  'Who this endpoint is for. Null means the whole workspace, which is how every endpoint behaved before this column existed. Set, it receives only events whose data.human_id matches — the routing an approval alert needs, since only the delegating user can resolve one.';
