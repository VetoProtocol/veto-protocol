-- Consent Grants: make "when did this grant last get used" cheap.
--
-- The screen asks, per grant, for the most recent allowed decision naming that
-- agent and that resource. Without an index that is a sequential scan of every
-- decision the workspace has ever recorded, once per grant — fine on a
-- fortnight-old deployment and not fine later.
--
-- Indexes only. No column is added, no row is touched, and nothing here changes
-- what any existing query returns. Safe to apply to a running system.

-- Last allowed use, per agent and resource.
--
-- `resource_ref` is in the key because the join is on it, and `created_at desc`
-- so the planner can stop at the first row rather than sorting a group.
-- Partial on `allow`: a denial is not a use, and on a deny-by-default system
-- denials are a large share of the table.
create index if not exists decisions_consent_last_use_idx
  on decisions (workspace_id, agent_id, resource_ref, created_at desc)
  where veto_result = 'allow';

-- Provenance: who created the grant, and when.
--
-- `audit_events` already records `grant.created` with the actor and a
-- `resource_ref` of `<type>:<key>#agent=<id>`, so the lineage needs no new
-- table — only a way to find those rows without scanning the whole timeline.
create index if not exists audit_events_grant_lineage_idx
  on audit_events (workspace_id, event_type, occurred_at desc)
  where event_type in ('grant.created', 'grant.revoked');

comment on index decisions_consent_last_use_idx is
  'Consent Grants joins a grant to its last use on resource_ref. packages/core/src/grant-ref.ts owns the format both sides must agree on.';
