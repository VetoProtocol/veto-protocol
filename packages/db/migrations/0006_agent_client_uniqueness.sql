-- Stage 1, phase 4 prerequisite. Correct agent uniqueness.
--
-- 0002 carried `unique (workspace_id, provider, client_id)`. That was wrong in
-- two ways.
--
-- First, it conflated two different identities. Spec §5.1 shows client_id as
-- "claude-desktop" — it names the client *software*, not a registration. The old
-- constraint therefore allowed a workspace exactly one Claude Desktop agent in
-- total, so a second person in the same workspace could never register.
--
-- Second, it made a revoked agent's client_id unusable forever. That looks like
-- a safety property and is not one: registration only creates an identity. A
-- fresh agent holds no policy grants, no connection and no session, and under
-- deny-by-default (invariant 2) it can do nothing until those are attached. The
-- control that actually matters is that revocation removes the Permit facts and
-- kills the sessions — enforced in the revocation path, and asserted by the
-- "re-registration inherits nothing" test. Blocking re-registration guarded the
-- wrong door while making an accidental revoke unrecoverable.
--
-- Replacement: one *live* agent per owner per client per provider.
--   * Two users in one workspace can each register the same client.
--   * One user cannot hold two live agents for the same client, so resolving
--     client -> agent at the gateway stays unambiguous.
--   * A revoked agent stops reserving the slot.
--   * 'suspended' still reserves it: suspension is temporary and the agent is
--     expected back.
--
-- Revoked rows are never removed. decisions and audit_events reference agents,
-- and removing one would break the audit trail (spec §7.3 audit tampering).

alter table agents
  drop constraint agents_workspace_id_provider_client_id_key;

create unique index agents_one_live_per_client_idx
  on agents (workspace_id, owner_user_id, provider, client_id)
  where status in ('active', 'suspended');

comment on index agents_one_live_per_client_idx is
  'One live agent per owner per client. Revoked agents free the slot (FR-08).';
