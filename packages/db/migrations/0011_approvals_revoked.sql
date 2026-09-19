-- Stage 4, phase 1. A grant must not outlive the authority it was granted under.
--
-- An approval is permission to perform one action *later*. Locking a workspace
-- or revoking an agent is a statement that nothing more should happen — but an
-- approval issued a minute earlier was, until now, still redeemable afterwards.
-- The window is small and it is exactly the window §12.1's "emergency lock
-- during an active session" scenario is about.
--
-- The new status is 'revoked' rather than reusing 'expired', for two reasons:
--
--  1. They are different facts. 'expired' means nobody acted in time; 'revoked'
--     means somebody pulled the plug. An auditor reading a lock incident needs
--     to tell those apart, and a timestamp comparison cannot.
--  2. 'expired' carries a rule that resolved_at is null, because a lapsed grant
--     was never resolved by anyone. A revoked grant may well have been approved
--     first, and clearing resolved_at to fit the constraint would erase
--     who-approved-when — the thing migration 0008 refused to do.
--
-- So the constraint is restated per status instead of as a set membership. It
-- now says what each status means about resolved_at, including the one status
-- for which the answer is "either".

alter table approvals drop constraint approvals_status_check;

alter table approvals add constraint approvals_status_check
  check (status in ('pending', 'approved', 'denied', 'expired', 'consumed', 'revoked'));

alter table approvals drop constraint resolved_has_timestamp;

alter table approvals add constraint resolved_has_timestamp
  check (
    case status
      when 'pending'  then resolved_at is null
      when 'expired'  then resolved_at is null
      when 'approved' then resolved_at is not null
      when 'denied'   then resolved_at is not null
      when 'consumed' then resolved_at is not null
      -- Killed by a lock or a revoke. It may have been approved first, in which
      -- case the resolution stands and stays readable; it may have been pending,
      -- in which case there is nothing to record.
      when 'revoked'  then true
    end
  );

comment on constraint resolved_has_timestamp on approvals is
  'Resolved, refused and spent grants carry the time the human decided. Lapsed ones do not. A revoked grant keeps whatever it had.';

-- Revoking is recorded, not erased: consumed_at stays null, and the row keeps
-- its digest and its approver so the incident is reconstructable.
create index approvals_workspace_live_idx
  on approvals (workspace_id, expires_at)
  where status in ('pending', 'approved');

comment on index approvals_workspace_live_idx is
  'Finds the grants a lock or a revoke has to kill. Partial, because the dead ones are never the answer.';
