-- Stage 2, phase 6. A consumed approval must remember that it was resolved.
--
-- 0003 wrote:
--
--   check ((status in ('approved', 'denied')) = (resolved_at is not null))
--
-- which reads correctly until the state machine actually runs. The lifecycle is
-- pending -> approved -> consumed, and `resolved_at` records when the human said
-- yes. Moving an approved row to 'consumed' left resolved_at set while the left
-- side of the equality became false, so every redemption violated the check.
--
-- The fix is not to clear resolved_at — that would erase who-approved-when at
-- the exact moment the grant is spent, which is the moment an auditor most
-- wants it (§7.3). A consumed approval *was* resolved, so it belongs on the
-- list.
--
-- 'expired' stays off the list: a grant that lapsed untouched was never
-- resolved by anyone, and recording a resolution time for it would invent one.

alter table approvals drop constraint resolved_has_timestamp;

alter table approvals add constraint resolved_has_timestamp
  check ((status in ('approved', 'denied', 'consumed')) = (resolved_at is not null));

comment on constraint resolved_has_timestamp on approvals is
  'Resolved, refused and spent grants all carry the time the human decided. Expired ones do not.';
