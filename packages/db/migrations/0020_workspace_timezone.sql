-- The clock a workspace's rules are read against (spec FR-06, "limit access by
-- ... time ...").
--
-- A rule saying "only during working hours" has to mean working hours *for the
-- people in this workspace*, not for whichever data centre the gateway happens
-- to run in. Without this, "09:00 to 17:00" would quietly mean something
-- different for every customer, and would change meaning if the service moved.
--
-- An IANA zone name, not an offset. An offset cannot express daylight saving,
-- so a rule written in March would drift by an hour in October — silently, and
-- in the direction of allowing an hour nobody intended.
--
-- Checked loosely here and properly in the application: Postgres has no list of
-- valid zone names available to a CHECK constraint, and `Intl.DateTimeFormat`
-- does. The constraint is a shape guard, not the validation.
alter table workspaces
  add column timezone text not null default 'UTC'
    check (timezone ~ '^[A-Za-z][A-Za-z0-9+_-]*(/[A-Za-z0-9+_-]+){0,2}$'
           and length(timezone) between 1 and 64);

comment on column workspaces.timezone is
  'IANA zone name the workspace''s time-based policy conditions are evaluated in. UTC until somebody sets it.';
