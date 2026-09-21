-- When a client registration was last worth anything.
--
-- Pruning abandoned registrations needs to know whether anything ever descended
-- from a client. The obvious query — "delete clients with no refresh tokens" —
-- cannot work: `oauth_refresh_tokens` has FORCEd row-level security, and
-- `oauth_clients` has no tenant, so the sweep runs untenanted and the subquery
-- sees *zero* rows. Every old client then looks unused, including the ones in
-- daily use.
--
-- The foreign key caught it — `on delete restrict` refused, and the resulting
-- error surfaced as a misleading 401. That is the constraint doing its job, and
-- not a design to lean on.
--
-- So the fact lives on the client instead. "Has anything ever descended from
-- this registration" is a property of the registration, and recording it here
-- removes the cross-tenant read rather than working around it.
--
-- Null means never used, which is exactly what makes a row safe to delete.
alter table oauth_clients add column last_used_at timestamptz;

comment on column oauth_clients.last_used_at is
  'When a token was last issued for this client. Null means never — the only clients safe to prune.';
