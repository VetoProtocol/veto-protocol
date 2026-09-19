-- Stage 4, phase 2 follow-up. Webhook targets are https, at the column too.
--
-- 0012 wrote `url ~ '^https?://'`, which is looser than what actually happens:
-- `checkDestination` refuses anything but https, so an http endpoint could be
-- stored and would then fail every delivery attempt forever. A row the system
-- can never act on is a trap for whoever wrote it — the shape the database
-- accepts should be the shape the code accepts.
--
-- Plaintext is refused because a webhook carries a signed statement about who
-- was denied what, and over http that is readable and rewritable in flight. The
-- signature would still detect tampering; it would not stop the reading.

alter table webhook_endpoints drop constraint webhook_endpoints_url_check;

alter table webhook_endpoints add constraint webhook_endpoints_url_check
  check (url ~ '^https://' and length(url) between 9 and 2048);

comment on column webhook_endpoints.url is
  'https only. Checked again by checkDestination on every delivery, because DNS can change after registration.';
