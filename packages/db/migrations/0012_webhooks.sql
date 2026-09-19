-- Stage 4, phase 2. Alerts (spec §5.4).
--
-- Eight events, and a way for somebody to find out about them. Until now a
-- workspace could be locked, an agent revoked and a credential destroyed with
-- the only record being a row nobody is watching.
--
-- Two tables, because an endpoint and an attempt to reach it are different
-- lifetimes: endpoints are configuration and outlive everything, deliveries are
-- a queue that drains.
--
-- ## Why delivery is a table and not a fetch
--
-- §5.4 wants retry with exponential backoff and idempotent consumers, and
-- neither is possible from inside the request that caused the event. Worse, a
-- webhook endpoint that hangs would hold up a decision — a receiver's outage
-- would become an authorization outage. So the row is written in the same
-- transaction as the thing it describes (an event cannot exist for something
-- that rolled back) and a worker drains it afterwards.

create table webhook_endpoints (
  id            text        primary key check (id ~ '^whe_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,

  -- Checked against the same SSRF rules as any other destination before it is
  -- stored. A webhook target is a caller-supplied URL that this server fetches,
  -- which is the §12.1 SSRF scenario wearing a different hat.
  url           text        not null check (url ~ '^https?://' and length(url) between 8 and 2048),

  -- The signing secret, envelope-encrypted. It has to be reversible because the
  -- receiver verifies with the same bytes, and reversible secrets live in the
  -- vault. Per endpoint, so one compromised receiver cannot forge events to
  -- another.
  secret_sealed bytea       not null,
  secret_key_id text        not null,

  -- Which of the eight §5.4 events this endpoint wants. Empty means none, not
  -- all: an endpoint that subscribed to nothing should receive nothing.
  events        text[]      not null,

  status        text        not null default 'active' check (status in ('active', 'disabled')),
  created_by    text        not null,
  created_at    timestamptz not null default now(),
  disabled_at   timestamptz,

  unique (workspace_id, id),
  -- One endpoint per URL per workspace. Two rows for the same receiver would
  -- double every delivery and halve the value of an idempotency key.
  unique (workspace_id, url),
  foreign key (workspace_id, created_by) references users (workspace_id, id) on delete restrict,

  constraint disabled_has_timestamp check ((status = 'disabled') = (disabled_at is not null))
);

comment on column webhook_endpoints.secret_sealed is
  'Envelope-encrypted per §3.4. The encryption context binds workspace, purpose and endpoint id.';

create table webhook_deliveries (
  id              text        primary key check (id ~ '^whd_[A-Za-z0-9_-]{1,64}$'),
  workspace_id    text        not null references workspaces (id) on delete restrict,
  endpoint_id     text        not null,

  -- Stable across every retry. This is what an idempotent consumer deduplicates
  -- on (§5.4), so it must not be regenerated when an attempt fails.
  event_id        text        not null check (event_id ~ '^evt_[A-Za-z0-9_-]{1,64}$'),
  event_type      text        not null,

  -- What is sent. Carries no document content, no arguments, no tokens and no
  -- challenges (invariant 5) — the shape is enforced in TypeScript, and there
  -- is nothing here that would make a wider payload representable.
  payload         jsonb       not null,

  status          text        not null default 'pending'
                              check (status in ('pending', 'delivered', 'failed')),
  attempts        integer     not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  last_status     integer,
  -- A short reason, never a response body. A receiver's error page is somebody
  -- else's content and may echo what we sent it.
  last_error      text        check (last_error is null or length(last_error) <= 200),
  delivered_at    timestamptz,
  occurred_at     timestamptz not null default now(),

  unique (workspace_id, id),
  -- One delivery per event per endpoint. An emitter that fires twice for the
  -- same event produces one row, not two attempts at the receiver.
  unique (workspace_id, endpoint_id, event_id),
  foreign key (workspace_id, endpoint_id)
    references webhook_endpoints (workspace_id, id) on delete cascade,

  constraint delivered_has_timestamp check ((status = 'delivered') = (delivered_at is not null))
);

-- The worker's only query: what is due, oldest first. Partial, because
-- delivered and failed rows are never the answer and this table is append-heavy.
create index webhook_deliveries_due_idx
  on webhook_deliveries (workspace_id, next_attempt_at)
  where status = 'pending';

create index webhook_deliveries_recent_idx
  on webhook_deliveries (workspace_id, occurred_at desc);

alter table webhook_endpoints enable row level security;
alter table webhook_endpoints force row level security;
create policy tenant_isolation on webhook_endpoints
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

alter table webhook_deliveries enable row level security;
alter table webhook_deliveries force row level security;
create policy tenant_isolation on webhook_deliveries
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());
