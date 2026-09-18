-- Stage 1, phase 3. Append-only audit with a per-workspace hash chain.
--
-- Spec §7.3 "audit tampering" requires append-only storage, restricted writers,
-- and integrity hashes. Two independent guards, because either alone is weak:
--   * A privilege revoke stops the app role, but the table owner can re-grant.
--   * A trigger cannot be bypassed without DDL, which is a separate privilege.

create table audit_events (
  -- Chain order. Separate from the public id so ordering never depends on a
  -- caller-supplied value.
  seq            bigint      generated always as identity primary key,
  id             text        not null unique check (id ~ '^aud_[A-Za-z0-9_-]{1,64}$'),
  workspace_id   text        not null references workspaces (id) on delete restrict,
  actor          text        not null,
  event_type     text        not null,
  -- A *reference*, never content. Spec §11 data minimisation, invariant 5.
  resource_ref   text,
  outcome        text        not null check (outcome in ('allow', 'deny', 'challenge', 'lifecycle')),
  correlation_id text,
  prev_hash      bytea,
  hash           bytea       not null,
  occurred_at    timestamptz not null default now(),

  unique (workspace_id, id)
);

comment on column audit_events.resource_ref is
  'Opaque reference to the resource. Never document bodies or message contents.';

-- Chain each event to its predecessor within the same workspace.
create or replace function audit_events_chain() returns trigger
  language plpgsql
  set search_path = public, pg_catalog
as $$
declare
  prev bytea;
  payload text;
begin
  -- Serialise chain writes per workspace. Without this, two concurrent inserts
  -- read the same predecessor and produce a fork that verification would miss.
  perform pg_advisory_xact_lock(hashtext(new.workspace_id)::bigint);

  select ae.hash into prev
    from audit_events ae
   where ae.workspace_id = new.workspace_id
   order by ae.seq desc
   limit 1;

  new.prev_hash := prev;

  -- Unit separator between fields so concatenation cannot be gamed by a value
  -- containing the delimiter.
  payload := concat_ws(
    chr(31),
    new.id, new.workspace_id, new.actor, new.event_type,
    coalesce(new.resource_ref, ''), new.outcome,
    coalesce(new.correlation_id, ''),
    to_char(new.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
  );

  new.hash := public.digest(coalesce(prev, ''::bytea) || convert_to(payload, 'utf8'), 'sha256');
  return new;
end;
$$;

create trigger audit_events_chain_trg
  before insert on audit_events
  for each row execute function audit_events_chain();

create or replace function audit_events_immutable() returns trigger
  language plpgsql
  set search_path = pg_catalog
as $$
begin
  raise exception 'audit_events is append-only (spec §7.3 audit tampering)'
    using errcode = 'restrict_violation';
end;
$$;

create trigger audit_events_no_update_trg
  before update on audit_events
  for each row execute function audit_events_immutable();

create trigger audit_events_no_delete_trg
  before delete on audit_events
  for each row execute function audit_events_immutable();

create trigger audit_events_no_truncate_trg
  before truncate on audit_events
  for each statement execute function audit_events_immutable();

revoke update, delete, truncate on audit_events from public;

create index audit_events_workspace_time_idx on audit_events (workspace_id, occurred_at desc);
create index audit_events_workspace_type_idx on audit_events (workspace_id, event_type, occurred_at desc);

-- Walks a workspace's chain and returns the first break, if any.
create or replace function audit_chain_verify(p_workspace_id text)
  returns table (broken_at bigint, event_id text)
  language plpgsql
  set search_path = public, pg_catalog
as $$
declare
  r        record;
  expected bytea := null;
  payload  text;
begin
  for r in
    select * from audit_events
     where workspace_id = p_workspace_id
     order by seq asc
  loop
    payload := concat_ws(
      chr(31),
      r.id, r.workspace_id, r.actor, r.event_type,
      coalesce(r.resource_ref, ''), r.outcome,
      coalesce(r.correlation_id, ''),
      to_char(r.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.USOF')
    );

    if r.prev_hash is distinct from expected then
      broken_at := r.seq; event_id := r.id; return next; return;
    end if;

    if r.hash <> public.digest(coalesce(expected, ''::bytea) || convert_to(payload, 'utf8'), 'sha256') then
      broken_at := r.seq; event_id := r.id; return next; return;
    end if;

    expected := r.hash;
  end loop;
  return;
end;
$$;
