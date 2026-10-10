-- What software has been connecting as each agent.
--
-- `agents.fingerprint` has existed since migration 0002 and nothing has ever
-- read it. It was an operator-*declared* value: somebody typed a string at
-- registration and no code compared anything to it. This table is the
-- *observed* counterpart — what actually arrived, when, and how often.
--
-- ## What is being measured, and what it is worth
--
-- Everything here is derived from the `User-Agent` of the MCP request. Measured
-- against Claude Code 2.1.293 on 2026-10-09, that header is present on every
-- request in the connection — the handshake, the SSE stream, `tools/list` and
-- therefore `tools/call`:
--
--   user-agent: claude-code/2.1.293 (sdk-cli)
--
-- That it arrives with the tool call itself is what makes this usable at all.
-- The gateway is stateless per HTTP request and the MCP `clientInfo` object
-- comes only with `initialize`, so anything keyed to the handshake would need
-- shared state and would be absent for a client that never handshook.
--
-- A `User-Agent` is a string the client chose to send. Somebody who steals a
-- gateway token can send the same string. This is change detection, not
-- authentication, and the only honest claim for it is that it raises the cost
-- of using a stolen credential from zero to slightly above zero. Nothing
-- downstream may treat a matching fingerprint as proof of anything.
--
-- ## Why the version is not part of the digest
--
-- `product` and `channel` are stable across releases; the version moves on
-- every one. Hashing the whole header would make every Claude Code update look
-- exactly like a different program arriving on the same credential, so the
-- control would fire constantly and be switched off — and a control that is off
-- protects nothing. The digest covers the stable half; the version is recorded
-- beside it as a fact an operator can read.
--
-- ## Nothing here decides anything yet
--
-- This migration and the code that writes it are observation only. No column
-- here is read by the §3.3 pipeline, no request is denied or challenged because
-- of a row in this table, and `agents` gains no mode column — the one lesson
-- `agents.fingerprint` already taught is that a column nothing reads is worse
-- than no column, because it looks like a control. The mode arrives in the same
-- migration as the code that honours it.

create table agent_fingerprints (
  workspace_id text not null references workspaces (id) on delete restrict,
  agent_id     text not null,

  -- Over the stable half only, and versioned: see `FINGERPRINT_VERSION` in
  -- packages/identity/src/fingerprints.ts. If what goes into the hash ever
  -- changes, every stored digest stops matching — the version prefix makes
  -- that a visible migration rather than a silent mass re-pinning.
  fingerprint  text not null check (fingerprint ~ '^sha256:[0-9a-f]{64}$'),

  -- The hashed half, kept legible so a human can read a row without reversing
  -- a digest. `(absent)` and `(unparsable)` are sentinels; parentheses are not
  -- legal in an HTTP token, so neither can collide with a real product name.
  product      text not null check (length(product) between 1 and 200),
  channel      text check (length(channel) between 1 and 200),

  -- The moving half. Recorded, never hashed.
  first_version text check (length(first_version) between 1 and 200),
  last_version  text check (length(last_version) between 1 and 200),

  -- From the MCP `initialize` handshake, when one was seen. Richer than the
  -- header but handshake-only, so it is context for a screen and never
  -- material for a decision.
  client_name      text check (length(client_name) between 1 and 200),
  client_title     text check (length(client_title) between 1 and 200),
  client_version   text check (length(client_version) between 1 and 200),
  protocol_version text check (length(protocol_version) between 1 and 200),

  -- `seen` is every row's starting state and says only that this software
  -- turned up. Deliberately not a synonym for trusted: promoting a row to
  -- `pinned` is a human act, and nothing in this phase performs it.
  status text not null default 'seen' check (status in ('pinned', 'seen', 'refused')),

  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  sightings     bigint      not null default 1 check (sightings > 0),

  primary key (workspace_id, agent_id, fingerprint),

  -- An agent in workspace A cannot acquire a fingerprint recorded against
  -- workspace B, and the composite target makes that unrepresentable rather
  -- than merely untested.
  foreign key (workspace_id, agent_id) references agents (workspace_id, id) on delete restrict,

  constraint last_seen_not_before_first check (last_seen_at >= first_seen_at)
);

alter table agent_fingerprints enable row level security;
alter table agent_fingerprints force row level security;
create policy tenant_isolation on agent_fingerprints
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

-- The screen's query: every fingerprint for an agent, newest sighting first.
create index agent_fingerprints_recent_idx
  on agent_fingerprints (workspace_id, agent_id, last_seen_at desc);

comment on table agent_fingerprints is
  'Observed MCP client software per agent, derived from the request User-Agent. Change detection, never authentication: every value is one the client chose to send.';

comment on column agent_fingerprints.fingerprint is
  'Digest of the stable half (product, channel) only. The version moves on every release and is recorded separately, so an update is a note rather than an alarm.';

comment on column agent_fingerprints.sightings is
  'How many requests carried this fingerprint. Bounded growth per agent is enforced in the writer, not here: see MAX_FINGERPRINTS_PER_AGENT.';
