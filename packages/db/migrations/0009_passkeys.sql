-- Stage 3, phase 2. Enrolled passkeys (spec §7.1, §15 WebAuthn).
--
-- `users.passkey_enrolled` has been a boolean since 0002, which answers "can
-- this person be challenged at all" but holds nothing to verify a signature
-- against. This is where the credentials live.
--
-- Design notes that matter:
--
--  * `credential_id` is globally unique, not unique per workspace. A WebAuthn
--    credential belongs to exactly one account; the same authenticator
--    registering twice must collide rather than quietly create a second
--    identity that can satisfy the first one's challenges.
--
--  * `sign_count` is the authenticator's own counter. A signature arriving with
--    a counter at or below the stored value means the credential has been
--    cloned, or a response is being replayed. Storing it is what makes that
--    detectable; the check lives in the verification path.
--
--  * The public key is stored, never a private one — a passkey's private half
--    never leaves the user's device. Nothing here is a secret in the sense the
--    vault deals with, so it needs no envelope encryption.
--
--  * Several credentials per user is the normal case, not an edge case. One
--    passkey is one lost phone away from being locked out of every approval.

create table passkeys (
  id            text        primary key check (id ~ '^pky_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  user_id       text        not null,

  -- The WebAuthn credential id, as raw bytes.
  credential_id bytea       not null unique,
  public_key    bytea       not null,
  sign_count    bigint      not null default 0 check (sign_count >= 0),
  transports    text[]      not null default '{}',

  -- A label the user recognises, e.g. "MacBook Touch ID". Never a device
  -- fingerprint and never used for policy — presence and identity come from the
  -- signature, not from what the thing calls itself.
  label         text        check (label is null or length(label) between 1 and 80),

  created_at    timestamptz not null default now(),
  last_used_at  timestamptz,

  unique (workspace_id, id),
  foreign key (workspace_id, user_id) references users (workspace_id, id) on delete restrict
);

comment on column passkeys.sign_count is
  'Authenticator counter. A non-increasing value on use indicates cloning or replay.';

create index passkeys_owner_idx on passkeys (workspace_id, user_id);

alter table passkeys enable row level security;
alter table passkeys force row level security;
create policy tenant_isolation on passkeys
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());
