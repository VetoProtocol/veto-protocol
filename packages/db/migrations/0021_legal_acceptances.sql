-- Who agreed to what, and when (a prerequisite for OAuth verification, and for
-- being able to answer the question at all).
--
-- A consent dialogue that records nothing is decoration: it either nags forever
-- or it is dismissed once and forgotten, and in both cases nobody can say
-- afterwards whether a given person agreed to a given text. This is the record.
--
-- ## One row per document per version, never updated
--
-- Acceptance is an event, not a state. When the terms change, the new version
-- is a new row and the old row stays exactly as it was — so "did this person
-- agree to the text we were showing in September" remains answerable in March.
-- Updating a row in place would replace the evidence with its successor.
--
-- The unique constraint makes re-submitting idempotent rather than duplicating,
-- which matters because a double-click on a modal is not a second agreement.
--
-- ## Deliberately not on `users`
--
-- Two columns on `users` would have been less work and would have thrown the
-- history away on the first revision. It would also have meant a legal record
-- living in a row the application updates for unrelated reasons.
create table legal_acceptances (
  id           text        primary key check (id ~ '^lac_[A-Za-z0-9_-]{1,64}$'),
  workspace_id text        not null references workspaces (id) on delete cascade,
  user_id      text        not null,
  -- A closed set. A free-text document name would make the outstanding-document
  -- check unanswerable: you cannot tell what is missing without knowing what
  -- the full list is.
  document     text        not null check (document in ('terms', 'privacy')),
  -- The published date of the text that was shown, as ISO 8601. Whatever the
  -- person actually read is identified by this, so it is stored as given rather
  -- than derived.
  version      text        not null check (version ~ '^\d{4}-\d{2}-\d{2}$'),
  accepted_at  timestamptz not null default now(),

  foreign key (workspace_id, user_id) references users (workspace_id, id) on delete cascade,
  unique (workspace_id, user_id, document, version)
);

create index legal_acceptances_by_user
  on legal_acceptances (workspace_id, user_id);

-- Tenant isolation, the same as every other table (invariant 4). FORCEd because
-- the veto role owns it.
alter table legal_acceptances enable row level security;
alter table legal_acceptances force row level security;
create policy tenant_isolation on legal_acceptances
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());

comment on table legal_acceptances is
  'Append-only record of which published document version each user agreed to. One row per user per document per version; never updated.';
