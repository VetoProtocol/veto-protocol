-- Stage 3 follow-up. Sensitivity labels on resources (spec §4.2 `sensitivity`).
--
-- Before this, "sensitive" meant "a policy rule happened to carry a presence
-- condition". That works but it scatters the decision: protecting a folder
-- meant remembering to add the condition to every rule that could reach it, and
-- forgetting one left a gap with nothing to point at.
--
-- A label moves the protection to the thing being protected. Mark /Finance
-- confidential once, and every rule that reaches it inherits the requirement.
--
-- Two rules that keep this from becoming a second policy engine:
--
--   * **A label can only narrow.** It never grants. A rule still has to allow
--     the action; the label can add a presence or intent requirement on top.
--     Marking something `public` does not open it.
--   * **Most specific wins**, and specificity is longest match. An exact
--     resource id beats a prefix, and a longer prefix beats a shorter one, so
--     /Finance/Public can be less restricted than /Finance without ambiguity.

create table resource_labels (
  id            text        primary key check (id ~ '^lbl_[A-Za-z0-9_-]{1,64}$'),
  workspace_id  text        not null references workspaces (id) on delete restrict,
  resource_type text        not null check (length(resource_type) between 1 and 60),

  -- Matched against the resource id. A prefix by default; `exact` pins it.
  pattern       text        not null check (length(pattern) between 1 and 512),
  exact         boolean     not null default false,

  sensitivity   text        not null check (sensitivity in ('public', 'internal', 'confidential', 'restricted')),
  note          text        check (note is null or length(note) between 1 and 200),
  created_at    timestamptz not null default now(),
  created_by    text        not null,

  unique (workspace_id, id),
  -- One label per resource pattern per type: two labels disagreeing about the
  -- same resource would make the answer depend on row order.
  unique (workspace_id, resource_type, pattern, exact),
  foreign key (workspace_id, created_by) references users (workspace_id, id) on delete restrict
);

comment on table resource_labels is
  'Sensitivity attached to resources. Only ever adds a requirement; never grants.';

create index resource_labels_lookup_idx
  on resource_labels (workspace_id, resource_type, pattern);

alter table resource_labels enable row level security;
alter table resource_labels force row level security;
create policy tenant_isolation on resource_labels
  using (workspace_id = current_workspace_id())
  with check (workspace_id = current_workspace_id());
