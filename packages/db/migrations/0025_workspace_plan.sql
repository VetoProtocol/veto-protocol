-- Which tier a workspace is on.
--
-- Until now "PRO" was a badge in the sidebar beside features that did not exist.
-- That was harmless while nothing was behind it. The moment one of those
-- features shipped, the badge had nothing to enforce: a paying and a
-- non-paying workspace were indistinguishable to every line of code.
--
-- This is the column that makes the badge mean something. It is deliberately
-- the smallest possible shape — two values, no billing, no dates, no provider
-- ids. Veto is not a billing system, and a plan column is the only part of one
-- it needs to answer "may this workspace see this screen".
--
-- `free` is the default, so every existing workspace keeps exactly the access it
-- had. An upgrade is one update statement, and nothing is wasted if this is
-- later replaced by a real entitlements table: every reader goes through `plan`
-- rather than through a count of anything.

alter table workspaces
  add column plan text not null default 'free' check (plan in ('free', 'pro'));

comment on column workspaces.plan is
  'Tier. Read at request time, never cached in a session cookie: an upgrade must take effect on the next page, not on the next sign-in.';
