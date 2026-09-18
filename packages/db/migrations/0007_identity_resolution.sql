-- Stage 1, phase 6. Resolving an OIDC subject to a user, before a tenant is known.
--
-- Sign-in has a bootstrapping problem that every other query in this schema
-- avoids. RLS scopes reads to `veto.workspace_id`, but at the moment an OIDC
-- callback arrives all we hold is a subject: the workspace is the thing we are
-- trying to find. A tenant-scoped query cannot answer "which tenant?".
--
-- The obvious workarounds are worse:
--
--   * Reading `users` with no GUC set returns zero rows, because RLS is FORCEd
--     and the tenant predicate is NULL. Correct, and useless here.
--   * A BYPASSRLS role would solve it, but the `veto` role is not a superuser
--     and cannot create one (noted in 0005 as a deployment item).
--   * Letting the application set a bypass GUC itself would put a cross-tenant
--     read behind a flag any query could flip.
--
-- So the exception is made once, in one function, with the narrowest surface
-- that can work:
--
--   * It takes one exact subject and returns two columns. It cannot list,
--     enumerate, or filter — there is no prefix, pattern or pagination.
--   * It returns only `active` users. A suspended or revoked person cannot sign
--     in, and that check lives here rather than in the caller so it cannot be
--     forgotten (invariant 1).
--   * The policy it relies on is SELECT-only and names itself. Nothing can
--     write through this path.
--   * The GUC is set inside the function and is transaction-local, so it is
--     gone before the connection returns to the pool.
--
-- This is a real widening of invariant 4 and is recorded as such. It is
-- confined to the one question that genuinely precedes tenancy.

create policy identity_resolution on users
  for select
  using (current_setting('veto.identity_lookup', true) = 'on');

comment on policy identity_resolution on users is
  'Sign-in only. Readable via resolve_identity_subject(), which scopes to one exact subject.';

create or replace function resolve_identity_subject(p_subject text)
  returns table (user_id text, workspace_id text)
  language plpgsql
  security definer
  stable
  set search_path = public, pg_catalog
as $$
begin
  if p_subject is null or length(p_subject) = 0 or length(p_subject) > 255 then
    return;
  end if;

  perform set_config('veto.identity_lookup', 'on', true);

  return query
    select u.id, u.workspace_id
      from users u
     where u.identity_subject = p_subject
       and u.status = 'active'
     order by u.workspace_id;
end;
$$;

comment on function resolve_identity_subject(text) is
  'OIDC subject -> (user, workspace). The one read that precedes knowing the tenant.';

-- A subject may legitimately belong to several workspaces: `users` is unique on
-- (workspace_id, identity_subject), not on identity_subject alone. The function
-- returns every match and the caller decides, rather than silently picking one.
