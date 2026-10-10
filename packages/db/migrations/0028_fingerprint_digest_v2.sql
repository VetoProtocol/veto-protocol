-- Clear every recorded fingerprint, because what goes into the digest changed.
--
-- `FINGERPRINT_VERSION` moved from 1 to 2: the channel — the parenthesised
-- comment in a `User-Agent` — is no longer hashed. It is still recorded.
--
-- ## Why it had to come out
--
-- One Claude Code install, measured twice:
--
--   claude-code/2.1.293 (sdk-cli)   the client's own server health check
--   claude-code/2.1.289 (cli)       an actual tool call
--
-- Same machine, same install, same person. The channel varies with which
-- internal path built the request, exactly as the version varies with when the
-- client was last updated. Hashing it would have given every user two
-- fingerprints for one program, pinned whichever connected first, and
-- challenged the other the moment anybody turned enforcement on — the precise
-- false alarm the version was split out to avoid. The product is what survives.
--
-- ## Why the rows go rather than being migrated
--
-- Nothing can translate a v1 digest into a v2 one: the hash is one-way, and
-- recomputing it here would mean duplicating the formatter in SQL.
--
-- Leaving them would be worse than clearing them. Trust on first use pins only
-- when an agent has *no* rows, so a stale v1 row would sit there, the agent's
-- real client would arrive under its new v2 digest as `seen` rather than
-- `pinned`, and every existing agent would raise a "new software" alert for the
-- software it has always been using. Clearing the table lets first use pin
-- cleanly on the next request.
--
-- What is lost is first-seen dates and request counts, for a table that is
-- hours old and that no policy reads. Nothing that ever decided anything is
-- affected: no workspace has left `observe`, which is why this is cheap today
-- and would not have been in a month.

truncate table agent_fingerprints;

comment on column agent_fingerprints.channel is
  'The parenthesised comment from the User-Agent, e.g. "cli". Recorded, never hashed: one install sends different channels from different internal paths, so hashing it would split one program into two identities.';
