-- Whether a changed client is allowed to matter, per agent.
--
-- Migration 0026 recorded what connects and deliberately added no mode column,
-- because `agents.fingerprint` had spent twenty-five migrations looking like a
-- control while nothing read it. This column arrives with the code that
-- honours it, which is the pipeline's step 3.
--
-- ## Three settings, and why the default is the weakest one
--
--   observe    record only. Never changes an answer.
--   challenge  an unpinned client needs the delegating human's approval.
--   deny       an unpinned client is refused.
--
-- `observe` is the default and every existing agent gets it, so applying this
-- migration changes no decision anywhere. That is not timidity: a gateway in
-- production is being used right now by a client nobody has pinned yet, and a
-- default that enforced would refuse the operator's own session the moment the
-- migration ran. The switch belongs to whoever can see the list of what has
-- been connecting.
--
-- ## `observe` means observe
--
-- In `observe` the fingerprint cannot change an outcome at all — not even a
-- client an operator has explicitly marked `refused`. The alternative was to
-- let a refusal bite in every mode, which reads as the safer choice and is
-- worse: it makes the mode's meaning conditional, and a control whose effect
-- depends on two settings at once is one nobody can reason about at three in
-- the morning. The screen therefore offers `Refuse` only where enforcement is
-- on, so the button never promises something the mode will ignore.
--
-- It also means the common case costs nothing: step 3 skips the lookup
-- entirely when the mode is `observe`, so a workspace that has not turned this
-- on spends no part of the §11 budget on it.

alter table agents
  add column fingerprint_mode text not null default 'observe'
    check (fingerprint_mode in ('observe', 'challenge', 'deny'));

comment on column agents.fingerprint_mode is
  'Whether an unrecognised client software narrows this agent''s answer. Read at §3.3 step 3. Default observe: records, decides nothing.';

-- The declared field from migration 0002 is not the one being read.
--
-- `agents.fingerprint` was free text an operator typed at registration, and
-- nothing ever compared anything to it. It is deliberately NOT consumed as a
-- constraint on the first sighting: it is unvalidated, nobody has filled it in
-- with a real digest, and turning a stale guess into a lockout is a worse
-- failure than leaving a dead field alone. `agent_fingerprints` is the record
-- that decides; this comment is here so the next reader does not assume the
-- two are connected.
comment on column agents.fingerprint is
  'Legacy, unused. An operator-declared string from migration 0002 that nothing reads. The observed record is agent_fingerprints; see docs/fingerprints.md.';
