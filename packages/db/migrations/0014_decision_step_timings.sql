-- Per-step timings on a decision (§11).
--
-- `latency_ms` records how long the whole decision took. It has never recorded
-- where that time went, so "authorization overhead P95 < 200 ms" could be
-- checked in aggregate and never diagnosed: a slow decision looked the same
-- whether Permit was slow, the presence lookup was slow, or the audit write was.
-- The decision trace screen says "per-step timings are not recorded yet" in as
-- many words, which is honest and is the hole this closes.
--
-- jsonb rather than fourteen columns. The pipeline has nine steps, two of which
-- never run on most requests, and a decision that stopped at step 5 has nothing
-- to say about steps 6 to 9 — a shape that is naturally sparse. Adding a step
-- would otherwise be a migration.
--
-- Nullable, and left null for every row written before this. A missing map means
-- "not measured", which is different from "measured as zero", and the screen has
-- to be able to tell those apart.
--
-- What it may contain is deliberately narrow: step keys and numbers. No
-- argument, resource, tool response or identifier goes in here. Invariant 5
-- applies to a timing map exactly as it applies to an audit event — the fact
-- that a value is a duration is not a reason to relax about what sits beside it.
alter table decisions add column step_timings jsonb;

comment on column decisions.step_timings is
  'Milliseconds per §3.3 step, keyed by step name. Null for rows written before timings were recorded. Numbers only — never arguments, content or identifiers (invariant 5).';
