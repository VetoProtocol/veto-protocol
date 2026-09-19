/**
 * Reading the audit timeline (spec §5 `/v1/audit-events`, §11).
 *
 * The write side has always been careful — `AuditEventInput` has no field that
 * can carry a document body, a token, or a passkey challenge. The read side
 * inherits that: every column returned here is an identifier, a classification,
 * or a hash, because those are the only kinds of column the table has.
 *
 * ## Why the hashes are returned
 *
 * `prev_hash` and `hash` go out with each event on purpose. A hash chain whose
 * links only the server can see is a promise, not a proof — the customer should
 * be able to export the timeline and verify it themselves, which is also what
 * §11's portability requirement asks for. They are not secrets: they are
 * digests of data the reader already has.
 *
 * ## Why the cursor is `seq`
 *
 * `occurred_at` is a timestamp and two events can share one. Paging on a
 * non-unique column either skips rows or repeats them, and an audit timeline
 * that quietly drops an event is worse than one that is hard to read. `seq` is
 * the identity column the chain is ordered by, so it is unique and monotonic by
 * construction.
 */

import type { Db } from '@veto/db';

export interface AuditEvent {
  readonly seq: number;
  readonly id: string;
  readonly actor: string;
  readonly eventType: string;
  readonly resourceRef: string | null;
  readonly outcome: 'allow' | 'deny' | 'challenge' | 'lifecycle';
  readonly correlationId: string | null;
  readonly prevHash: string | null;
  readonly hash: string;
  readonly occurredAt: Date;
}

interface AuditRow {
  seq: string;
  id: string;
  actor: string;
  event_type: string;
  resource_ref: string | null;
  outcome: AuditEvent['outcome'];
  correlation_id: string | null;
  prev_hash: Buffer | null;
  hash: Buffer;
  occurred_at: Date;
}

const toEvent = (row: AuditRow): AuditEvent => ({
  // bigint arrives as a string from pg.
  seq: Number(row.seq),
  id: row.id,
  actor: row.actor,
  eventType: row.event_type,
  resourceRef: row.resource_ref,
  outcome: row.outcome,
  correlationId: row.correlation_id,
  prevHash: row.prev_hash === null ? null : row.prev_hash.toString('hex'),
  hash: row.hash.toString('hex'),
  occurredAt: row.occurred_at,
});

export interface AuditQuery {
  /** Return events strictly older than this seq. Newest first. */
  readonly before?: number | null;
  readonly limit?: number;
  readonly eventType?: string | null;
  readonly actor?: string | null;
  readonly outcome?: AuditEvent['outcome'] | null;
  readonly correlationId?: string | null;
}

export interface AuditPage {
  readonly events: readonly AuditEvent[];
  /** Pass back as `before`. Null when the timeline is exhausted. */
  readonly nextCursor: number | null;
}

export const AUDIT_PAGE_MAX = 200;

export async function readAuditEvents(
  db: Db,
  workspaceId: string,
  query: AuditQuery = {},
): Promise<AuditPage> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), AUDIT_PAGE_MAX);

  // Filters are separate parameters, never interpolated. An audit reader is an
  // obvious place to try an injection because it is the one endpoint whose
  // whole job is returning rows.
  const { rows } = await db.query<AuditRow>(
    `select seq, id, actor, event_type, resource_ref, outcome, correlation_id,
            prev_hash, hash, occurred_at
       from audit_events
      where workspace_id = $1
        and ($2::bigint is null or seq < $2)
        and ($3::text is null or event_type = $3)
        and ($4::text is null or actor = $4)
        and ($5::text is null or outcome = $5)
        and ($6::text is null or correlation_id = $6)
      order by seq desc
      limit $7`,
    [
      workspaceId,
      query.before ?? null,
      query.eventType ?? null,
      query.actor ?? null,
      query.outcome ?? null,
      query.correlationId ?? null,
      // One extra row, to tell "this page is full" from "there is more".
      limit + 1,
    ],
  );

  const page = rows.slice(0, limit).map(toEvent);
  const hasMore = rows.length > limit;

  return {
    events: page,
    nextCursor: hasMore ? (page[page.length - 1]?.seq ?? null) : null,
  };
}

export interface ChainVerification {
  readonly verified: boolean;
  /** The first event whose link does not hold, when the chain is broken. */
  readonly brokenAt: number | null;
  readonly eventId: string | null;
}

/**
 * Walk the workspace's chain and report the first break.
 *
 * Delegated to `audit_chain_verify()` so verification happens where the data
 * is — recomputing the digests in the application would mean reproducing the
 * trigger's exact field order and separator, and a verifier that disagrees with
 * the writer reports breaks that are its own fault.
 */
export async function verifyAuditChain(db: Db, workspaceId: string): Promise<ChainVerification> {
  const { rows } = await db.query<{ broken_at: string; event_id: string }>(
    `select broken_at, event_id from audit_chain_verify($1)`,
    [workspaceId],
  );

  const break_ = rows[0];
  if (!break_) return { verified: true, brokenAt: null, eventId: null };

  return { verified: false, brokenAt: Number(break_.broken_at), eventId: break_.event_id };
}
