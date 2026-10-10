/**
 * Which software is connecting as this agent.
 *
 * ## What this is, and what it is not
 *
 * An MCP client sends a `User-Agent` with every request. Measured against
 * Claude Code 2.1.293, it looks like this, and it is present on the handshake,
 * the SSE stream, `tools/list` and `tools/call` alike:
 *
 *     claude-code/2.1.293 (sdk-cli)
 *
 * That is the whole raw material. It is a string the client chose to send, so
 * anyone holding a stolen gateway token can send the same one. **This is
 * change detection, never authentication.** A matching fingerprint is not
 * evidence of anything; a *changed* one is a fact worth putting in front of an
 * operator. Nothing in this module may be read as proof of identity, and the
 * screens that display it have to say so in words.
 *
 * ## The split that makes it usable
 *
 * `product` and `channel` survive a release. The version does not. Hashing the
 * whole header would make every routine Claude Code update indistinguishable
 * from a different program arriving on the same credential — the control would
 * fire on every upgrade, somebody would switch it off, and a control that is
 * off protects nothing.
 *
 * So the digest covers the stable half and the version rides alongside as a
 * recorded fact. "A different program is using this agent" is the alarm;
 * "this program updated itself" is a note with a date on it.
 *
 * ## Nothing here decides anything
 *
 * This module observes. It returns no verdict, and `recordSighting` is called
 * outside the §3.3 pipeline. A failure to write a row must never deny a
 * request, because at this phase the row changes no outcome and refusing
 * someone over failed bookkeeping would be a new way to break rather than a
 * way to be safe.
 */

import { createHash } from 'node:crypto';
import type { Db } from '@veto/db';
import type { FingerprintMode } from './agents.ts';

/**
 * What goes into the digest, as a version number.
 *
 * Every stored fingerprint was produced by one of these. Changing what is
 * hashed invalidates every pin in the database, so the version is part of the
 * hashed payload: a change becomes a visible migration instead of a silent
 * mass re-pinning that an operator would read as "everything changed at once".
 */
export const FINGERPRINT_VERSION = 1;

/**
 * How many distinct fingerprints one agent may accumulate.
 *
 * The `User-Agent` is attacker-controlled, and without a ceiling a caller
 * holding one token could mint a new row per request simply by varying it —
 * unbounded table growth driven by a header, which is the cheapest kind of
 * denial of service there is. Past the ceiling, existing rows keep counting
 * and new ones are dropped: the record stops growing rather than the request
 * stopping, because this is observation and must not become an outage.
 */
export const MAX_FINGERPRINTS_PER_AGENT = 20;

/** Longest value stored for any single field. Longer is truncated, not refused. */
const MAX_FIELD = 200;

/** No `User-Agent` at all. Parentheses cannot occur in an HTTP token, so this cannot collide. */
export const PRODUCT_ABSENT = '(absent)';

/** A `User-Agent` that is present but not shaped like one. Same collision argument. */
export const PRODUCT_UNPARSABLE = '(unparsable)';

/** RFC 9110 token characters. A product name outside this set is not a product name. */
const TOKEN = "[!#$%&'*+\\-.^_`|~0-9A-Za-z]+";
const PRODUCT = new RegExp(`^(${TOKEN})(?:/(${TOKEN}))?`);

export interface ClientObservation {
  /** `sha256:<64 hex>` over the stable half. */
  readonly fingerprint: string;
  /** `claude-code`, or one of the two sentinels. */
  readonly product: string;
  /** The first parenthesised comment — `sdk-cli` — or null. */
  readonly channel: string | null;
  /** The moving half. Never hashed. */
  readonly version: string | null;
}

/**
 * Control characters are stripped before anything else happens.
 *
 * This value reaches a log line and a dashboard table, and a header carrying a
 * newline would otherwise let a caller forge a second log entry. Truncation is
 * silent and deliberate: an over-long header is a thing to bound, not a reason
 * to refuse a request this module has no authority to refuse.
 */
function clean(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, MAX_FIELD);
}

/**
 * Parse a `User-Agent` into the halves that matter.
 *
 * Only the *first* product token is read. A header listing several products is
 * identified by the one that introduced itself first, which is the one that
 * built the request; reading them all would make "same client, extra proxy
 * token" look like a different client.
 */
export function observeClient(userAgent: string | undefined | null): ClientObservation {
  const raw = typeof userAgent === 'string' ? clean(userAgent) : '';

  if (raw === '') return digestOf(PRODUCT_ABSENT, null, null);

  const matched = PRODUCT.exec(raw);
  if (!matched?.[1]) {
    // Present but not shaped like a `User-Agent`. Recorded as one bucket
    // rather than hashed verbatim, so a caller varying unparsable junk fills
    // one row instead of the agent's whole allowance.
    return digestOf(PRODUCT_UNPARSABLE, null, null);
  }

  const comment = /\(([^)]*)\)/.exec(raw)?.[1];
  const channel = comment === undefined ? null : clean(comment) || null;

  return digestOf(matched[1], channel, matched[2] ?? null);
}

function digestOf(product: string, channel: string | null, version: string | null): ClientObservation {
  // A fixed-shape JSON payload, not concatenation. `a|b` and `a` + `|b` must
  // not produce the same digest, and the same discipline governs `actionDigest`
  // in @veto/core.
  const payload = JSON.stringify({ v: FINGERPRINT_VERSION, product, channel });
  const fingerprint = `sha256:${createHash('sha256').update(payload, 'utf8').digest('hex')}`;
  return { fingerprint, product, channel, version };
}

/** What the MCP `initialize` handshake said about itself. Context only. */
export interface ClientHandshake {
  readonly clientName?: string | null;
  readonly clientTitle?: string | null;
  readonly clientVersion?: string | null;
  readonly protocolVersion?: string | null;
}

/**
 * What writing the sighting actually did.
 *
 * `new` is the only newsworthy one: software that is not the first thing this
 * agent ever used has started using it. `first` is an agent being used for the
 * first time, which is not a change and must not raise an alarm — an alert on
 * every agent's first ever request is noise that teaches an operator to ignore
 * the channel.
 */
export type SightingOutcome =
  /** First software ever seen for this agent. Pinned by trust on first use. */
  | { readonly kind: 'first' }
  /** Additional software on an agent that already had some. Recorded as `seen`. */
  | { readonly kind: 'new' }
  /** Already on file. Counters bumped. */
  | { readonly kind: 'repeat' }
  /** MAX_FINGERPRINTS_PER_AGENT reached; nothing written. */
  | { readonly kind: 'dropped' };

export interface SightingInput {
  readonly workspaceId: string;
  readonly agentId: string;
  readonly observation: ClientObservation;
  /** Present only on the request that carried the handshake. */
  readonly handshake?: ClientHandshake | null;
}

/**
 * Write down that this software was seen.
 *
 * One statement, because this runs on the request path and §11 allows 200 ms
 * for the whole authorization decision. The ceiling is enforced inside it
 * rather than by a count-then-insert, which would be two round trips and a
 * race between them.
 *
 * The `where` clause is what makes the ceiling safe: a fingerprint already on
 * file always passes it and gets its counters bumped, so reaching the ceiling
 * stops *new* rows appearing and never freezes the rows already there.
 * Counting first and inserting second would have stopped both.
 */
export async function recordSighting(db: Db, input: SightingInput): Promise<SightingOutcome> {
  const { workspaceId, agentId, observation: seen } = input;
  const hand = input.handshake ?? null;

  const text = (value: string | null | undefined): string | null =>
    typeof value === 'string' && clean(value) !== '' ? clean(value) : null;

  const written = await db.query<{ status: FingerprintStatus; sightings: string }>(
    `insert into agent_fingerprints (
       workspace_id, agent_id, fingerprint, product, channel,
       first_version, last_version,
       client_name, client_title, client_version, protocol_version,
       status
     )
     select $1, $2, $3, $4, $5, $6, $6, $7, $8, $9, $10,
            -- Trust on first use, like an SSH host key.
            --
            -- The first software ever seen for an agent is pinned; everything
            -- after it is merely "seen". Without this, raising the mode to
            -- "challenge" would immediately challenge the client the operator
            -- is sitting in front of, which is how a control gets switched
            -- straight back off again.
            --
            -- What it costs: whoever connects first is trusted, so an attacker
            -- who beats the legitimate client to a freshly registered agent is
            -- pinned instead of it. In practice registration and first use are
            -- the same person minutes apart, the row is visible on the screen,
            -- and an operator can refuse it. Stated here rather than discovered
            -- later.
            case
              when exists (
                select 1 from agent_fingerprints
                 where workspace_id = $1 and agent_id = $2
              ) then 'seen'
              else 'pinned'
            end
      where exists (
              select 1 from agent_fingerprints
               where workspace_id = $1 and agent_id = $2 and fingerprint = $3
            )
         or (
              select count(*) from agent_fingerprints
               where workspace_id = $1 and agent_id = $2
            ) < $11
     on conflict (workspace_id, agent_id, fingerprint) do update
        set last_seen_at = now(),
            sightings    = agent_fingerprints.sightings + 1,
            -- The newest version wins; the first is never overwritten, so a row
            -- carries the span over which this software has been connecting.
            last_version = coalesce(excluded.last_version, agent_fingerprints.last_version),
            -- Handshake fields fill in but never blank out: most requests carry
            -- no handshake, and letting those erase what "initialize" told us
            -- would leave the column empty almost always.
            client_name      = coalesce(excluded.client_name, agent_fingerprints.client_name),
            client_title     = coalesce(excluded.client_title, agent_fingerprints.client_title),
            client_version   = coalesce(excluded.client_version, agent_fingerprints.client_version),
            protocol_version = coalesce(excluded.protocol_version, agent_fingerprints.protocol_version)
     returning status, sightings`,
    [
      workspaceId,
      agentId,
      seen.fingerprint,
      seen.product,
      seen.channel,
      seen.version,
      text(hand?.clientName),
      text(hand?.clientTitle),
      text(hand?.clientVersion),
      text(hand?.protocolVersion),
      MAX_FINGERPRINTS_PER_AGENT,
    ],
  );

  // No row at all means the `where` excluded it: the ceiling is reached and
  // this fingerprint was not already on file.
  const row = written.rows[0];
  if (!row) return { kind: 'dropped' };

  // `sightings` defaults to 1 on insert and the conflict branch increments it,
  // so anything above one is a repeat. Told by the statement itself rather than
  // by a second read, which would race another request doing the same thing.
  if (Number(row.sightings) > 1) return { kind: 'repeat' };

  // Freshly inserted. Trust on first use pinned it only if it was the first.
  return row.status === 'pinned' ? { kind: 'first' } : { kind: 'new' };
}

export interface AgentFingerprint {
  readonly fingerprint: string;
  readonly product: string;
  readonly channel: string | null;
  readonly first_version: string | null;
  readonly last_version: string | null;
  readonly client_name: string | null;
  readonly client_title: string | null;
  readonly client_version: string | null;
  readonly protocol_version: string | null;
  readonly status: 'pinned' | 'seen' | 'refused';
  readonly first_seen_at: Date;
  readonly last_seen_at: Date;
  readonly sightings: string;
}

/** Every fingerprint recorded for one agent, newest sighting first. */
export async function listFingerprints(
  db: Db,
  workspaceId: string,
  agentId: string,
): Promise<AgentFingerprint[]> {
  const { rows } = await db.query<AgentFingerprint>(
    `select fingerprint, product, channel, first_version, last_version,
            client_name, client_title, client_version, protocol_version,
            status, first_seen_at, last_seen_at, sightings
       from agent_fingerprints
      where workspace_id = $1 and agent_id = $2
      order by last_seen_at desc, fingerprint`,
    [workspaceId, agentId],
  );
  return rows;
}

export type FingerprintStatus = 'pinned' | 'seen' | 'refused';

/**
 * Read an agent's mode defensively, defaulting to `observe`.
 *
 * `findAgent` does `select *`, so on a database where migration 0027 has not
 * run the field is simply absent — and `undefined !== 'observe'` is *true*,
 * which would send step 3 into the enforcing branch, query a table that does
 * not exist either, and deny every request in the workspace. A deploy that
 * restarted the services before running the migrations would take the gateway
 * down completely.
 *
 * Defaulting to `observe` here is **not** failing open. If the column does not
 * exist then no workspace can ever have configured enforcement, so `observe` is
 * the only state that could have been set; and if the column does exist, a
 * value outside the three is impossible — the CHECK constraint forbids it. The
 * only thing this converts is a deployment mistake, and it converts it from a
 * total outage into the feature being switched off.
 *
 * Invariant 1 is about failing closed on *authority* — missing identity, an
 * unreachable policy, an emergency lock. A missing column is a broken
 * deployment, and denying every request is not a safer answer to it.
 */
export function fingerprintModeOf(agent: { readonly fingerprint_mode?: unknown }): FingerprintMode {
  const mode = agent.fingerprint_mode;
  return mode === 'challenge' || mode === 'deny' ? mode : 'observe';
}

/**
 * Where this exact software stands with this agent — the §3.3 step 3 read.
 *
 * `null` means never seen before. That is a different fact from `seen`, which
 * means it has connected and nobody has decided about it yet, and the pipeline
 * treats both as not-pinned.
 *
 * One statement, by primary key. Step 3 calls it only when the agent's mode is
 * not `observe`, so a workspace that has not turned enforcement on never pays
 * for it.
 */
export async function fingerprintStanding(
  db: Db,
  workspaceId: string,
  agentId: string,
  fingerprint: string,
): Promise<FingerprintStatus | null> {
  const { rows } = await db.query<{ status: FingerprintStatus }>(
    `select status from agent_fingerprints
      where workspace_id = $1 and agent_id = $2 and fingerprint = $3`,
    [workspaceId, agentId, fingerprint],
  );
  return rows[0]?.status ?? null;
}

/**
 * An operator's verdict on one piece of software.
 *
 * Only ever applied to a fingerprint already on file: there is no way to pin
 * something that has never connected, because a pin for a digest nobody has
 * seen is a guess, and the digest is not a value an operator can be expected
 * to type correctly.
 *
 * Returns whether a row was changed, so a caller can answer 404 rather than
 * reporting success against nothing.
 */
export async function setFingerprintStatus(
  db: Db,
  input: {
    readonly workspaceId: string;
    readonly agentId: string;
    readonly fingerprint: string;
    readonly status: FingerprintStatus;
  },
): Promise<boolean> {
  const { rowCount } = await db.query(
    `update agent_fingerprints set status = $4
      where workspace_id = $1 and agent_id = $2 and fingerprint = $3`,
    [input.workspaceId, input.agentId, input.fingerprint, input.status],
  );
  return (rowCount ?? 0) > 0;
}

/**
 * Change an agent's enforcement mode.
 *
 * Deliberately does **not** pin anything on the way up. Turning enforcement on
 * is a statement about what happens next, not a bulk blessing of everything
 * already on file — trust on first use has already pinned the client that was
 * there first, and anything else arrived afterwards and is exactly what the
 * operator is turning this on to catch.
 */
export async function setFingerprintMode(
  db: Db,
  workspaceId: string,
  agentId: string,
  mode: FingerprintMode,
): Promise<boolean> {
  const { rowCount } = await db.query(
    `update agents set fingerprint_mode = $3 where workspace_id = $1 and id = $2`,
    [workspaceId, agentId, mode],
  );
  return (rowCount ?? 0) > 0;
}
