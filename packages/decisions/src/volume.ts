/**
 * Cumulative volume limits (§4.2 `maximum_volume`, §7.1, T13).
 *
 * **This is an authorization control, not a rate limit**, and the difference is
 * the point of the §12.1 "blocked bulk request split into many small ones"
 * scenario. A rate limit protects the service and throttles; exceeding this
 * *denies*. They are separate code paths with separate failure behaviour, and
 * collapsing them would turn an authorization boundary into a speed bump an
 * attacker waits out.
 *
 * Redis rather than Postgres: the counter is read and written on every
 * protected request, and it has to be shared across gateway processes — a
 * per-process count is not a limit at all.
 *
 * Only *allowed* actions consume budget. A denied request that spent quota
 * would let anyone exhaust a victim's daily allowance by making requests they
 * knew would fail.
 */

import type Redis from 'ioredis';

const DAY_SECONDS = 60 * 60 * 24;

/** Tenant-scoped, as every cache key must be (invariant 4). */
export const volumeKey = (workspaceId: string, agentId: string, action: string, day: string): string =>
  `veto:${workspaceId}:vol:${agentId}:${action}:${day}`;

export const utcDay = (now: Date = new Date()): string => now.toISOString().slice(0, 10);

export async function currentUsage(
  redis: Redis,
  workspaceId: string,
  agentId: string,
  action: string,
  now?: Date,
): Promise<number> {
  const raw = await redis.get(volumeKey(workspaceId, agentId, action, utcDay(now)));
  return raw === null ? 0 : Number(raw);
}

/**
 * Take one unit of budget, atomically.
 *
 * Returns whether the reservation fits. INCR then compare — not "read, decide,
 * write" — because concurrent requests at the boundary must not all observe the
 * same pre-increment count and all be allowed. When it does not fit the unit is
 * given back, so a refused request leaves the budget as it found it.
 */
export async function reserve(
  redis: Redis,
  workspaceId: string,
  agentId: string,
  action: string,
  limit: number,
  now?: Date,
): Promise<boolean> {
  const key = volumeKey(workspaceId, agentId, action, utcDay(now));
  const used = await redis.incr(key);

  // Set the expiry on first use. A key without one is a limit that never resets.
  if (used === 1) await redis.expire(key, DAY_SECONDS);

  if (used > limit) {
    await redis.decr(key);
    return false;
  }
  return true;
}
