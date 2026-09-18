/**
 * Agent session index in Redis.
 *
 * Every key is prefixed with the workspace (invariant 4: cache keys are
 * tenant-scoped too, not just SQL). Sessions carry a TTL so an abandoned
 * session expires on its own; revocation removes them immediately, which is
 * what makes FR-08 effective within the §11 five-second target rather than at
 * the next natural expiry.
 */

import type Redis from 'ioredis';

const sessionKey = (workspaceId: string, sessionId: string): string =>
  `veto:${workspaceId}:session:${sessionId}`;

const agentIndexKey = (workspaceId: string, agentId: string): string =>
  `veto:${workspaceId}:agent:${agentId}:sessions`;

export async function recordSession(
  redis: Redis,
  workspaceId: string,
  agentId: string,
  sessionId: string,
  ttlSeconds: number,
): Promise<void> {
  await redis
    .multi()
    .set(sessionKey(workspaceId, sessionId), agentId, 'EX', ttlSeconds)
    .sadd(agentIndexKey(workspaceId, agentId), sessionId)
    .expire(agentIndexKey(workspaceId, agentId), ttlSeconds)
    .exec();
}

export async function liveSessionIds(
  redis: Redis,
  workspaceId: string,
  agentId: string,
): Promise<string[]> {
  const ids = await redis.smembers(agentIndexKey(workspaceId, agentId));
  const live: string[] = [];
  for (const id of ids) {
    if ((await redis.exists(sessionKey(workspaceId, id))) === 1) live.push(id);
  }
  return live.sort();
}

/** Drop every session belonging to one agent. Returns how many were removed. */
export async function dropAgentSessions(
  redis: Redis,
  workspaceId: string,
  agentId: string,
): Promise<number> {
  const index = agentIndexKey(workspaceId, agentId);
  const ids = await redis.smembers(index);
  const pipeline = redis.multi();
  for (const id of ids) pipeline.del(sessionKey(workspaceId, id));
  pipeline.del(index);
  await pipeline.exec();
  return ids.length;
}
