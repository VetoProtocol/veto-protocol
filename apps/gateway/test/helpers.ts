import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Redis from 'ioredis';
import type { Pool } from 'pg';
import { createPool } from '@veto/db';
import { mintCapability } from '@veto/tokens';
import { GATEWAY_AUDIENCE, GATEWAY_SCOPE } from '../src/session.ts';

const here = path.dirname(fileURLToPath(import.meta.url));

export const SECRET = 'g'.repeat(48);

function loadEnv(): void {
  const runnerEnv = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* already present */
  }
  if (runnerEnv !== undefined) process.env['NODE_ENV'] = runnerEnv;
}

export function testPool(): Pool {
  loadEnv();
  return createPool(process.env['DATABASE_URL'] ?? '');
}

export function testRedis(): Redis {
  loadEnv();
  return new Redis(process.env['REDIS_URL'] ?? 'redis://localhost:6379');
}

export const suffix = (): string => Math.random().toString(36).slice(2, 10);

export async function seedAgent(
  pool: Pool,
  ws: string,
  user: string,
  agent: string,
  clientId: string,
  status: 'active' | 'suspended' | 'revoked' = 'active',
): Promise<void> {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
    await c.query(
      `insert into workspaces (id, name, type) values ($1,$1,'organization') on conflict do nothing`,
      [ws],
    );
    await c.query(
      `insert into users (id, workspace_id, identity_subject) values ($1,$2,$3) on conflict do nothing`,
      [user, ws, `oidc|${user}`],
    );
    await c.query(
      `insert into agents (id, workspace_id, provider, client_id, owner_user_id, status, revoked_at)
       values ($1,$2,'mcp',$3,$4,$5,$6)`,
      [agent, ws, clientId, user, status, status === 'revoked' ? new Date() : null],
    );
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

export function gatewayToken(
  ws: string,
  human: string,
  agent: string | null,
  over: { aud?: string; action?: string; ttlMs?: number } = {},
): string {
  return mintCapability(SECRET, {
    aud: over.aud ?? GATEWAY_AUDIENCE,
    workspaceId: ws,
    humanId: human,
    agentId: agent,
    action: over.action ?? GATEWAY_SCOPE,
    resource: 'mcp',
    ttlMs: over.ttlMs ?? 60_000,
  });
}

export const rpc = (method: string, params: Record<string, unknown> = {}, id: unknown = 1) => ({
  jsonrpc: '2.0',
  id,
  method,
  params,
});
