import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Redis from 'ioredis';
import type { Pool } from 'pg';
import { createPool, withWorkspace } from '@veto/db';
import type { EvaluateInput } from '../src/types.ts';

const here = path.dirname(fileURLToPath(import.meta.url));

function env(): void {
  const runner = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* already present */
  }
  if (runner !== undefined) process.env['NODE_ENV'] = runner;
}

export function testPool(): Pool {
  env();
  return createPool(process.env['DATABASE_URL'] ?? '');
}

export function testRedis(): Redis {
  env();
  return new Redis(process.env['REDIS_URL'] ?? 'redis://localhost:6379');
}

export const suffix = (): string => Math.random().toString(36).slice(2, 10);

export async function seed(
  pool: Pool,
  ws: string,
  user: string,
  agent: string,
): Promise<void> {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
    await c.query(`insert into workspaces (id,name,type) values ($1,$1,'organization')`, [ws]);
    await c.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3)`, [
      user, ws, `oidc|${user}`,
    ]);
    await c.query(
      `insert into agents (id,workspace_id,provider,client_id,owner_user_id) values ($1,$2,'mcp',$3,$4)`,
      [agent, ws, `client-${suffix()}`, user],
    );
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

export async function addPolicy(
  pool: Pool,
  ws: string,
  rule: {
    subject: string;
    action: string;
    effect: 'allow' | 'deny' | 'challenge';
    resourceFilter?: Record<string, unknown>;
    conditions?: Record<string, unknown>;
    version?: string;
  },
): Promise<void> {
  await withWorkspace(pool, ws, (db) =>
    db.query(
      `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        `pol_${suffix()}${suffix()}`,
        ws,
        rule.subject,
        rule.action,
        JSON.stringify(rule.resourceFilter ?? {}),
        JSON.stringify(rule.conditions ?? {}),
        rule.effect,
        rule.version ?? 'polv_1',
      ],
    ),
  );
}

export async function setPresence(pool: Pool, ws: string, user: string, state: string): Promise<void> {
  await withWorkspace(pool, ws, (db) =>
    db.query(
      `insert into presence (workspace_id,user_id,state,source) values ($1,$2,$3,'test')
       on conflict (workspace_id,user_id) do update set state = excluded.state`,
      [ws, user, state],
    ),
  );
}

export async function setLock(pool: Pool, ws: string, locked: boolean): Promise<void> {
  await withWorkspace(pool, ws, (db) =>
    db.query(
      `update workspaces set emergency_lock=$2, locked_at = case when $2 then now() else null end
        where id=$1`,
      [ws, locked],
    ),
  );
}

export const request = (over: Partial<EvaluateInput> & Pick<EvaluateInput,
  'workspaceId' | 'humanId' | 'agentId'>): EvaluateInput => ({
  requestId: `req_${suffix()}`,
  clientId: 'claude-desktop',
  tool: 'google_drive.read_file',
  action: 'read',
  resource: { type: 'google_file', id: '/Work/report.md' },
  arguments: { fields: ['name'] },
  declaredIntent: 'Summarize the weekly report',
  destination: null,
  occurredAt: new Date().toISOString(),
  ...over,
});
