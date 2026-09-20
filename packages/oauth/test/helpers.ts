import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Pool } from 'pg';
import { createPool } from '@veto/db';

const here = path.dirname(fileURLToPath(import.meta.url));

export function testPool(): Pool {
  const runnerEnv = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* already in the environment */
  }
  if (runnerEnv !== undefined) process.env['NODE_ENV'] = runnerEnv;
  return createPool(process.env['DATABASE_URL'] ?? '');
}

export const suffix = (): string => Math.random().toString(36).slice(2, 10);
