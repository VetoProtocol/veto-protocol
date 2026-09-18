/** `pnpm --filter @veto/db migrate` */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRepoEnv } from './env.ts';
import { createPool } from './client.ts';
import { migrate } from './migrate.ts';

loadRepoEnv();

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const pool = createPool(process.env['DATABASE_URL'] ?? '');

try {
  const { applied, skipped } = await migrate(pool, dir);
  console.error(`applied: ${applied.length ? applied.join(', ') : '(none)'}`);
  console.error(`already current: ${skipped.length}`);
} finally {
  await pool.end();
}
