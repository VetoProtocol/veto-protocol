import { migrate } from '../src/migrate.ts';
import { MIGRATIONS_DIR, testPool } from './helpers.ts';

export default async function setup(): Promise<void> {
  const pool = testPool();
  try {
    await migrate(pool, MIGRATIONS_DIR);
  } finally {
    await pool.end();
  }
}
