/**
 * `pnpm --filter @veto/db plan -- --workspace ws_abc --plan pro`
 *
 * Sets a workspace's tier. There is no billing behind this and none is implied:
 * `plan` is a flag an operator sets, and this is the operator's hand.
 *
 * It prints the previous value as well as the new one, because the common
 * mistake with a command like this is running it against the wrong workspace
 * and not noticing. Seeing `free -> pro` on a workspace you did not mean to
 * touch is the only warning you get.
 *
 * Listing is what it does with no `--plan`, so finding the id is part of the
 * same tool rather than a psql incantation somebody keeps in a note.
 */

import { createPool, loadRepoEnv, withWorkspace } from './index.ts';

loadRepoEnv();

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

const PLANS = new Set(['free', 'pro']);

const workspaceId = flag('workspace');
const plan = flag('plan');

if (plan !== undefined && !PLANS.has(plan)) {
  console.error(`plan must be one of: ${[...PLANS].join(', ')}`);
  process.exit(2);
}

if (plan !== undefined && workspaceId === undefined) {
  console.error('usage: plan --workspace ws_... --plan pro|free');
  console.error('       plan                      # list every workspace and its tier');
  process.exit(2);
}

const pool = createPool(process.env['DATABASE_URL'] ?? '');

try {
  // Listing crosses tenants on purpose: an operator setting tiers works above
  // the workspace boundary by definition, and this runs from a shell on the
  // server rather than from a request. It reads ids, names and plans — never
  // anything a workspace owns.
  if (plan === undefined) {
    const { rows } = await pool.query<{ id: string; name: string; plan: string }>(
      `select id, name, plan from workspaces order by created_at asc`,
    );

    if (rows.length === 0) {
      console.error('no workspaces');
    } else {
      for (const row of rows) {
        // stderr, like `invite`: these CLIs report to an operator watching,
        // not to a pipe.
        console.error(`${row.plan.padEnd(4)}  ${row.id.padEnd(24)}  ${row.name}`);
      }
    }
  } else {
    const target = workspaceId as string;

    // Checked before the update, so a typo reports "no such workspace" rather
    // than succeeding against zero rows and printing nothing useful.
    const current = await withWorkspace(pool, target, (db) =>
      db.query<{ name: string; plan: string }>(`select name, plan from workspaces where id = $1`, [
        target,
      ]),
    );

    const before = current.rows[0];
    if (!before) {
      console.error(`no such workspace: ${target}`);
      process.exitCode = 1;
    } else if (before.plan === plan) {
      console.error(`${target} (${before.name}) is already ${plan}`);
    } else {
      await withWorkspace(pool, target, (db) =>
        db.query(`update workspaces set plan = $2 where id = $1`, [target, plan]),
      );

      console.error(`${target} (${before.name})`);
      console.error(`${before.plan} -> ${plan}`);
      console.error('Takes effect on the next request; nobody needs to sign in again.');
    }
  }
} finally {
  await pool.end();
}
