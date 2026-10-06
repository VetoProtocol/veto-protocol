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
 * It cannot list workspaces, and deliberately does not try. RLS is `FORCE`d and
 * `withoutTenant` does not bypass it — with no tenant set, tenant tables read
 * empty. Listing would need a third `security definer` cross-tenant read, and
 * the second one already brings the threat model back for review. A convenience
 * listing is not worth that trade.
 *
 * The workspace id is on every dashboard screen, in the path line at the top
 * (`~/ws_.../policies`), and on every audit and decision row.
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

if (workspaceId === undefined || plan === undefined) {
  console.error('usage: plan --workspace ws_... --plan pro|free');
  console.error('');
  console.error('The workspace id is shown at the top of every dashboard screen.');
  process.exit(2);
}

const pool = createPool(process.env['DATABASE_URL'] ?? '');

const target = workspaceId;

try {
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
} finally {
  await pool.end();
}
