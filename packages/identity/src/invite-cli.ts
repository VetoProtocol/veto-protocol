/**
 * `pnpm --filter @veto/identity invite -- --subject "oidc|1078..." --workspace "Acme"`
 *
 * Prints the ids it created. Run it with the subject from the failed sign-in
 * log line; see docs/auth-setup.md.
 */

import { newId } from '@veto/core';
import { createPool, loadRepoEnv, withWorkspace } from '@veto/db';
import { inviteSubject } from './invite.ts';

loadRepoEnv();

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

const subject = flag('subject');
const workspaceName = flag('workspace') ?? 'My workspace';
const workspaceId = flag('workspace-id') ?? newId('ws_');

if (!subject) {
  console.error('usage: invite --subject "oidc|<sub>" [--workspace "Name"] [--workspace-id ws_...]');
  process.exit(2);
}

const pool = createPool(process.env['DATABASE_URL'] ?? '');

try {
  const result = await withWorkspace(pool, workspaceId, (db) =>
    inviteSubject(db, { workspaceId, workspaceName, subject }),
  );

  console.error(`workspace ${result.workspaceId}${result.workspaceCreated ? ' (created)' : ' (existing)'}`);
  console.error(`user      ${result.userId}${result.created ? ' (created)' : ' (already a member)'}`);
  console.error(`subject   ${subject}`);
} finally {
  await pool.end();
}
