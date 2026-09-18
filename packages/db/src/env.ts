/**
 * Load the repo-root `.env` for command-line entry points (the migration CLI).
 *
 * Servers get their environment from the process manager, but a CLI run by hand
 * has only the shell. Without this, `pnpm --filter @veto/permit bootstrap` fails
 * on a missing key even though the key is sitting in `.env`.
 *
 * Precedence: **an explicitly set variable always wins over the file.**
 * `process.loadEnvFile` overwrites what is already in `process.env`, which is
 * the wrong way round and has bitten this repo before — the app `.env` sets
 * NODE_ENV=development and silently clobbered vitest's NODE_ENV=test, disabling
 * the test-only guard in the Permit fake. So the pre-existing environment is
 * snapshotted and restored, leaving the file to fill in only what is missing.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function loadRepoEnv(): void {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const envFile = path.join(here, '..', '..', '..', '.env');

  const before = { ...process.env };
  try {
    process.loadEnvFile(envFile);
  } catch {
    return; // No .env; the shell is the only source.
  }

  for (const [key, value] of Object.entries(before)) {
    if (value !== undefined) process.env[key] = value;
  }
}
