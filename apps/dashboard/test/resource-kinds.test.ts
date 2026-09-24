/**
 * Every grantable resource type must have a name on screen.
 *
 * The grant form offered `gmail_mailbox`, the API stored `gmail_mailbox`, and
 * two separate places in the dashboard then described it as a **file** —
 * because both asked `=== 'google_folder' ? 'folder' : 'file'` and a mailbox is
 * neither. The row was right and the screen was wrong, which is the worse way
 * round: nothing failed, so there was nothing to go looking for.
 *
 * `RESOURCE_KINDS` is a hand-kept copy of `GRANTABLE` for the same reason the
 * connect route keeps its own service list — the dashboard cannot import from
 * the API or from `@veto/permit`. So the copy is compared with the original
 * here, read from source, the way `connect-services.test.ts` does it.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { RESOURCE_KINDS, kindLabel, kindReach } from '../src/app/policies/resource-kinds.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const grantsRoute = path.join(here, '../../..', 'apps/api/src/routes/grants.ts');
const model = path.join(here, '../../..', 'packages/permit/src/model.ts');

/** The resource types the API will actually accept in a grant. */
function grantableTypes(): string[] {
  const route = readFileSync(grantsRoute, 'utf8');
  const names = /const GRANTABLE = \[([^\]]*)\]/.exec(route)?.[1];
  if (!names) throw new Error('could not find GRANTABLE in the grants route');

  // GRANTABLE holds constants, not literals — resolve each from model.ts.
  const source = readFileSync(model, 'utf8');
  return names
    .split(',')
    .map((n) => n.trim())
    .filter(Boolean)
    .map((constant) => {
      const value = new RegExp(`${constant}\\s*=\\s*'([^']+)'`).exec(source)?.[1];
      if (!value) throw new Error(`could not resolve ${constant} in model.ts`);
      return value;
    })
    .sort();
}

describe('grantable resource kinds', () => {
  it('finds the API list, so this test cannot silently pass on nothing', () => {
    expect(grantableTypes().length).toBeGreaterThan(0);
  });

  it('names every type the API accepts', () => {
    expect(Object.keys(RESOURCE_KINDS).sort()).toEqual(grantableTypes());
  });

  it('never calls a mailbox or a calendar a file', () => {
    expect(kindLabel('gmail_mailbox')).toBe('mailbox');
    expect(kindLabel('google_calendar')).toBe('calendar');
    expect(kindReach('gmail_mailbox')).toBe('that mailbox');
    expect(kindReach('google_calendar')).toBe('that calendar');
  });

  it('shows an unknown type as itself rather than guessing', () => {
    expect(kindLabel('something_new')).toBe('something_new');
  });
});
