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
const forms = path.join(here, '..', 'src/app/policies/forms.tsx');

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

describe('the policy and grant forms offer every grantable type', () => {
  /** Every `resource_type` option value the forms actually render. */
  function offered(): Set<string> {
    const source = readFileSync(forms, 'utf8');
    // `<select name="resource_type"`, not merely `name="resource_type"`. A
    // hidden input carries that name too, and splitting on the bare attribute
    // treated it as a dropdown — scooping up every `<option>` that happened to
    // appear later in the file, from an unrelated form, until the next
    // `</select>`. It passed for as long as nothing followed it, and failed
    // the first time somebody added a select below. The thing being searched
    // for is a dropdown, so say so.
    const selects = source.split('<select name="resource_type"').slice(1);
    const values = new Set<string>();
    for (const block of selects) {
      // Stop at the closing tag so a later select's options are not counted
      // against this one; every option before it belongs to this dropdown.
      const until = block.indexOf('</select>');
      for (const m of (until < 0 ? block : block.slice(0, until)).matchAll(
        /<option value="([^"]+)"/g,
      )) {
        if (m[1] !== undefined) values.add(m[1]);
      }
    }
    return values;
  }

  it('lets an operator name every type the API would accept', () => {
    // A type the API accepts but no dropdown offers is a feature that exists
    // and cannot be reached. GitHub shipped that way: the engine decided,
    // Permit knew the resource, and there was no option to select it — so the
    // only answer an agent ever got was deny-by-default, which looks exactly
    // like the system working correctly.
    const options = offered();
    for (const type of grantableTypes()) {
      expect(options.has(type), `no dropdown offers ${type}`).toBe(true);
    }
  });

  it('offers nothing the API would refuse', () => {
    const grantable = new Set(grantableTypes());
    for (const value of offered()) {
      expect(grantable.has(value), `${value} is offered but not grantable`).toBe(true);
    }
  });
});
