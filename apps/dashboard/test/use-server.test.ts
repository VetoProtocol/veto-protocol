/**
 * Every `'use server'` module may export only async functions.
 *
 * Next turns each export of such a module into a callable server endpoint, so a
 * plain object has no meaning there and the module is refused **when it is
 * required** — not when it is built. A constant exported beside the actions
 * therefore compiled, built, and passed every existing test, then took the page
 * down on first render with nothing but a digest to go on.
 *
 * This is the check `next build` does not do.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const src = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return walk(full);
    return /\.tsx?$/.test(full) ? [full] : [];
  });
}

const serverModules = walk(src).filter((file) =>
  /^\s*['"]use server['"]/.test(readFileSync(file, 'utf8')),
);

describe("'use server' modules", () => {
  it('finds the action modules, so this test cannot silently pass on nothing', () => {
    expect(serverModules.length).toBeGreaterThan(0);
  });

  it.each(serverModules)('%s exports only async functions', async (file) => {
    const loaded: Record<string, unknown> = await import(file);

    for (const [name, value] of Object.entries(loaded)) {
      expect(typeof value, `${name} must be a function`).toBe('function');
      expect(
        (value as { constructor: { name: string } }).constructor.name,
        `${name} must be async`,
      ).toBe('AsyncFunction');
    }
  });
});
