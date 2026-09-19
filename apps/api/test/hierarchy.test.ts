/**
 * The folder walk (§4.2 containment), and the bounds that keep it a walk
 * rather than a crawl.
 *
 * This file needs no database and no Permit: the walk is a pure function of
 * what Drive returns and what it writes into `PolicyFacts`. The route that
 * calls it is tested separately, where the credential and tenant checks live.
 *
 * The properties worth holding:
 *
 *  * A file's parent comes from Drive, and a folder's contents reach any depth
 *    within the bound — that is the whole point of the change.
 *  * Every bound reports `truncated`. A walk that stopped early and said it
 *    finished would leave an operator believing a grant reaches files it does
 *    not, which is the failure mode this feature exists to remove.
 *  * A cycle terminates. Drive shortcuts can point at an ancestor.
 */

import { describe, expect, it } from 'vitest';
import { createFakePolicyFacts } from '@veto/permit';
import { FILE_RESOURCE, FOLDER_RESOURCE, parentFact } from '@veto/permit';
import type { DriveEntry, DriveReader } from '@veto/connections';
import { syncFolderHierarchy, MAX_SYNC_DEPTH, MAX_SYNC_ENTRIES } from '../src/hierarchy.ts';

const FOLDER_MIME = 'application/vnd.google-apps.folder';

const file = (id: string): DriveEntry => ({
  id,
  name: id,
  mimeType: 'text/plain',
  modifiedTime: null,
});

const folder = (id: string): DriveEntry => ({
  id,
  name: id,
  mimeType: FOLDER_MIME,
  modifiedTime: null,
});

/** A Drive described as a map from folder id to its contents. */
const driveOf = (tree: Record<string, readonly DriveEntry[]>): DriveReader & { calls: string[] } => {
  const calls: string[] = [];
  return {
    calls,
    async listFolder(_token, folderId): Promise<readonly DriveEntry[]> {
      calls.push(folderId);
      return tree[folderId] ?? [];
    },
    async readFile() {
      throw new Error('the walk never reads a file');
    },
  };
};

const WS = 'ws_hier';

describe('walking a folder', () => {
  it('records each file against the folder that holds it', async () => {
    const facts = createFakePolicyFacts();
    const drive = driveOf({ root: [file('f1'), file('f2')] });

    const report = await syncFolderHierarchy(
      { drive, facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    expect(report.links).toBe(2);
    expect(report.truncated).toBe(false);

    const held = await facts.factsFor(WS);
    expect(held).toContain(parentFact(FILE_RESOURCE, 'f1', 'root'));
    expect(held).toContain(parentFact(FILE_RESOURCE, 'f2', 'root'));
  });

  it('follows folders down, so a grant on the top reaches the bottom', async () => {
    const facts = createFakePolicyFacts();
    const drive = driveOf({
      root: [folder('sub')],
      sub: [file('deep')],
    });

    await syncFolderHierarchy(
      { drive, facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    const held = await facts.factsFor(WS);
    // The subfolder is a child of root, and the file is a child of it. Permit
    // derives the rest: reader(root) → reader(sub) → reader(deep).
    expect(held).toContain(parentFact(FOLDER_RESOURCE, 'sub', 'root'));
    expect(held).toContain(parentFact(FILE_RESOURCE, 'deep', 'sub'));
  });

  it('never claims a file is a parent of anything', async () => {
    const facts = createFakePolicyFacts();
    const drive = driveOf({ root: [file('f1')] });

    await syncFolderHierarchy(
      { drive, facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    // Access flows downward only. An edge pointing the other way would make
    // §12.1's "authorized for one file, asks for the whole folder" an allow.
    for (const fact of await facts.factsFor(WS)) {
      expect(fact.startsWith(`${FOLDER_RESOURCE}:root#`)).toBe(false);
    }
  });

  it('does not read any file', async () => {
    const facts = createFakePolicyFacts();
    const drive = driveOf({ root: [file('f1')] });

    // `readFile` throws in the fake. Containment is metadata; the walk has no
    // business opening anything.
    await expect(
      syncFolderHierarchy(
        { drive, facts },
        { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
      ),
    ).resolves.toBeDefined();
  });
});

describe('the bounds', () => {
  it('stops at the depth limit and says so', async () => {
    const facts = createFakePolicyFacts();

    // One folder per level, deeper than the limit.
    const tree: Record<string, readonly DriveEntry[]> = {};
    let here = 'root';
    for (let level = 0; level < MAX_SYNC_DEPTH + 2; level += 1) {
      const below = `d${level}`;
      tree[here] = [folder(below)];
      here = below;
    }

    const report = await syncFolderHierarchy(
      { drive: driveOf(tree), facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    expect(report.truncated).toBe(true);
    // Reported, not silently accepted: the operator can see the grant does not
    // yet reach the bottom instead of meeting it later as a denial.
    expect(report.folders).toBeLessThanOrEqual(MAX_SYNC_DEPTH);
  });

  it('stops at the entry limit and says so', async () => {
    const facts = createFakePolicyFacts();
    const many = Array.from({ length: 60 }, (_, i) => folder(`b${i}`));
    const tree: Record<string, readonly DriveEntry[]> = { root: many };
    for (const entry of many) tree[entry.id] = Array.from({ length: 60 }, (_, i) => file(`${entry.id}-${i}`));

    const report = await syncFolderHierarchy(
      { drive: driveOf(tree), facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    expect(report.truncated).toBe(true);
    expect(report.links).toBeLessThanOrEqual(MAX_SYNC_ENTRIES);
  });

  it('terminates on a cycle', async () => {
    const facts = createFakePolicyFacts();
    // A shortcut pointing back at an ancestor. Without the visited set this
    // walk does not return.
    const drive = driveOf({
      root: [folder('a')],
      a: [folder('root')],
    });

    const report = await syncFolderHierarchy(
      { drive, facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    expect(report.folders).toBeLessThan(5);
    expect(drive.calls.filter((id) => id === 'root')).toHaveLength(1);
  });

  it('flags a full page, because Drive may have had more', async () => {
    const facts = createFakePolicyFacts();
    const full = Array.from({ length: 100 }, (_, i) => file(`f${i}`));

    const report = await syncFolderHierarchy(
      { drive: driveOf({ root: full }), facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    // `listFolder` takes no page token, so a full page is indistinguishable
    // from a folder that happens to hold exactly that many. Reported rather
    // than assumed to be the whole folder.
    expect(report.truncated).toBe(true);
  });
});

describe('what a walk is not', () => {
  it('writes containment, never a grant', async () => {
    const facts = createFakePolicyFacts();

    await syncFolderHierarchy(
      { drive: driveOf({ root: [file('f1')] }), facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    // An edge under a folder nobody was granted reaches nobody. This is what
    // makes the walk safe to run on its own: no role assignment appears.
    expect(await facts.listGrants(WS)).toHaveLength(0);
  });

  it('is scoped to one workspace', async () => {
    const facts = createFakePolicyFacts();

    await syncFolderHierarchy(
      { drive: driveOf({ root: [file('f1')] }), facts },
      { workspaceId: WS, accessToken: 'ya29.fake', folderId: 'root' },
    );

    expect(await facts.factsFor('ws_other')).toHaveLength(0);
  });
});
