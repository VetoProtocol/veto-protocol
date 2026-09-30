/**
 * The folder walk writes parents concurrently.
 *
 * Those writes go to Permit's Cloud API, not the local PDP. Measured from a
 * deployed host one takes about 1.7 s, and they used to run one after another:
 * a 200-entry folder took six minutes, and the HTTP request died long before
 * the server stopped working. The operator saw "something went wrong talking to
 * the control plane" and nothing else.
 *
 * Wall-clock is not asserted here — a test that fails on a slow machine teaches
 * nobody anything. What is asserted is the property that makes it fast: more
 * than one write in flight, never more than the bound, and every entry still
 * written exactly once.
 */

import { describe, expect, it } from 'vitest';
import type { DriveEntry, DriveFile, DriveReader } from '@veto/connections';
import type { PolicyFacts } from '@veto/permit';
import {
  MAX_SYNC_ENTRIES,
  SYNC_RETRY_ATTEMPTS,
  SYNC_WRITE_CONCURRENCY,
  syncFolderHierarchy,
} from '../src/hierarchy.ts';

/** One folder holding `n` files. */
function flatDrive(n: number): DriveReader {
  const entries: DriveEntry[] = Array.from({ length: n }, (_, i) => ({
    id: `f${i}`,
    name: `f${i}.txt`,
    mimeType: 'text/plain',
    modifiedTime: null,
  }));
  return {
    async listFolder(_t, folderId): Promise<readonly DriveEntry[]> {
      return folderId === 'root' ? entries : [];
    },
    async readFile(): Promise<DriveFile> {
      throw new Error('a walk never reads a file');
    },
  };
}

/** Records how many writes were in flight, and every key written. */
function countingFacts() {
  let inFlight = 0;
  let peak = 0;
  const written: string[] = [];
  const facts = {
    async recordParent(input: { childKey: string }): Promise<void> {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      // Yield twice so overlapping work is actually observable rather than
      // each call resolving before the next begins.
      await Promise.resolve();
      await Promise.resolve();
      written.push(input.childKey);
      inFlight -= 1;
    },
  } as unknown as PolicyFacts;
  return { facts, written, peak: () => peak };
}

/** No real waiting: the backoff is exercised, not endured. */
const slept: number[] = [];
const run = (drive: DriveReader, facts: PolicyFacts) =>
  syncFolderHierarchy(
    {
      drive,
      facts,
      sleep: async (ms) => {
        slept.push(ms);
      },
    },
    { workspaceId: 'ws_conc', accessToken: 'token', folderId: 'root' },
  );

/** Permit's answer when the walk is going too fast. */
const rateLimited = () =>
  Object.assign(new Error('Permit is unavailable (recordParent)'), {
    cause: new Error('You have exceeded the rate limit for this resource. Please try again later.'),
  });

describe('the folder walk', () => {
  it('writes more than one parent at a time', async () => {
    const { facts, peak } = countingFacts();
    await run(flatDrive(40), facts);
    expect(peak()).toBeGreaterThan(1);
  });

  it('never exceeds the bound', async () => {
    const { facts, peak } = countingFacts();
    await run(flatDrive(60), facts);
    expect(peak()).toBeLessThanOrEqual(SYNC_WRITE_CONCURRENCY);
  });

  it('writes every entry exactly once', async () => {
    const { facts, written } = countingFacts();
    const report = await run(flatDrive(25), facts);

    expect(written).toHaveLength(25);
    expect(new Set(written).size).toBe(25);
    expect(report.links).toBe(25);
  });

  it('still stops at the entry bound, and says so', async () => {
    const { facts, written } = countingFacts();
    const report = await run(flatDrive(MAX_SYNC_ENTRIES + 50), facts);

    expect(report.truncated).toBe(true);
    expect(written.length).toBeLessThanOrEqual(MAX_SYNC_ENTRIES);
  });

  it('propagates a failed write rather than reporting links it did not make', async () => {
    const facts = {
      async recordParent(input: { childKey: string }): Promise<void> {
        if (input.childKey === 'f3') throw new Error('permit said no');
      },
    } as unknown as PolicyFacts;

    await expect(run(flatDrive(10), facts)).rejects.toThrow('permit said no');
  });
});

describe('when Permit asks the walk to slow down', () => {
  // Concurrency alone was not enough. Eight at a time exceeded Permit's rate
  // limit on a real folder and the whole walk failed — a worse outcome than
  // being slow. A lower number helps and does not fix it, because a large
  // enough folder meets a limit at any concurrency.

  it('retries a rate-limited write instead of failing the walk', async () => {
    slept.length = 0;
    let attempts = 0;
    const facts = {
      async recordParent(): Promise<void> {
        attempts += 1;
        if (attempts <= 2) throw rateLimited();
      },
    } as unknown as PolicyFacts;

    const report = await run(flatDrive(1), facts);
    expect(report.links).toBe(1);
    expect(attempts).toBe(3);
  });

  it('backs off further each time', async () => {
    slept.length = 0;
    let attempts = 0;
    const facts = {
      async recordParent(): Promise<void> {
        attempts += 1;
        if (attempts <= 2) throw rateLimited();
      },
    } as unknown as PolicyFacts;

    await run(flatDrive(1), facts);
    expect(slept).toHaveLength(2);
    expect(slept[1]).toBeGreaterThan(slept[0] ?? 0);
  });

  it('gives up rather than retrying forever', async () => {
    slept.length = 0;
    let attempts = 0;
    const facts = {
      async recordParent(): Promise<void> {
        attempts += 1;
        throw rateLimited();
      },
    } as unknown as PolicyFacts;

    await expect(run(flatDrive(1), facts)).rejects.toThrow();
    expect(attempts).toBe(SYNC_RETRY_ATTEMPTS);
  });

  it('does not retry a failure that is not a rate limit', async () => {
    slept.length = 0;
    let attempts = 0;
    const facts = {
      async recordParent(): Promise<void> {
        attempts += 1;
        throw new Error('the folder does not exist');
      },
    } as unknown as PolicyFacts;

    await expect(run(flatDrive(1), facts)).rejects.toThrow('does not exist');
    // Waiting would not have helped, so it did not wait.
    expect(attempts).toBe(1);
    expect(slept).toHaveLength(0);
  });
});
