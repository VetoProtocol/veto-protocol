/**
 * Teaching Permit where Drive files live (spec §4.2, §4.4).
 *
 * ## The gap this closes
 *
 * Permit's `reader` role on a folder derives `reader` on everything inside it,
 * through the `parent` relation. That derivation is declared in the environment
 * bootstrap and has always been correct — but nothing ever wrote a `parent`
 * tuple, so it derived across an empty graph. Granting a folder produced an
 * allow for the folder and a deny for every file in it, which reads as a
 * working grant right until somebody opens a file.
 *
 * ## Why the hierarchy is fetched and never asserted
 *
 * The parent of a file is a fact about Drive. It is read here from Drive, over
 * a credential the workspace already holds, and never taken from a tool
 * argument or a tool response. An agent that could state "this file's parent is
 * the folder you granted me" would be able to read any file in Drive by saying
 * so — privilege escalation by argument, the same shape invariant 10 refuses
 * for credentials and the injection rule refuses for retrieved content.
 *
 * ## Why this is not on the decision path
 *
 * The pipeline decides and never fetches (§3.3). A walk of Drive inside step 5
 * would blow the §11 200 ms budget and make an authorization check depend on an
 * upstream being up. This runs in the control plane, before any decision, and
 * what it writes is a fact about where things are — not a grant. An edge under
 * a folder nobody was granted reaches nobody.
 *
 * ## What it is bounded by, and why that is not a formality
 *
 * A Drive can be arbitrarily large and can contain cycles, because a shortcut
 * may point at an ancestor. All three bounds below are load-bearing: without
 * them this is an unbounded upstream walk kicked off by one HTTP request.
 */

import type { DriveEntry, DriveReader } from '@veto/connections';
import { FILE_RESOURCE, FOLDER_RESOURCE, type PolicyFacts } from '@veto/permit';

/** Google's own marker for a folder. Everything else is a file. */
const FOLDER_MIME = 'application/vnd.google-apps.folder';

/**
 * How far down to walk.
 *
 * Three levels covers the shape real Drives have without turning one request
 * into a crawl of everything. A deeper tree is not refused — it is reported as
 * truncated, so the operator knows the grant does not yet reach the bottom
 * rather than discovering it as a denial later.
 */
export const MAX_SYNC_DEPTH = 3;

/** Total entries examined, across every folder, before the walk stops. */
export const MAX_SYNC_ENTRIES = 500;

/** Children requested per folder. `listFolder` clamps to 100 of its own accord. */
const PAGE_SIZE = 100;

/**
 * How many parent writes are in flight at once.
 *
 * The walk reads from Drive and writes to Permit's **Cloud API** — not the
 * local PDP, which only answers decisions. Measured from a deployed host, one
 * such write takes about 1.7 s, and the writes were sequential: a 200-entry
 * folder took six minutes and a 500-entry one would have taken fourteen. No
 * browser, proxy or fetch survives that, so the request died while the server
 * was still working and the operator saw only that something went wrong.
 *
 * Eight at a time, which is the difference between minutes and seconds. Kept
 * modest on purpose: this is somebody else's rate limit, and a sync that
 * finishes in a minute is worth more than one that finishes in twenty seconds
 * and sometimes gets throttled instead.
 */
export const SYNC_WRITE_CONCURRENCY = 4;

/** How many times a rate-limited write is retried before the walk gives up. */
export const SYNC_RETRY_ATTEMPTS = 5;

/** First backoff. Doubles each attempt, with jitter, so retries spread out. */
const RETRY_BASE_MS = 750;

/**
 * Did Permit refuse this because we are going too fast?
 *
 * Worth telling apart from every other failure. A rate limit is temporary and
 * the right response is to wait; anything else is a reason to stop, and
 * retrying it would just be slower.
 *
 * Walks the `cause` chain because the adapter wraps upstream errors in
 * `PolicyUnavailableError` — the status lives underneath. Status first, message
 * second: a number is a contract and a sentence is not, but this SDK does not
 * always surface one.
 */
function isRateLimited(error: unknown): boolean {
  const seen = new Set<unknown>();
  let cursor: unknown = error;
  while (cursor !== null && cursor !== undefined && typeof cursor === 'object' && !seen.has(cursor)) {
    seen.add(cursor);
    const e = cursor as {
      status?: unknown;
      statusCode?: unknown;
      message?: unknown;
      cause?: unknown;
    };
    if (e.status === 429 || e.statusCode === 429) return true;
    if (typeof e.message === 'string' && /rate limit|too many requests/i.test(e.message)) {
      return true;
    }
    cursor = e.cause;
  }
  return false;
}

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * One write, retried while Permit is asking us to slow down.
 *
 * Concurrency alone was not enough: eight at a time exceeded Permit's rate
 * limit and the whole walk failed, which is a worse outcome than being slow.
 * Lowering the number helps and does not fix it — a large enough folder meets a
 * limit at any concurrency — so the limit is handled rather than avoided.
 *
 * Jittered, because four workers backing off in lockstep would arrive together
 * and be refused together.
 */
async function writeWithRetry(
  attempt: () => Promise<void>,
  sleep: (ms: number) => Promise<void>,
): Promise<void> {
  for (let tries = 0; ; tries += 1) {
    try {
      await attempt();
      return;
    } catch (error) {
      if (tries >= SYNC_RETRY_ATTEMPTS - 1 || !isRateLimited(error)) throw error;
      const backoff = RETRY_BASE_MS * 2 ** tries;
      await sleep(backoff + Math.floor(Math.random() * RETRY_BASE_MS));
    }
  }
}

/**
 * Run tasks with at most `limit` in flight.
 *
 * A rejection propagates, exactly as an awaited call in the loop used to: a
 * parent link that cannot be written is a hierarchy that does not reach where
 * the caller will be told it reaches.
 */
async function runBounded(tasks: ReadonlyArray<() => Promise<void>>, limit: number): Promise<void> {
  let cursor = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const task = tasks[cursor];
      cursor += 1;
      if (task === undefined) return;
      await task();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
}

export interface HierarchyDeps {
  readonly drive: DriveReader;
  readonly facts: PolicyFacts;
  /** Overridable so a test can exercise the backoff without waiting for it. */
  readonly sleep?: (ms: number) => Promise<void>;
  /**
   * Edges Permit has already been told about, as `edgeKey` strings.
   *
   * A second walk of the same Drive otherwise re-states everything: on a real
   * deployment 648 of 676 upstream calls were duplicates, and the rate budget
   * they spent is why the remaining 28 were refused. Skipping them is what
   * makes a repeat walk cheap enough to be worth running.
   */
  readonly known?: ReadonlySet<string>;
  /** Called for each edge actually written, so the caller can remember it. */
  readonly onWritten?: (childType: string, childKey: string, parentKey: string) => void;
}

/** How an edge is named in `known`. One shape, one place. */
export const edgeKey = (childType: string, childKey: string, parentKey: string): string =>
  `${childType}|${childKey}|${parentKey}`;

export interface HierarchyInput {
  readonly workspaceId: string;
  /** Narrow, short-lived, and Drive-only. Minted by the caller. */
  readonly accessToken: string;
  /** The folder to walk. `root` is Drive's own name for the top. */
  readonly folderId: string;
}

export interface HierarchyReport {
  /** Edges Permit already had, so no call was made. */
  readonly skipped: number;
  /** Folders whose contents were listed. */
  readonly folders: number;
  /** Containment edges written. Idempotent, so a re-run reports the same number. */
  readonly links: number;
  /** True when a bound stopped the walk before it ran out of Drive. */
  readonly truncated: boolean;
}

/**
 * Walk a folder and record where everything inside it lives.
 *
 * Breadth-first, so the shallow levels — the ones a grant most likely meant —
 * are recorded first if a bound cuts the walk short.
 */
export async function syncFolderHierarchy(
  deps: HierarchyDeps,
  input: HierarchyInput,
): Promise<HierarchyReport> {
  // Guards against a shortcut pointing at an ancestor. Without it a cycle is an
  // infinite walk, and the entry cap would be the only thing that stopped it.
  const seen = new Set<string>([input.folderId]);

  let queue: Array<{ id: string; depth: number }> = [{ id: input.folderId, depth: 0 }];
  let folders = 0;
  let links = 0;
  let skipped = 0;
  let examined = 0;
  let truncated = false;

  while (queue.length > 0) {
    const next: Array<{ id: string; depth: number }> = [];
    // Collected while walking this level, then run together. The walk itself
    // stays sequential and its bounds are unchanged — only the waiting is
    // shared out.
    const writes: Array<() => Promise<void>> = [];

    for (const folder of queue) {
      if (examined >= MAX_SYNC_ENTRIES) {
        truncated = true;
        break;
      }

      const entries: readonly DriveEntry[] = await deps.drive.listFolder(
        input.accessToken,
        folder.id,
        PAGE_SIZE,
      );
      folders += 1;

      // A full page means Drive may have had more to give. `listFolder` takes
      // no page token, so this is reported rather than silently accepted as
      // the whole folder.
      if (entries.length >= PAGE_SIZE) truncated = true;

      for (const entry of entries) {
        if (entry.id === '') continue;
        if (examined >= MAX_SYNC_ENTRIES) {
          truncated = true;
          break;
        }
        examined += 1;

        const isFolder = entry.mimeType === FOLDER_MIME;

        const childType = isFolder ? FOLDER_RESOURCE : FILE_RESOURCE;
        const childKey = entry.id;
        const parentKey = folder.id;

        // Already sent. The walk still descends through it — where a file sits
        // has not changed — it simply does not say so again.
        if (deps.known?.has(edgeKey(childType, childKey, parentKey))) {
          skipped += 1;
        } else {
        writes.push(async () => {
          await writeWithRetry(
            () =>
              deps.facts.recordParent({
                workspaceId: input.workspaceId,
                childType,
                childKey,
                parentKey,
              }),
            deps.sleep ?? wait,
          );
          // Counted on success, so a reported link is one that exists.
          links += 1;
          deps.onWritten?.(childType, childKey, parentKey);
        });
        }

        if (!isFolder) continue;
        if (folder.depth + 1 >= MAX_SYNC_DEPTH) {
          // The folder itself is recorded — a grant reaches it — but its
          // contents are not walked. Saying so is the difference between a
          // bound and a bug.
          truncated = true;
          continue;
        }
        if (seen.has(entry.id)) continue;
        seen.add(entry.id);
        next.push({ id: entry.id, depth: folder.depth + 1 });
      }
    }

    // Every parent this level found, written before descending — so a failure
    // stops the walk rather than leaving a deeper level recorded above a
    // shallower one that is not.
    await runBounded(writes, SYNC_WRITE_CONCURRENCY);

    if (examined >= MAX_SYNC_ENTRIES) {
      truncated = true;
      break;
    }
    queue = next;
  }

  return { folders, links, skipped, truncated };
}
