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

export interface HierarchyDeps {
  readonly drive: DriveReader;
  readonly facts: PolicyFacts;
}

export interface HierarchyInput {
  readonly workspaceId: string;
  /** Narrow, short-lived, and Drive-only. Minted by the caller. */
  readonly accessToken: string;
  /** The folder to walk. `root` is Drive's own name for the top. */
  readonly folderId: string;
}

export interface HierarchyReport {
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
  let examined = 0;
  let truncated = false;

  while (queue.length > 0) {
    const next: Array<{ id: string; depth: number }> = [];

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

        await deps.facts.recordParent({
          workspaceId: input.workspaceId,
          childType: isFolder ? FOLDER_RESOURCE : FILE_RESOURCE,
          childKey: entry.id,
          parentKey: folder.id,
        });
        links += 1;

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

    if (examined >= MAX_SYNC_ENTRIES) {
      truncated = true;
      break;
    }
    queue = next;
  }

  return { folders, links, truncated };
}
