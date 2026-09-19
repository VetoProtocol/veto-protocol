/**
 * Sensitivity labels (spec §4.2 `sensitivity`).
 *
 * A label says how protected a resource is. It is attached to the resource, so
 * marking `/Finance` confidential once covers every rule that can reach it —
 * rather than every rule having to remember to carry a presence condition, with
 * a gap wherever one forgot.
 *
 * ## A label can only narrow
 *
 * This is the property that keeps labels from becoming a second, competing
 * policy engine. A rule still has to allow the action; the label can add a
 * requirement on top. Marking something `public` does not open it, and removing
 * a label does not grant anything — it only stops adding a restriction.
 *
 * ## What each level requires
 *
 * Fixed in code rather than configurable per label. A knob here would mean two
 * places to look when asking "why was this challenged", and the answer to that
 * question needs to be short.
 */

import type { Db } from '@veto/db';

export const SENSITIVITY_LEVELS = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Sensitivity = (typeof SENSITIVITY_LEVELS)[number];

/** The default when nothing is labelled: no added requirement. */
export const DEFAULT_SENSITIVITY: Sensitivity = 'internal';

export interface SensitivityRequirement {
  /** Presence states in which no challenge is added. Empty means any. */
  readonly presence: readonly string[];
  readonly requireIntent: boolean;
}

export const REQUIREMENTS: Readonly<Record<Sensitivity, SensitivityRequirement>> = {
  // Nothing added. A rule that allows it, allows it.
  public: { presence: [], requireIntent: false },
  internal: { presence: [], requireIntent: false },
  // §7.2: away challenges sensitive reads. This is what "sensitive" means now.
  confidential: { presence: ['active'], requireIntent: false },
  // The strongest label: present *and* say what you are doing, so the approval
  // screen has something for a human to compare the action against.
  restricted: { presence: ['active'], requireIntent: true },
};

export interface ResourceLabel {
  readonly id: string;
  readonly resourceType: string;
  readonly pattern: string;
  readonly exact: boolean;
  readonly sensitivity: Sensitivity;
  readonly note: string | null;
}

interface LabelRow {
  id: string;
  resource_type: string;
  pattern: string;
  exact: boolean;
  sensitivity: Sensitivity;
  note: string | null;
}

const toLabel = (row: LabelRow): ResourceLabel => ({
  id: row.id,
  resourceType: row.resource_type,
  pattern: row.pattern,
  exact: row.exact,
  sensitivity: row.sensitivity,
  note: row.note,
});

export async function loadLabels(db: Db, workspaceId: string): Promise<ResourceLabel[]> {
  const { rows } = await db.query<LabelRow>(
    `select id, resource_type, pattern, exact, sensitivity, note
       from resource_labels where workspace_id = $1`,
    [workspaceId],
  );
  return rows.map(toLabel);
}

/**
 * The label that applies to one resource.
 *
 * Most specific wins, and specificity is longest match: an exact id beats any
 * prefix, and a longer prefix beats a shorter one. That is what lets
 * `/Finance/Public` be less restricted than `/Finance` without the answer
 * depending on row order.
 *
 * Returns null when nothing matches, which the caller reads as the default.
 */
export function matchLabel(
  labels: readonly ResourceLabel[],
  resourceType: string,
  resourceId: string,
): ResourceLabel | null {
  let best: ResourceLabel | null = null;
  let bestLength = -1;

  for (const label of labels) {
    if (label.resourceType !== resourceType) continue;

    if (label.exact) {
      // An exact match is the most specific thing there is; nothing outranks it.
      if (label.pattern === resourceId) return label;
      continue;
    }

    if (!resourceId.startsWith(label.pattern)) continue;

    if (label.pattern.length > bestLength) {
      best = label;
      bestLength = label.pattern.length;
    }
  }

  return best;
}

export const requirementFor = (sensitivity: Sensitivity): SensitivityRequirement =>
  REQUIREMENTS[sensitivity];
