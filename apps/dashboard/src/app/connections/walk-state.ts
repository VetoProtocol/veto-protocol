import type { HierarchyJob } from '@/lib/api';

/**
 * What a finished folder walk should say.
 *
 * Shared because two places say it: the action, when a small folder finishes
 * inside the request, and the page, when a slow one finishes later. One
 * sentence with two authors drifts.
 *
 * `truncated` is reported rather than buried. A walk that stopped early and
 * said it finished would leave somebody believing a grant reaches files it does
 * not — the failure this whole feature exists to remove.
 */
export function describeWalk(job: HierarchyJob): string {
  if (job.status === 'failed') {
    return job.error ?? 'That walk did not finish. Check the connected account and try again.';
  }
  if (job.status === 'running') {
    return 'Still walking that folder. It writes one entry at a time to the policy engine.';
  }

  const found =
    `${job.links} item${job.links === 1 ? '' : 's'} across ` +
    `${job.folders} folder${job.folders === 1 ? '' : 's'}`;

  return job.truncated
    ? `Recorded ${found}. Stopped at the ${job.depth}-level limit — anything deeper is not ` +
      'reachable yet, so run it again on a subfolder if you need it.'
    : `Recorded ${found}. A grant on that folder now reaches everything inside it.`;
}
