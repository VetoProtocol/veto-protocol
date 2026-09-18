/** `pnpm --filter @veto/permit latency` — see latency.ts for how to read the output. */
import { loadRepoEnv } from './env.ts';
import { permitConfigFromEnv } from './config.ts';
import { measureCheckLatency } from './latency.ts';
import { agentUserKey } from './model.ts';

loadRepoEnv();

const tenant = process.env['PERMIT_LATENCY_TENANT'] ?? 'ws_latency_probe';
const config = permitConfigFromEnv();

const report = await measureCheckLatency(
  config,
  {
    user: agentUserKey('agt_latency_probe'),
    action: 'read',
    resourceType: process.env['PERMIT_LATENCY_RESOURCE'] ?? 'google_file',
    resourceKey: 'probe',
    tenant,
  },
  {
    samples: Number(process.env['PERMIT_LATENCY_SAMPLES'] ?? 50),
    budgetMs: Number(process.env['PERMIT_LATENCY_BUDGET_MS'] ?? 100),
  },
);

console.error(`pdp           ${config.pdpUrl}`);
console.error(`samples       ${report.samples} (${report.failures} failed)`);
console.error(`min / p50     ${report.minMs} ms / ${report.p50Ms} ms`);
console.error(`p95 / p99     ${report.p95Ms} ms / ${report.p99Ms} ms`);
console.error(`max           ${report.maxMs} ms`);
console.error(`budget        ${report.budgetMs} ms for the PDP slice of the §11 200 ms P95`);
console.error(report.withinBudget ? 'VERDICT       within budget' : 'VERDICT       OVER BUDGET');

if (!report.withinBudget) process.exitCode = 1;
