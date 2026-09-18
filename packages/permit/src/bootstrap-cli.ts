/** `pnpm --filter @veto/permit bootstrap` — creates the §4.2 resource model in one environment. */
import { loadRepoEnv } from './env.ts';
import { permitConfigFromEnv } from './config.ts';
import { bootstrapPermitEnvironment } from './bootstrap.ts';

loadRepoEnv();

const report = await bootstrapPermitEnvironment(permitConfigFromEnv());

console.error(`created:  ${report.created.length ? report.created.join(', ') : '(none)'}`);
console.error(`existing: ${report.existing.length ? report.existing.join(', ') : '(none)'}`);
