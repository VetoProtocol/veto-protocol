import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ['test/**/*.test.ts'], fileParallelism: false, env: { NODE_ENV: 'test' } },
});
