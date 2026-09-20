import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    fileParallelism: false,
    // Pinned, not inherited. The Permit fake refuses to load outside
    // NODE_ENV=test, and that guard is worth more than the convenience of
    // whatever the invoking shell happened to export.
    env: { NODE_ENV: 'test' },
  },
});
