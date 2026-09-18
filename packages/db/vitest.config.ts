import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['./test/global-setup.ts'],
    // The tenant-isolation tests share one database and rely on advisory locks
    // for the audit chain; parallel files would interleave unpredictably.
    fileParallelism: false,
  },
});
