import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@': path.join(here, 'src'),
      // `server-only` exists to make a build fail when server code is pulled
      // into a client bundle. Under vitest there is no bundle, so it is stubbed
      // rather than removed from the source — the guard stays real where it
      // matters.
      'server-only': path.join(here, 'test', 'server-only-stub.ts'),
    },
  },
  test: { include: ['test/**/*.test.ts'], env: { NODE_ENV: 'test' } },
});
