import path from 'node:path';
import { fileURLToPath } from 'node:url';

/*
 * Next loads `.env` from its own directory, but this repo keeps one at the
 * root so every package reads the same file. Load it here, before the server
 * starts, and let anything already set in the environment win — the reverse
 * precedence is what let `.env` clobber NODE_ENV elsewhere in this repo.
 */
{
  const before = { ...process.env };
  try {
    process.loadEnvFile(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '.env'));
    for (const [key, value] of Object.entries(before)) {
      if (value !== undefined) process.env[key] = value;
    }
  } catch {
    // No .env; the environment is the only source.
  }
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // @veto/tokens ships TypeScript source, like every package here. It is a
  // single file with no relative imports, so Next compiles it directly and the
  // .ts-extension convention the node-run packages need never comes up.
  transpilePackages: ['@veto/tokens'],
  poweredByHeader: false,
  // The dashboard renders authorization state. It must never be cached by an
  // intermediary, and it must never be framed — a clickjacked revoke button is
  // a revoke button (§7.3).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Cache-Control', value: 'no-store, max-age=0' },
        ],
      },
    ];
  },
};

export default nextConfig;
