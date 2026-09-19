# Demo recording

Records a walkthrough of the dashboard as a `.webm`, with a cursor overlay and
subtitles. Throwaway tooling — not part of the product, not wired into any
build.

```bash
# 1. mint a session (10 minutes, matching SESSION_TTL_MS)
node --experimental-strip-types tools/demo/mint-session.ts <workspaceId> <userId> > /tmp/sess

# 2. see what is actually on each screen
DEMO_SESSION_COOKIE="$(cat /tmp/sess)" node tools/demo/discover.mjs

# 3. verify every selector resolves
DEMO_SESSION_COOKIE="$(cat /tmp/sess)" node tools/demo/record.mjs --rehearse

# 4. record
DEMO_SESSION_COOKIE="$(cat /tmp/sess)" node tools/demo/record.mjs
```

Output lands in `tools/demo/out/`, which is gitignored — a recording of a real
workspace shows real file names and real agent ids, and does not belong in a
repository.

## Why a minted cookie

A headless browser cannot complete an OIDC round trip against a real provider,
and a demo of Veto should show Veto's screens rather than Google's consent page.
`mint-session.ts` mirrors `apps/dashboard/src/lib/session.ts` rather than
importing it, because that module is `server-only` and throws outside a Next
request. It reads the same `.env` the dashboard reads and holds no power the
operator does not already have — but it signs sessions, so run it only on a
machine you own, never in CI.

## The demo is read-only

`Confirm revoke`, `remove` and `stop` all live on these screens and all destroy
real state. `record.mjs` clicks navigation and nothing else. Keep it that way.

## Re-recording after UI changes

Run discovery again first. Selectors drift, and a silent selector failure
produces a video that looks fine until somebody watches it.
