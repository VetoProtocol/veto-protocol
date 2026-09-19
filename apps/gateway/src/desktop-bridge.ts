/**
 * A stdio bridge, so a desktop MCP client can reach the gateway today.
 *
 * ## Why this exists, and what it is not
 *
 * §8 asks for OAuth 2.1-compatible discovery. Half of it is there: the gateway
 * serves `/.well-known/oauth-protected-resource` and names an authorization
 * server. That server does not exist yet — there is no `/authorize`, no
 * `/token`, no client registration — so a client that tries to authorize itself
 * gets as far as discovery and stops.
 *
 * Until it exists, this carries the credential instead. It is a **development
 * bridge and not an authentication design**: it holds the capability signing
 * key, so it may only ever run on the same machine as the control plane, under
 * the same person. Nothing about it belongs in a deployment.
 *
 * ## What it does not do
 *
 * It does not decide anything. Every request is forwarded to the gateway
 * unchanged, and all nine steps of §3.3 run there: identity, normalisation,
 * presence and lock, prechecks, `permit.check`, risk, emit, upstream, audit.
 * A bridge that answered a `tools/call` itself would be a second enforcement
 * point, which invariant 8 does not allow.
 *
 * ## One token per request
 *
 * Capability tokens are capped at fifteen minutes (`MAX_TTL_MS`), so a static
 * one pasted into a config file would stop working mid-session. Minting per
 * request also means a token exists for exactly as long as the call it
 * authorises — which is what a capability is for.
 */

import { createInterface } from 'node:readline';
import { mintCapability } from '@veto/tokens';
import { loadRepoEnv } from '@veto/db';
import { GATEWAY_AUDIENCE, GATEWAY_SCOPE } from './session.ts';

loadRepoEnv();

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) {
    // stderr, never stdout: stdout is the JSON-RPC stream and a stray line
    // corrupts every message after it.
    process.stderr.write(`[veto-bridge] ${name} is not set\n`);
    process.exit(2);
  }
  return value;
}

const secret = required('VETO_CAPABILITY_SECRET');
const workspaceId = required('VETO_WORKSPACE_ID');
const humanId = required('VETO_HUMAN_ID');
const agentId = required('VETO_AGENT_ID');
const endpoint = (process.env['VETO_GATEWAY_URL'] ?? 'http://127.0.0.1:4100/mcp').trim();

/** Short: it only has to outlive one round trip. */
const token = (): string =>
  mintCapability(secret, {
    aud: GATEWAY_AUDIENCE,
    workspaceId,
    humanId,
    agentId,
    action: GATEWAY_SCOPE,
    resource: 'mcp',
    ttlMs: 60_000,
  });

const send = (message: unknown): void => {
  process.stdout.write(`${JSON.stringify(message)}\n`);
};

const rl = createInterface({ input: process.stdin });

/**
 * Requests still waiting on the gateway.
 *
 * stdin closing means the client has stopped talking, not that it has stopped
 * listening. Exiting on `close` drops every reply still in flight — which for
 * a tool call means the client waits forever for an answer that was already
 * decided.
 */
let pending = 0;
let closed = false;

const finish = (): void => {
  if (closed && pending === 0) process.exit(0);
};

rl.on('line', (line) => {
  const text = line.trim();
  if (text === '') return;

  pending += 1;
  void (async () => {
    // Parsed only to find the id, so a failure can be reported against the
    // right request. The body is forwarded exactly as it arrived.
    let id: unknown;
    let isNotification = false;
    try {
      const parsed = JSON.parse(text) as { id?: unknown; method?: unknown };
      id = parsed.id;
      // A notification has no id and expects no reply. Answering one puts a
      // message on the stream the client never asked for.
      isNotification = parsed.id === undefined;
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      // Releases the slot this line took. Returning without it would leave the
      // bridge believing a request was still outstanding and never exiting.
      pending -= 1;
      finish();
      return;
    }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${token()}`,
        },
        body: text,
        signal: AbortSignal.timeout(30_000),
      });

      const body = await response.text();
      if (isNotification) return;
      if (body.trim() === '') return;
      process.stdout.write(`${body.trimEnd()}\n`);
    } catch (error) {
      if (isNotification) return;
      process.stderr.write(`[veto-bridge] ${String(error)}\n`);
      send({
        jsonrpc: '2.0',
        id: id ?? null,
        // The gateway being unreachable is not a decision, and must not be
        // reported as one. -32603 is a transport failure; a denial would have
        // come back as a proper result.
        error: { code: -32603, message: 'The Veto gateway could not be reached' },
      });
    } finally {
      pending -= 1;
      finish();
    }
  })();
});

rl.on('close', () => {
  closed = true;
  finish();
});
