/**
 * The Veto MCP gateway — the enforcement point (spec §3.1, invariant 8).
 *
 * This is the *only* thing that decides whether a protected action happens.
 * `apps/api` manages objects; this intercepts actions. They are separate
 * services because they have different trust boundaries and because invariant 8
 * reads better when exactly one process can enforce.
 *
 * ## What phase 2 deliberately does not do
 *
 * Every `tools/call` is denied, with `TOOL_NOT_ALLOWED`. That is the exit
 * condition, not a stub: CLAUDE.md requires deterministic deny-by-default to
 * ship before anything can allow, so the gateway is built refusing everything
 * and phase 3 adds the pipeline that can say yes. A gateway that allowed by
 * default while the pipeline was "coming soon" would be the exact failure this
 * product exists to prevent.
 *
 * ## Denials are JSON-RPC errors, not tool results
 *
 * MCP reports a tool's own failure inside a successful result with
 * `isError: true`. A Veto denial is not that: the tool never ran, nothing was
 * contacted, and there is no result to carry. Returning it as a result would
 * make a refusal structurally identical to content the model is meant to act
 * on. It is an error with a stable `reason_code` in `data` (§5.3).
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { RPC, RpcError, parseRpcRequest, rpcError, rpcResult, type RpcRequest } from './jsonrpc.ts';
import { GATEWAY_AUDIENCE, resolveSession, unauthenticated, type GatewaySession } from './session.ts';
import { findTool, toolListing } from './tools.ts';

/** The MCP revision this server speaks. */
export const PROTOCOL_VERSION = '2025-06-18';

export interface GatewayDeps {
  readonly pool: Pool;
  /** Verifies gateway capability tokens. Required — there is no open configuration. */
  readonly capabilitySecret: string;
  /** This gateway's public origin. Only Veto-controlled URLs are ever returned. */
  readonly publicUrl: string;
  /** Where a client goes to obtain a token. */
  readonly authorizationServer: string;
  readonly logger?: boolean;
}

export function createGateway(deps: GatewayDeps): FastifyInstance {
  if (deps.capabilitySecret.trim().length < 32) {
    throw new Error('capabilitySecret must be at least 32 characters');
  }
  const publicUrl = deps.publicUrl.replace(/\/+$/, '');

  const app = Fastify({
    logger: deps.logger ?? false,
    // Tool arguments are short. Anything larger is not a request worth parsing,
    // and a large body is the cheapest denial-of-service there is.
    bodyLimit: 256 * 1024,
    // §3.4 strict timeouts. A slow client must not hold a connection open while
    // an emergency lock it should have seen goes unread.
    requestTimeout: 15_000,
    connectionTimeout: 20_000,
    ajv: { customOptions: { removeAdditional: false, coerceTypes: false, allErrors: false } },
  });

  // Parse JSON ourselves so a malformed body becomes a JSON-RPC parse error
  // rather than a Fastify 400 the client cannot interpret.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    try {
      done(null, JSON.parse(body as string) as unknown);
    } catch {
      done(null, Symbol.for('veto.unparsable'));
    }
  });

  /**
   * RFC 9728 protected resource metadata (§8).
   *
   * Public and unauthenticated by design: it is how a client discovers where to
   * authenticate. It names only Veto-controlled URLs.
   */
  app.get('/.well-known/oauth-protected-resource', async (_request, reply) =>
    reply.header('cache-control', 'no-store').send({
      resource: `${publicUrl}/mcp`,
      authorization_servers: [deps.authorizationServer],
      bearer_methods_supported: ['header'],
      scopes_supported: ['mcp'],
      resource_documentation: `${publicUrl}/docs`,
    }),
  );

  app.post('/mcp', async (request, reply) => {
    const body = request.body;

    if (body === Symbol.for('veto.unparsable')) {
      return reply.code(400).send(rpcError(null, { code: RPC.PARSE_ERROR, message: 'Invalid JSON' }));
    }

    let rpc: RpcRequest;
    try {
      rpc = parseRpcRequest(body);
    } catch (error) {
      const rpcErr = error instanceof RpcError ? error : new RpcError(RPC.INVALID_REQUEST, 'Invalid request');
      return reply.code(400).send(rpcError(null, rpcErr.toBody()));
    }

    let session: GatewaySession;
    try {
      session = await resolveSession(deps.pool, deps.capabilitySecret, request);
    } catch {
      // The challenge header is how a client learns where to authenticate
      // (§8). It points at this gateway's own metadata document.
      return reply
        .code(401)
        .header(
          'www-authenticate',
          `Bearer resource_metadata="${publicUrl}/.well-known/oauth-protected-resource"`,
        )
        .send(rpcError(rpc.id, unauthenticated().toBody()));
    }

    try {
      const result = await dispatch(rpc, session, request);
      // A notification gets no body, even a successful one.
      if (rpc.isNotification) return reply.code(202).send();
      return reply.send(rpcResult(rpc.id, result));
    } catch (error) {
      const rpcErr =
        error instanceof RpcError
          ? error
          : new RpcError(RPC.INTERNAL_ERROR, 'Request failed');

      request.log.error(
        { code: rpcErr.code, method: rpc.method, agent: session.agentId, err: error },
        'gateway request failed',
      );

      if (rpc.isNotification) return reply.code(202).send();
      // Denials are a normal outcome, not a transport failure: 200 with a
      // JSON-RPC error, which is what the protocol expects.
      return reply.code(200).send(rpcError(rpc.id, rpcErr.toBody()));
    }
  });

  async function dispatch(
    rpc: RpcRequest,
    session: GatewaySession,
    request: FastifyRequest,
  ): Promise<unknown> {
    switch (rpc.method) {
      case 'initialize':
        return {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'veto-gateway', version: '0.1.0' },
          instructions:
            'Every tool call is authorized individually at call time. A previously listed ' +
            'or previously allowed tool is not permission for this call.',
        };

      case 'notifications/initialized':
        return {};

      case 'ping':
        return {};

      case 'tools/list':
        // Listing is not granting (invariant 9). The same catalogue goes to
        // every caller; what differs is what each is allowed to do with it.
        return { tools: toolListing() };

      case 'tools/call':
        return callTool(rpc, session, request);

      default:
        throw new RpcError(RPC.METHOD_NOT_FOUND, `Unknown method: ${rpc.method}`);
    }
  }

  async function callTool(
    rpc: RpcRequest,
    session: GatewaySession,
    request: FastifyRequest,
  ): Promise<never> {
    const name = rpc.params['name'];
    if (typeof name !== 'string' || name === '') {
      throw new RpcError(RPC.INVALID_PARAMS, 'name is required');
    }

    const args = rpc.params['arguments'];
    if (args !== undefined && (typeof args !== 'object' || args === null || Array.isArray(args))) {
      throw new RpcError(RPC.INVALID_PARAMS, 'arguments must be an object');
    }

    const tool = findTool(name);
    if (!tool) {
      // An unknown tool is refused as a denial, not as "no such method". The
      // catalogue is not secret, but a caller probing for tools should get the
      // same shape of answer as one asking for a tool it may not use.
      throw denied('TOOL_NOT_ALLOWED', 'This tool is not available to this agent.', session, request);
    }

    // Phase 2 ends here, on purpose. Argument validation against the tool's
    // strict schema, then the nine-step pipeline, land in phase 3. Until then
    // there is no path through this function that reaches an upstream service.
    throw denied(
      'TOOL_NOT_ALLOWED',
      'No policy grants this agent that action yet.',
      session,
      request,
    );
  }

  function denied(
    reasonCode: string,
    humanMessage: string,
    session: GatewaySession,
    request: FastifyRequest,
  ): RpcError {
    return new RpcError(RPC.DENIED, humanMessage, {
      result: 'deny',
      reason_code: reasonCode,
      human_message: humanMessage,
      // One correlation id spans request, decision, approval, upstream call and
      // audit event (§8). Fastify's request id is that id at this end.
      correlation_id: request.id,
      agent_id: session.agentId,
    });
  }

  return app;
}

export { GATEWAY_AUDIENCE };
