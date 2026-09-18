/**
 * Step 2 of §3.3 — turn a tool call into a normalized action.
 *
 * Two jobs, in this order:
 *
 *  1. **Validate arguments against the tool's strict schema.** Invariant 9 puts
 *     this before policy evaluation, not after, and the reason is the digest: an
 *     argument set that has not been validated cannot be digested meaningfully,
 *     and an approval bound to an unvalidated digest is not bound to anything.
 *  2. **Extract the resource the call is actually about.** A tool names its
 *     resource in its own argument (`file_id`, `folder_id`); the pipeline needs
 *     one shape. Getting this wrong would authorize a different object from the
 *     one the call touches.
 */

import { Ajv, type ValidateFunction } from 'ajv';
import type { EvaluateInput } from '@veto/decisions';
import { RPC, RpcError } from './jsonrpc.ts';
import { TOOLS, type ToolDefinition } from './tools.ts';
import type { GatewaySession } from './session.ts';

// Compiled once. `allErrors: false` stops at the first failure — the caller
// gets one refusal either way, and enumerating every problem with a hostile
// payload is work done on an attacker's behalf.
const ajv = new Ajv({ allErrors: false, removeAdditional: false, coerceTypes: false, strict: true });

const validators = new Map<string, ValidateFunction>(
  TOOLS.map((tool) => [tool.name, ajv.compile(tool.inputSchema)]),
);

/** Which argument names the resource, per tool. */
const RESOURCE_ARGUMENT: Readonly<Record<string, string>> = {
  'google_drive.read_file': 'file_id',
  'google_drive.list_folder': 'folder_id',
};

const invalid = (): RpcError =>
  // The validation detail is not echoed. It is derived from attacker-supplied
  // input and would land in a response that may be logged downstream.
  new RpcError(RPC.INVALID_PARAMS, 'Arguments failed validation', {
    reason_code: 'ARGUMENT_SCHEMA_INVALID',
  });

export function normalize(
  tool: ToolDefinition,
  rawArguments: Readonly<Record<string, unknown>>,
  session: GatewaySession,
  requestId: string,
): EvaluateInput {
  const validate = validators.get(tool.name);
  if (!validate) throw new RpcError(RPC.INVALID_PARAMS, 'Unknown tool');
  if (!validate(rawArguments)) throw invalid();

  const argName = RESOURCE_ARGUMENT[tool.name];
  const resourceId = argName === undefined ? undefined : rawArguments[argName];
  if (typeof resourceId !== 'string' || resourceId === '') throw invalid();

  const intent = rawArguments['declared_intent'];

  return {
    requestId,
    workspaceId: session.workspaceId,
    humanId: session.humanId,
    agentId: session.agentId,
    clientId: session.clientId,
    tool: tool.name,
    action: tool.action,
    resource: { type: tool.resourceType, id: resourceId },
    arguments: rawArguments,
    declaredIntent: typeof intent === 'string' ? intent : null,
    // No tool sends anywhere yet. When one does, this carries the destination
    // into the SSRF check at step 6.
    destination: null,
    occurredAt: new Date().toISOString(),
  };
}
