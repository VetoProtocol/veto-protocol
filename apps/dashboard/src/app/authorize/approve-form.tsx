'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { approveAuthorizationAction } from './actions';

export interface AgentChoice {
  readonly id: string;
  readonly clientId: string;
  /** Whether any policy rule names this agent. An agent with none can do nothing. */
  readonly hasRules: boolean;
}

export function ApproveForm({
  agents,
  clientId,
  redirectUri,
  codeChallenge,
  resource,
  state,
}: {
  agents: readonly AgentChoice[];
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  state: string | null;
}) {
  const [formState, action, pending] = useActionState<ActionState, FormData>(
    approveAuthorizationAction,
    EMPTY,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 18 }}>
      {/* The request, carried through the approval unchanged. A client that
          could alter any of this between the screen and the exchange would be
          approved for something the person never read. */}
      <input type="hidden" name="client_id" value={clientId} />
      <input type="hidden" name="redirect_uri" value={redirectUri} />
      <input type="hidden" name="code_challenge" value={codeChallenge} />
      <input type="hidden" name="resource" value={resource} />
      {state === null ? null : <input type="hidden" name="state" value={state} />}

      <label style={{ display: 'grid', gap: 7 }}>
        <span className="label">acting as</span>
        <select
          name="agent_id"
          required
          // No default. The previous version selected whichever agent came
          // first, and approving the wrong one produced a correct denial
          // minutes later on a different screen, with nothing connecting the
          // two. Choosing is now deliberate.
          defaultValue=""
          style={{
            background: 'var(--bg-raised)',
            border: '1px solid var(--border-strong)',
            color: 'var(--text)',
            padding: '9px 11px',
            fontSize: 12.5,
            fontFamily: 'inherit',
            minWidth: 320,
          }}
        >
          <option value="" disabled>
            choose an agent…
          </option>
          {agents.map((agent) => (
            <option key={agent.id} value={agent.id}>
              {agent.clientId} — {agent.id}
              {agent.hasRules ? '' : '  (no rules yet — will be refused)'}
            </option>
          ))}
        </select>
      </label>

      {/* Said before approving rather than discovered afterwards. Not a
          warning against proceeding: authorizing an agent and then writing its
          rules is a perfectly ordinary order to work in. */}
      {agents.every((agent) => !agent.hasRules) ? (
        <p style={{ margin: 0, color: 'var(--challenge)', fontSize: 11.5, maxWidth: 560 }}>
          None of these agents has a policy rule yet, so every request will be refused until one
          is written. You can approve now and add rules on the Policies screen.
        </p>
      ) : null}

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <Button type="submit" disabled={pending}>
          {pending ? 'approving…' : 'Approve'}
        </Button>
        {/* Cancel is a link back, not a form action. Nothing to undo: no code
            exists until Approve is pressed. */}
        <a href="/agents" style={{ color: 'var(--text-dim)', fontSize: 12.5 }}>
          Cancel
        </a>
      </div>

      {formState.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12 }}>
          {formState.error}
        </p>
      ) : null}
    </form>
  );
}
