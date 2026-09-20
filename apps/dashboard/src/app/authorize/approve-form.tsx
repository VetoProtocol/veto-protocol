'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { approveAuthorizationAction } from './actions';

export interface AgentChoice {
  readonly id: string;
  readonly clientId: string;
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
          defaultValue={agents[0]?.id ?? ''}
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
          {agents.map((agent) => (
            <option key={agent.id} value={agent.id}>
              {agent.clientId} — {agent.id}
            </option>
          ))}
        </select>
      </label>

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
