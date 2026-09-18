'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { revokeAgentAction } from './actions';
import { EMPTY, type ActionState } from './action-state';

/**
 * Revocation, behind a disclosure.
 *
 * Two steps on purpose. Revoking drops every live session for the agent and is
 * not undone by re-registering — the new agent is a different identity with
 * nothing attached. A single click in a table row is too cheap for that.
 *
 * `<details>` rather than a modal or `confirm()`: it is focusable, opens with
 * Enter or Space, traps nothing, and needs no JavaScript to be operable. §11
 * asks for keyboard-complete flows, and the cheapest way to be keyboard
 * complete is to not reinvent a control the browser already ships.
 */
export function RevokeControl({ agentId, disabled }: { agentId: string; disabled: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(revokeAgentAction, EMPTY);

  if (disabled) {
    return <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>—</span>;
  }

  return (
    <details>
      <summary
        style={{
          cursor: 'pointer',
          color: 'var(--text-dim)',
          fontSize: 11.5,
          listStyle: 'none',
          display: 'inline-block',
          borderBottom: '1px dotted var(--border-strong)',
        }}
      >
        revoke
      </summary>
      <form action={action} style={{ marginTop: 10, display: 'grid', gap: 8, maxWidth: 300 }}>
        <input type="hidden" name="agent_id" value={agentId} />
        <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 11.5, lineHeight: 1.6 }}>
          Drops every live session and removes this agent&rsquo;s policy facts. Permanent — a new
          registration is a different identity.
        </p>
        <div aria-live="polite" style={{ fontSize: 11.5 }}>
          {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
          {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
        </div>
        <div>
          <Button type="submit" variant="danger" disabled={pending}>
            {pending ? 'revoking…' : 'Confirm revoke'}
          </Button>
        </div>
      </form>
    </details>
  );
}
