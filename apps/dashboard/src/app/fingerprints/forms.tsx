'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import type { ActionState } from '../agents/action-state';
import { judgeFingerprintAction, setModeAction } from './actions';

const EMPTY: ActionState = { error: null, notice: null };

const message: React.CSSProperties = { fontSize: 11, lineHeight: 1.6, maxWidth: 420 };

function Feedback({ state }: { state: ActionState }) {
  if (state.error !== null) {
    return (
      <span role="alert" style={{ ...message, color: 'var(--deny)' }}>
        {state.error}
      </span>
    );
  }
  if (state.notice !== null) {
    return (
      <span role="status" style={{ ...message, color: 'var(--text-dim)' }}>
        {state.notice}
      </span>
    );
  }
  return null;
}

const MODES = [
  ['observe', 'record only'],
  ['challenge', 'ask me'],
  ['deny', 'refuse'],
] as const;

export function SetMode({ agentId, current }: { agentId: string; current: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(setModeAction, EMPTY);

  return (
    <form action={action} style={{ display: 'grid', gap: 7, justifyItems: 'start' }}>
      <input type="hidden" name="agent_id" value={agentId} />
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {MODES.map(([value, label]) => (
          <Button
            key={value}
            type="submit"
            name="mode"
            value={value}
            disabled={pending || current === value}
            variant={current === value ? 'solid' : 'outline'}
            style={{ padding: '5px 10px', fontSize: 11 }}
          >
            {current === value ? `· ${label}` : label}
          </Button>
        ))}
      </div>
      <Feedback state={state} />
    </form>
  );
}

/**
 * Trust or refuse one piece of software.
 *
 * `Refuse` is offered only where enforcement is on, because in `observe` the
 * mode ignores it — a button that quietly does nothing is worse than an absent
 * one. Nothing here can be applied to software that has never connected: a pin
 * for a digest nobody has seen would be a guess.
 */
export function JudgeClient({
  agentId,
  fingerprint,
  status,
  enforcing,
}: {
  agentId: string;
  fingerprint: string;
  status: 'pinned' | 'seen' | 'refused';
  enforcing: boolean;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    judgeFingerprintAction,
    EMPTY,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
      <input type="hidden" name="agent_id" value={agentId} />
      <input type="hidden" name="fingerprint" value={fingerprint} />
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {status === 'pinned' ? null : (
          <Button
            type="submit"
            name="status"
            value="pinned"
            disabled={pending}
            style={{ padding: '5px 10px', fontSize: 11 }}
          >
            {pending ? '…' : 'trust'}
          </Button>
        )}
        {enforcing && status !== 'refused' ? (
          <Button
            type="submit"
            name="status"
            value="refused"
            variant="danger"
            disabled={pending}
            style={{ padding: '5px 10px', fontSize: 11 }}
          >
            refuse
          </Button>
        ) : null}
      </div>
      <Feedback state={state} />
    </form>
  );
}
