'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { revokeConnectionAction } from './actions';

export function RevokeConnection({ connectionId }: { connectionId: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    revokeConnectionAction,
    EMPTY,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 8, justifyItems: 'start' }}>
      <input type="hidden" name="connection_id" value={connectionId} />
      <Button type="submit" variant="danger" disabled={pending}>
        {pending ? 'disconnecting…' : 'disconnect'}
      </Button>
      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 11.5 }}>
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p role="status" style={{ margin: 0, color: 'var(--text-dim)', fontSize: 11.5 }}>
          {state.notice}
        </p>
      ) : null}
    </form>
  );
}
