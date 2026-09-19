'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { chooseWorkspaceAction } from './actions';

export function ChooseWorkspaceForm({ workspaceIds }: { workspaceIds: readonly string[] }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    chooseWorkspaceAction,
    EMPTY,
  );

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {workspaceIds.map((id) => (
        <form key={id} action={action}>
          <input type="hidden" name="workspace_id" value={id} />
          <Button
            type="submit"
            variant="outline"
            disabled={pending}
            style={{ width: '100%', maxWidth: 480, textAlign: 'left', padding: '12px 16px' }}
          >
            {id}
          </Button>
        </form>
      ))}

      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12.5 }}>
          {state.error}
        </p>
      ) : null}
    </div>
  );
}
