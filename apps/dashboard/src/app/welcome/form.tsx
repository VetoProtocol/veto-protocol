'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { createWorkspaceAction } from './actions';

export function CreateWorkspaceForm({ suggestion }: { suggestion: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    createWorkspaceAction,
    EMPTY,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 16, justifyItems: 'start' }}>
      <label style={{ display: 'grid', gap: 6, width: '100%', maxWidth: 420 }}>
        <span className="label">workspace name</span>
        <input
          name="workspace_name"
          required
          autoFocus
          maxLength={120}
          defaultValue={suggestion}
          style={{
            font: 'inherit',
            fontSize: 12.5,
            width: '100%',
            padding: '9px 11px',
            background: 'var(--bg-input)',
            border: '1px solid var(--border)',
            color: 'var(--text)',
          }}
        />
        <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
          Only you will see it. You can have one workspace of your own.
        </span>
      </label>

      <Button type="submit" variant="solid" disabled={pending}>
        {pending ? 'creating…' : 'create workspace'}
      </Button>

      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12.5, maxWidth: 480 }}>
          {state.error}
        </p>
      ) : null}
    </form>
  );
}
