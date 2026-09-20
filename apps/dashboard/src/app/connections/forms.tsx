'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { revokeConnectionAction, syncHierarchyAction } from './actions';

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

/**
 * Record what is inside a folder, so a grant on it reaches the files within.
 *
 * Defaults to `root`, Drive's own name for the top of My Drive, because that is
 * what somebody who has just connected an account almost always means. The
 * field is editable so a deeper folder can be walked on its own — the walk
 * stops at a depth limit and says so, and running it again lower down is the
 * answer to that.
 */
export function SyncHierarchy() {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    syncHierarchyAction,
    EMPTY,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 10, justifyItems: 'start' }}>
      <label style={{ display: 'grid', gap: 6 }}>
        <span className="label">folder to walk</span>
        <input
          name="folder_id"
          defaultValue="root"
          style={{
            background: 'var(--bg-raised)',
            border: '1px solid var(--border-strong)',
            color: 'var(--text)',
            padding: '8px 10px',
            fontSize: 12.5,
            fontFamily: 'inherit',
            minWidth: 280,
          }}
        />
      </label>
      <Button type="submit" disabled={pending}>
        {pending ? 'walking Drive…' : 'record folder structure'}
      </Button>
      {/* Said before it is pressed, because a walk of a large Drive takes
          minutes and a button that appears to hang is a button people press
          twice. */}
      <p style={{ margin: 0, color: 'var(--text-faint)', fontSize: 11.5, maxWidth: 560 }}>
        Walks the folder and records where each file sits, so a grant on it reaches what is inside.
        Grants nothing by itself. A large Drive takes a minute or two.
      </p>
      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 11.5 }}>
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p role="status" style={{ margin: 0, color: 'var(--text-dim)', fontSize: 11.5, maxWidth: 560 }}>
          {state.notice}
        </p>
      ) : null}
    </form>
  );
}
