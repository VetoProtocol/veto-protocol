'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { emergencyLockAction, setPresenceAction } from './actions';

const STATES = [
  ['active', 'Low-risk actions inside scope go ahead.'],
  ['away', 'Sensitive reads and every write need your approval.'],
  ['locked', 'Everything is denied until you change it back.'],
] as const;

export function PresenceControls({ current }: { current: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(setPresenceAction, EMPTY);

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 14 }}>
      {/* Radios rather than three buttons: the choice is one of a set, and a
          radio group is what a screen reader and a keyboard already understand. */}
      <fieldset style={{ border: 0, margin: 0, padding: 0, display: 'grid', gap: 10 }}>
        <legend className="label" style={{ padding: 0 }}>
          Set your state
        </legend>
        {STATES.map(([value, description]) => (
          <label
            key={value}
            style={{
              display: 'flex',
              gap: 12,
              alignItems: 'flex-start',
              padding: '11px 14px',
              border: `1px solid ${value === current ? 'var(--border-strong)' : 'var(--border)'}`,
              background: value === current ? '#131313' : 'transparent',
              cursor: 'pointer',
            }}
          >
            <input
              type="radio"
              name="state"
              value={value}
              defaultChecked={value === current}
              style={{ marginTop: 3, accentColor: '#ededed' }}
            />
            <span>
              <span style={{ fontSize: 12.5 }}>{value}</span>
              <span style={{ display: 'block', color: 'var(--text-dim)', fontSize: 11.5, marginTop: 3 }}>
                {description}
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      <div aria-live="polite" style={{ minHeight: 18, fontSize: 12 }}>
        {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
        {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <Button type="submit" variant="solid" disabled={pending}>
          {pending ? 'saving…' : 'Save state'}
        </Button>
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
          set from the dashboard · medium assurance · only a passkey proves more
        </span>
      </div>
    </form>
  );
}

export function EmergencyLock({ locked }: { locked: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(emergencyLockAction, EMPTY);

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 14 }}>
      <input type="hidden" name="locked" value={locked ? 'false' : 'true'} />
      <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.7, maxWidth: 620 }}>
        Denies every protected action in this workspace and drops every live agent session. Checked
        before policy is consulted, so an in-flight session cannot outrun it. New agents cannot be
        registered while it is on — revoking still works, because revoking only ever narrows.
      </p>

      <div aria-live="polite" style={{ minHeight: 18, fontSize: 12 }}>
        {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
        {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
      </div>

      <div>
        <Button type="submit" variant={locked ? 'outline' : 'danger'} disabled={pending}>
          {pending ? 'working…' : locked ? 'Unlock workspace' : 'Lock this workspace'}
        </Button>
      </div>
    </form>
  );
}
