'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { registerAgentAction } from './actions';
import { EMPTY, type ActionState } from './action-state';

const field: React.CSSProperties = {
  font: 'inherit',
  fontSize: 12.5,
  width: '100%',
  padding: '8px 10px',
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
};

export function RegisterForm() {
  const [state, action, pending] = useActionState<ActionState, FormData>(registerAgentAction, EMPTY);

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 14 }}>
      <div style={{ display: 'grid', gap: 14, gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))' }}>
        <Label text="provider" hint="e.g. mcp">
          <input name="provider" required maxLength={100} defaultValue="mcp" style={field} />
        </Label>
        <Label text="client id" hint="the client software">
          <input name="client_id" required maxLength={200} placeholder="claude-desktop" style={field} />
        </Label>
        <Label text="fingerprint" hint="optional">
          <input name="fingerprint" maxLength={512} style={field} />
        </Label>
      </div>

      {/* aria-live so the result is announced, not just painted. */}
      <div aria-live="polite" style={{ minHeight: 18, fontSize: 12 }}>
        {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
        {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <Button type="submit" variant="solid" disabled={pending}>
          {pending ? 'registering…' : 'Register agent'}
        </Button>
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
          registered to you · grants nothing until a connection is attached
        </span>
      </div>
    </form>
  );
}

function Label({ text, hint, children }: { text: string; hint: string; children: React.ReactNode }) {
  return (
    <label style={{ display: 'grid', gap: 6 }}>
      <span className="label">
        {text} <span style={{ color: 'var(--text-faint)' }}>{hint}</span>
      </span>
      {children}
    </label>
  );
}
