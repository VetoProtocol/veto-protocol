'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { EMPTY, type ActionState } from '../agents/action-state';
import { removeLabelAction, setLabelAction } from './actions';

const field: React.CSSProperties = {
  font: 'inherit',
  fontSize: 12.5,
  width: '100%',
  padding: '8px 10px',
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
};

const LEVELS = [
  ['internal', 'no extra requirement'],
  ['confidential', 'you must be at your desk'],
  ['restricted', 'at your desk, and state a purpose'],
  ['public', 'no extra requirement — not permission'],
] as const;

export function SetLabelForm() {
  const [state, action, pending] = useActionState<ActionState, FormData>(setLabelAction, EMPTY);

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 14 }}>
      <div style={{ display: 'grid', gap: 14, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <label style={{ display: 'grid', gap: 6 }}>
          <span className="label">
            resource type <span style={{ color: 'var(--text-faint)' }}>what kind</span>
          </span>
          <select name="resource_type" defaultValue="google_file" style={field}>
            <option value="google_file">google_file</option>
            <option value="google_folder">google_folder</option>
          </select>
        </label>

        <label style={{ display: 'grid', gap: 6 }}>
          <span className="label">
            pattern <span style={{ color: 'var(--text-faint)' }}>path or id</span>
          </span>
          <input name="pattern" required maxLength={512} placeholder="/Finance" style={field} />
        </label>

        <label style={{ display: 'grid', gap: 6 }}>
          <span className="label">
            level <span style={{ color: 'var(--text-faint)' }}>what it adds</span>
          </span>
          <select name="sensitivity" defaultValue="confidential" style={field}>
            {LEVELS.map(([value, hint]) => (
              <option key={value} value={value}>
                {value} — {hint}
              </option>
            ))}
          </select>
        </label>

        <label style={{ display: 'grid', gap: 6 }}>
          <span className="label">
            note <span style={{ color: 'var(--text-faint)' }}>optional</span>
          </span>
          <input name="note" maxLength={200} placeholder="Payroll and board papers" style={field} />
        </label>
      </div>

      <label style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 12 }}>
        <input type="checkbox" name="exact" style={{ accentColor: '#ededed' }} />
        <span style={{ color: 'var(--text-dim)' }}>
          Exact match only — this one resource, not everything beginning with it.
        </span>
      </label>

      <div aria-live="polite" style={{ minHeight: 18, fontSize: 12 }}>
        {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
        {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <Button type="submit" variant="solid" disabled={pending}>
          {pending ? 'saving…' : 'Apply label'}
        </Button>
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
          adds a requirement · never grants access
        </span>
      </div>
    </form>
  );
}

export function RemoveLabel({ labelId, pattern }: { labelId: string; pattern: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(removeLabelAction, EMPTY);

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
        remove
      </summary>
      <form action={action} style={{ marginTop: 10, display: 'grid', gap: 8, maxWidth: 320 }}>
        <input type="hidden" name="label_id" value={labelId} />
        <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 11.5, lineHeight: 1.6 }}>
          Takes the extra requirement off <span style={{ color: 'var(--text)' }}>{pattern}</span>. It
          grants nothing — whatever your rules already allow is what remains.
        </p>
        <div aria-live="polite" style={{ fontSize: 11.5 }}>
          {state.error ? <span style={{ color: 'var(--deny)' }}>{state.error}</span> : null}
          {state.notice ? <span style={{ color: 'var(--allow)' }}>{state.notice}</span> : null}
        </div>
        <div>
          <Button type="submit" variant="danger" disabled={pending}>
            {pending ? 'removing…' : 'Confirm remove'}
          </Button>
        </div>
      </form>
    </details>
  );
}
