'use client';

import { useActionState } from 'react';
import { Button } from '@/components/button';
import { createEndpointAction, disableEndpointAction, drainAction } from './actions';
import { EMPTY_ALERT, type AlertState } from './state';

const field: React.CSSProperties = {
  font: 'inherit',
  fontSize: 12.5,
  width: '100%',
  padding: '8px 10px',
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
};

/**
 * The eight §5.4 events, in the order somebody would decide about them.
 *
 * The two that mean "somebody is trying something" are first and ticked by
 * default: those are the ones worth waking up for. The rest are opt-in, because
 * an endpoint subscribed to everything gets muted within a week and then the
 * important ones are muted too.
 */
const EVENTS = [
  ['risk.anomaly_detected', 'a request was refused by a risk check, not by a rule', true],
  ['workspace.locked', 'the emergency lock was thrown', true],
  ['agent.revoked', 'an agent was cut off', false],
  ['credential.revoked', 'a stored credential was destroyed', false],
  ['connection.expired', 'a connected account stopped working', false],
  ['approval.requested', 'someone needs to approve an action', false],
  ['approval.resolved', 'a pending approval was answered', false],
  ['decision.denied', 'any refusal at all — the loud one', false],
] as const;

export function AddEndpointForm() {
  const [state, action, pending] = useActionState<AlertState, FormData>(
    createEndpointAction,
    EMPTY_ALERT,
  );

  return (
    <form action={action} style={{ padding: 18, display: 'grid', gap: 16 }}>
      <label style={{ display: 'grid', gap: 6 }}>
        <span className="label">
          url <span style={{ color: 'var(--text-faint)' }}>https only</span>
        </span>
        <input
          name="url"
          type="url"
          required
          maxLength={2048}
          placeholder="https://hooks.example.com/veto"
          style={field}
        />
        <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>
          Checked before it is saved, and again before every delivery — a name that points at the
          public internet today can point somewhere private tomorrow.
        </span>
      </label>

      <fieldset style={{ border: '1px solid var(--border)', padding: '14px 16px 16px', margin: 0 }}>
        <legend className="label" style={{ color: 'var(--text-faint)', padding: '0 6px' }}>
          send which events
        </legend>
        <div style={{ display: 'grid', gap: 7 }}>
          {EVENTS.map(([value, hint, on]) => (
            <label
              key={value}
              style={{ display: 'flex', gap: 9, alignItems: 'baseline', fontSize: 12 }}
            >
              <input type="checkbox" name="events" value={value} defaultChecked={on} />
              <span>
                {value} <span style={{ color: 'var(--text-faint)' }}>— {hint}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      {/* Routing. A checkbox rather than a person picker, because the only
          value the API accepts is "me" — there is no way to ask for somebody
          else's alerts, so there is nothing to pick. */}
      <label
        style={{
          display: 'flex',
          gap: 9,
          alignItems: 'baseline',
          fontSize: 12,
          border: '1px solid var(--border)',
          padding: '12px 14px',
        }}
      >
        <input type="checkbox" name="route_to_me" value="1" />
        <span>
          only my own events
          <span style={{ color: 'var(--text-faint)' }}>
            {' '}
            — an approval can only be resolved by the person it belongs to, so send mine here and
            nobody else&rsquo;s. Leave this off and the endpoint receives the whole
            workspace&rsquo;s.
          </span>
        </span>
      </label>

      <div>
        <Button type="submit" variant="solid" disabled={pending}>
          {pending ? 'adding…' : 'add endpoint'}
        </Button>
      </div>

      {state.error ? (
        <p role="alert" style={{ margin: 0, color: 'var(--deny)', fontSize: 12 }}>
          {state.error}
        </p>
      ) : null}

      {state.notice && state.secret === null ? (
        <p role="status" style={{ margin: 0, color: 'var(--allow)', fontSize: 12 }}>
          {state.notice}
        </p>
      ) : null}

      {state.secret ? (
        <div
          role="status"
          style={{
            border: '1px solid var(--challenge)',
            background: 'var(--challenge-bg)',
            padding: '14px 16px',
            display: 'grid',
            gap: 10,
          }}
        >
          <strong style={{ color: 'var(--challenge)', fontSize: 12.5 }}>
            Copy this now. It is not shown again.
          </strong>
          <code
            style={{
              display: 'block',
              padding: '10px 12px',
              background: 'var(--bg)',
              border: '1px solid var(--border-strong)',
              fontSize: 12.5,
              wordBreak: 'break-all',
              userSelect: 'all',
            }}
          >
            {state.secret}
          </code>
          <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>
            Your receiver verifies every delivery with it. There is no route that reads it back —
            that is the point, because a secret you can re-read is a secret in every log of every
            client that ever asked. Lost it? Add the endpoint again and remove this one.
          </span>
        </div>
      ) : null}
    </form>
  );
}

export function StopEndpoint({ endpointId }: { endpointId: string }) {
  const [state, action, pending] = useActionState<AlertState, FormData>(
    disableEndpointAction,
    EMPTY_ALERT,
  );

  return (
    <form action={action} style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
      <input type="hidden" name="endpoint_id" value={endpointId} />
      <Button type="submit" variant="danger" disabled={pending} style={{ padding: '5px 11px' }}>
        {pending ? 'stopping…' : 'stop'}
      </Button>
      {state.error ? (
        <span role="alert" style={{ color: 'var(--deny)', fontSize: 11 }}>
          {state.error}
        </span>
      ) : null}
      {state.notice ? (
        <span role="status" style={{ color: 'var(--text-dim)', fontSize: 11 }}>
          {state.notice}
        </span>
      ) : null}
    </form>
  );
}

export function DeliverNow({ waiting }: { waiting: number }) {
  const [state, action, pending] = useActionState<AlertState, FormData>(drainAction, EMPTY_ALERT);

  return (
    <form
      action={action}
      style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}
    >
      <Button type="submit" variant="outline" disabled={pending}>
        {pending ? 'delivering…' : `deliver now${waiting > 0 ? ` (${waiting} waiting)` : ''}`}
      </Button>
      <span style={{ color: 'var(--text-faint)', fontSize: 11.5, maxWidth: 480 }}>
        There is no scheduler here yet, so queued events wait for this button. A page that drained
        on every render would make &ldquo;why has nothing arrived&rdquo; impossible to answer.
      </span>
      {state.error ? (
        <span role="alert" style={{ color: 'var(--deny)', fontSize: 11.5 }}>
          {state.error}
        </span>
      ) : null}
      {state.notice ? (
        <span role="status" style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>
          {state.notice}
        </span>
      ) : null}
    </form>
  );
}
