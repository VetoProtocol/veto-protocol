'use client';

import { useState, useTransition } from 'react';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { Button } from '@/components/button';
import { Chip } from '@/components/chip';
import type { PendingApproval } from '@/lib/api';
import {
  completeRegistration,
  fetchApprovalChallenge,
  fetchRegistrationOptions,
  submitResolution,
} from './actions';

/**
 * Enrolment.
 *
 * The browser talks to the authenticator; the server decides whether what comes
 * back is acceptable. Nothing here validates anything — a check in the page
 * would be a check an attacker skips by not using the page.
 */
export function EnrolPasskey({ hasAny }: { hasAny: boolean }) {
  const [message, setMessage] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [label, setLabel] = useState('');
  const [pending, start] = useTransition();

  const enrol = () => {
    setMessage(null);
    start(async () => {
      try {
        const options = await fetchRegistrationOptions();
        const response = await startRegistration({ optionsJSON: options as never });
        const result = await completeRegistration(response, label);
        setFailed(!result.ok);
        setMessage(result.message);
      } catch {
        // A cancelled prompt and a failed one look the same from here, and the
        // distinction is not the user's problem.
        setFailed(true);
        setMessage('That did not complete. Try again.');
      }
    });
  };

  return (
    <div style={{ padding: 18, display: 'grid', gap: 14 }}>
      <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.7, maxWidth: 620 }}>
        {hasAny
          ? 'Add another device. One passkey is one lost phone away from being unable to approve anything.'
          : 'You need a passkey before you can approve anything. Without one, an approval could be granted by anyone holding your session — which is the thing this is for.'}
      </p>

      <label style={{ display: 'grid', gap: 6, maxWidth: 320 }}>
        <span className="label">name this device</span>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          maxLength={80}
          placeholder="MacBook Touch ID"
          style={{
            font: 'inherit', fontSize: 12.5, padding: '8px 10px',
            background: 'var(--bg-input)', border: '1px solid var(--border)', color: 'var(--text)',
          }}
        />
      </label>

      <div aria-live="polite" style={{ minHeight: 18, fontSize: 12 }}>
        {message ? (
          <span style={{ color: failed ? 'var(--deny)' : 'var(--allow)' }}>{message}</span>
        ) : null}
      </div>

      <div>
        <Button type="button" variant={hasAny ? 'outline' : 'solid'} onClick={enrol} disabled={pending}>
          {pending ? 'waiting for your device…' : 'Enrol a passkey'}
        </Button>
      </div>
    </div>
  );
}

/**
 * Resolving one approval.
 *
 * The challenge comes from the server and is the one stored on the approval, so
 * the signature is over *that* approval. Both answers require it: a refusal
 * that needed no proof would let anyone holding the link deny something the
 * real user wanted.
 */
export function ResolveApproval({ approval }: { approval: PendingApproval }) {
  const [message, setMessage] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [pending, start] = useTransition();

  const resolve = (decision: 'approved' | 'denied') => {
    setMessage(null);
    start(async () => {
      try {
        const options = await fetchApprovalChallenge(approval.id);
        const assertion = await startAuthentication({ optionsJSON: options as never });
        const result = await submitResolution(approval.id, decision, assertion);
        setFailed(!result.ok);
        setMessage(result.message);
      } catch {
        setFailed(true);
        setMessage('That did not complete. Try again.');
      }
    });
  };

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div aria-live="polite" style={{ minHeight: 16, fontSize: 11.5 }}>
        {message ? (
          <span style={{ color: failed ? 'var(--deny)' : 'var(--allow)' }}>{message}</span>
        ) : null}
      </div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <Button type="button" variant="solid" onClick={() => resolve('approved')} disabled={pending}>
          {pending ? 'waiting for your device…' : 'Approve with passkey'}
        </Button>
        <Button type="button" variant="danger" onClick={() => resolve('denied')} disabled={pending}>
          Deny
        </Button>
      </div>
    </div>
  );
}

export function Expiry({ at }: { at: string }) {
  const minutes = Math.max(0, Math.round((new Date(at).getTime() - Date.now()) / 60_000));
  return <Chip tone={minutes <= 1 ? 'deny' : 'challenge'}>{`expires in ${minutes} min`}</Chip>;
}
