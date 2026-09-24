'use client';

/**
 * The agreement dialogue.
 *
 * Shown to a signed-in person who has not accepted the current published
 * versions. Three decisions worth stating, because each was the alternative to
 * something easier and worse:
 *
 * **It blocks.** There is no dismiss, no "later", no close button. A consent
 * notice you can wave away has not collected consent, and the whole product is
 * an argument that agreement should be explicit. The way out is to sign out,
 * which is offered.
 *
 * **It does not cover the documents themselves.** Being asked to agree to a
 * text you cannot open would be absurd, so the gate hides itself on `/privacy`
 * and `/terms` — go and read them, come back, the dialogue returns. It also
 * stays out of the way of the signed-out and consent screens, which have their
 * own job.
 *
 * **It traps focus and is announced.** It is a real `alertdialog`: Escape does
 * nothing (there is nothing to escape to), Tab stays inside it, and focus moves
 * to it on open. A modal that a keyboard can walk out of is a modal that keeps
 * none of its promises.
 */

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { acceptLegalAction } from '@/app/legal-actions';
import { Mark } from '@/components/mark';

/** Pages the gate must never cover. */
const EXEMPT = ['/privacy', '/terms', '/signed-out', '/welcome', '/choose', '/authorize'];

export function LegalGate({ outstanding }: { outstanding: readonly string[] }) {
  const pathname = usePathname();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialog = useRef<HTMLDivElement>(null);

  const exempt = EXEMPT.some((p) => pathname === p || pathname.startsWith(`${p}/`));
  const show = outstanding.length > 0 && !exempt;

  useEffect(() => {
    if (!show) return;

    dialog.current?.focus();

    // Keep Tab inside. Without this the person can tab into the page behind and
    // operate a product they have not agreed to the terms of.
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;
      const focusable = dialog.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled])',
      );
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKey);
    // The page behind must not scroll while this is up.
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previous;
    };
  }, [show]);

  if (!show) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        background: 'rgba(0, 0, 0, 0.72)',
        backdropFilter: 'blur(3px)',
        display: 'grid',
        placeItems: 'center',
        padding: 24,
      }}
    >
      <div
        ref={dialog}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="legal-gate-title"
        aria-describedby="legal-gate-body"
        tabIndex={-1}
        style={{
          width: 520,
          maxWidth: '100%',
          border: '1px solid var(--border-strong)',
          background: 'var(--bg-panel)',
          padding: '30px 32px 28px',
          outline: 'none',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text)' }}>
          <Mark size={20} />
          <span style={{ fontSize: 14, letterSpacing: '0.02em' }}>veto</span>
        </div>

        <h2
          id="legal-gate-title"
          className="headline"
          style={{ fontSize: 24, margin: '22px 0 0', letterSpacing: '-0.028em' }}
        >
          Before you continue
        </h2>

        <p
          id="legal-gate-body"
          style={{ margin: '14px 0 0', fontSize: 13, lineHeight: 1.7, color: 'var(--text-dim)' }}
        >
          Veto reads the accounts you connect on behalf of the assistants you authorise. Please
          read and agree to the{' '}
          <Link href="/terms" style={{ color: 'var(--text)', textDecoration: 'underline' }}>
            terms of service
          </Link>{' '}
          and the{' '}
          <Link href="/privacy" style={{ color: 'var(--text)', textDecoration: 'underline' }}>
            privacy policy
          </Link>
          . They open in this window, and this will be here when you come back.
        </p>

        {error ? (
          <p
            role="alert"
            style={{
              margin: '18px 0 0',
              padding: '10px 12px',
              border: '1px solid var(--deny)',
              background: 'var(--deny-bg)',
              color: 'var(--deny)',
              fontSize: 12.5,
            }}
          >
            {error}
          </p>
        ) : null}

        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 26 }}>
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              setPending(true);
              setError(null);
              void acceptLegalAction().then((result) => {
                if (!result.ok) {
                  setError(result.error);
                  setPending(false);
                }
                // On success the layout re-renders without the gate; leaving
                // `pending` set avoids a flash of the enabled button first.
              });
            }}
            style={{
              padding: '10px 20px',
              border: '1px solid var(--text)',
              background: 'var(--text)',
              color: 'var(--bg)',
              font: 'inherit',
              fontSize: 13,
              cursor: pending ? 'default' : 'pointer',
              opacity: pending ? 0.6 : 1,
            }}
          >
            {pending ? 'recording…' : 'I agree'}
          </button>

          {/* The only other way out. Not a dismissal — a decision not to use it. */}
          <form action="/logout" method="post">
            <button
              type="submit"
              style={{
                padding: '10px 4px',
                border: 'none',
                background: 'none',
                color: 'var(--text-dim)',
                font: 'inherit',
                fontSize: 12.5,
                cursor: 'pointer',
                textDecoration: 'underline',
              }}
            >
              Sign out instead
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
