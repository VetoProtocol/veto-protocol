'use client';

import { useState } from 'react';

/**
 * Sign in with a wallet.
 *
 * ## The dialog is not a formality
 *
 * A wallet account cannot be recovered. There is no issuer to attest that you
 * are the same person, so a lost key is a lost workspace — and that workspace
 * holds a live grant to somebody's Drive.
 *
 * So the warning is a step, not small print beside a button. It appears before
 * the wallet is ever asked to connect, and continuing is a separate click. A
 * person who did not know that should not find out by losing everything.
 *
 * ## The message is the server's
 *
 * This asks for one and signs it. It never composes the text: a message the
 * client writes is a message the client chooses, and the wallet popup is the
 * one place the person is told what they are agreeing to.
 */

interface Ethereum {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

const wallet = (): Ethereum | null => {
  const injected = (globalThis as { ethereum?: Ethereum }).ethereum;
  return injected ?? null;
};

export function WalletSignIn() {
  const [warned, setWarned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signIn = async () => {
    setError(null);
    setBusy(true);
    try {
      const provider = wallet();
      if (!provider) {
        setError('No wallet found in this browser. Install MetaMask, then try again.');
        return;
      }

      const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as string[];
      const address = accounts[0];
      if (!address) {
        setError('No account was shared.');
        return;
      }

      const nonceResponse = await fetch('/auth/wallet/nonce', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address }),
      });
      if (!nonceResponse.ok) {
        setError('Could not start sign-in. Try again.');
        return;
      }
      const { message } = (await nonceResponse.json()) as { message: string };

      const signature = (await provider.request({
        method: 'personal_sign',
        params: [message, address],
      })) as string;

      const verified = await fetch('/auth/wallet/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address, message, signature }),
      });

      if (!verified.ok) {
        const body = (await verified.json().catch(() => ({}))) as { error?: string };
        setError(body.error ?? 'That did not complete.');
        return;
      }

      const { next } = (await verified.json()) as { next: string };
      globalThis.location.assign(next);
    } catch {
      // A rejected prompt and a failed one look the same from here, and the
      // difference is not the person's problem.
      setError('That did not complete. Try again.');
    } finally {
      setBusy(false);
    }
  };

  if (!warned) {
    return (
      <div style={{ display: 'grid', gap: 12 }}>
        <button type="button" onClick={() => setWarned(true)} style={outline}>
          Continue with MetaMask
        </button>
        {error ? <p style={errorText}>{error}</p> : null}
      </div>
    );
  }

  return (
    <div
      role="alertdialog"
      aria-label="Before you use a wallet"
      style={{
        border: '1px solid var(--challenge)',
        background: 'var(--bg-raised)',
        padding: '16px 18px',
        display: 'grid',
        gap: 12,
        textAlign: 'left',
      }}
    >
      <strong style={{ fontSize: 13, fontWeight: 500 }}>
        A wallet-only account can&rsquo;t be recovered.
      </strong>
      <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.7 }}>
        Lose the key and you lose the workspace &mdash; including any connected accounts inside it.
        Nobody can reset it, because nobody can vouch that you are the same person.
      </p>
      <p style={{ margin: 0, color: 'var(--text-faint)', fontSize: 11.5, lineHeight: 1.7 }}>
        Signing in with Google instead gives you an account that can be recovered.
      </p>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <button type="button" onClick={signIn} disabled={busy} style={solid}>
          {busy ? 'waiting for your wallet…' : 'I understand — continue'}
        </button>
        <button type="button" onClick={() => setWarned(false)} disabled={busy} style={outline}>
          Cancel
        </button>
      </div>
      {error ? <p style={errorText}>{error}</p> : null}
    </div>
  );
}

const base: React.CSSProperties = {
  font: 'inherit',
  fontSize: 12.5,
  padding: '10px 16px',
  cursor: 'pointer',
};

const outline: React.CSSProperties = {
  ...base,
  background: 'transparent',
  border: '1px solid var(--border-strong)',
  color: 'var(--text)',
};

const solid: React.CSSProperties = {
  ...base,
  background: 'var(--text)',
  border: '1px solid var(--text)',
  color: 'var(--bg)',
};

const errorText: React.CSSProperties = {
  margin: 0,
  color: 'var(--deny)',
  fontSize: 11.5,
};
