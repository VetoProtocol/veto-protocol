import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'solid' | 'outline' | 'danger';

const VARIANTS: Record<Variant, React.CSSProperties> = {
  // The filled light button, as on "Start building".
  solid: { background: 'var(--text)', color: 'var(--bg)', border: '1px solid var(--text)' },
  outline: { background: 'transparent', color: 'var(--text)', border: '1px solid var(--border-strong)' },
  // Destructive actions wear the deny colour and never the solid treatment, so
  // "revoke" can never be the button a hand lands on by momentum.
  danger: { background: 'transparent', color: 'var(--deny)', border: '1px solid var(--deny)' },
};

export function Button({
  variant = 'outline',
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; children: ReactNode }) {
  return (
    <button
      {...rest}
      style={{
        font: 'inherit',
        fontSize: 12,
        letterSpacing: '0.02em',
        padding: '8px 16px',
        cursor: rest.disabled ? 'not-allowed' : 'pointer',
        opacity: rest.disabled ? 0.45 : 1,
        ...VARIANTS[variant],
        ...rest.style,
      }}
    >
      {children}
    </button>
  );
}
