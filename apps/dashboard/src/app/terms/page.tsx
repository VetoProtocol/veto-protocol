/**
 * Terms of service. Public, and required for OAuth verification.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * NOT LEGAL ADVICE. This is a plain-language skeleton covering what Google's
 * review looks for and what the product actually does. The liability, warranty
 * and governing-law sections in particular need a lawyer, and the bracketed
 * values must be filled in before publishing.
 * ────────────────────────────────────────────────────────────────────────────
 */

import type { Metadata } from 'next';
import { H, Legal, UL } from '@/components/legal';

export const metadata: Metadata = {
  title: 'Terms — Veto Protocol',
  description: 'The terms under which Veto Protocol is provided.',
  robots: { index: true, follow: true },
};

export default function TermsPage() {
  return (
    <Legal title="Terms of service" updated="24 September 2026">
      <p>
        These terms govern your use of Veto Protocol, provided by [LEGAL ENTITY NAME]. By creating
        a workspace or connecting an account, you agree to them.
      </p>

      <H>What the service does</H>
      <p>
        Veto Protocol is an authorisation gateway. It sits between an AI assistant and the
        applications you connect, and decides on every request whether that assistant may proceed —
        allowing it, refusing it, or holding it until you approve in person. It records every
        decision.
      </p>
      <p>
        It is read-only. The service does not request permission to create, modify, send or delete
        anything in a connected application.
      </p>

      <H>Your account</H>
      <UL>
        <li>You must be old enough to enter a contract where you live.</li>
        <li>
          You are responsible for the rules you configure and the assistants you connect. The
          service enforces your policy; it does not decide it for you.
        </li>
        <li>
          Keep your sign-in and your passkeys secure. Anyone able to sign in as you can approve
          actions as you.
        </li>
        <li>
          You may only connect accounts you are entitled to connect, and only grant access to data
          you are entitled to share.
        </li>
      </UL>

      <H>Acceptable use</H>
      <p>Do not use the service to:</p>
      <UL>
        <li>access data you do not have the right to access;</li>
        <li>break any applicable law, or the terms of a connected provider;</li>
        <li>
          attempt to bypass, disable or interfere with its authorisation controls, or with the
          records it keeps;
        </li>
        <li>probe or attack the service or its infrastructure, except under an agreed test;</li>
        <li>resell or redistribute it without our written agreement.</li>
      </UL>

      <H>Connected services</H>
      <p>
        When you connect a third-party account, that provider&rsquo;s own terms continue to apply.
        We are not responsible for their availability or for changes they make. You may disconnect
        at any time, from within the product or from the provider.
      </p>
      <p>
        The purpose of the service is to deliver information to an AI assistant you choose. That
        assistant is operated by its own provider under its own terms, and what it does with what it
        receives is outside our control. Choose your assistants accordingly.
      </p>

      <H>Availability</H>
      <p>
        We aim to keep the service running and will give notice of planned maintenance where we
        reasonably can, but we do not promise uninterrupted availability.
      </p>
      <p>
        One behaviour is deliberate and worth stating: when the service cannot reach a component it
        needs in order to decide safely, it <strong>refuses</strong> the request rather than
        allowing it. Access may stop during a fault. That is the service working as designed, not
        failing.
      </p>

      <H>Your data</H>
      <p>
        Handled as described in our <a href="/privacy" style={{ color: 'var(--text)' }}>privacy policy</a>,
        which forms part of these terms. You keep all rights in your data. We claim none.
      </p>

      <H>Fees</H>
      <p>[PRICING AND BILLING TERMS, or: the service is currently provided without charge.]</p>

      <H>Suspension and termination</H>
      <p>
        You may stop using the service and delete your workspace at any time. We may suspend or end
        access if these terms are breached, if it is necessary to protect the service or other
        users, or if the law requires it — with notice where we reasonably can.
      </p>
      <p>On termination, credentials are deleted. Records are handled as set out in the privacy policy.</p>

      <H>Warranties and liability</H>
      <p>
        The service is provided &ldquo;as is&rdquo;. To the extent permitted by law we exclude
        implied warranties, and we are not liable for indirect or consequential loss, or for loss of
        profit, revenue or data.
      </p>
      <p>
        Nothing in these terms limits liability that cannot lawfully be limited. [CAP ON LIABILITY —
        NEEDS LEGAL REVIEW.]
      </p>

      <H>Changes</H>
      <p>
        We may update these terms. If a change materially affects your rights we will tell you
        before it takes effect. Continuing to use the service afterwards means accepting the revised
        terms.
      </p>

      <H>Governing law</H>
      <p>[GOVERNING LAW AND JURISDICTION.]</p>

      <H>Contact</H>
      <p>
        <a href="mailto:legal@example.com" style={{ color: 'var(--text)' }}>
          legal@example.com
        </a>
      </p>
    </Legal>
  );
}
