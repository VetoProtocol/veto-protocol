/**
 * The privacy policy. Public, and required.
 *
 * Google will fetch this during OAuth verification and read it against the
 * Limited Use requirements, so it names Google user data specifically rather
 * than describing "your information" in the abstract. A generic template does
 * not pass review.
 *
 * The root layout sets `robots: noindex` because authorization state is not for
 * search engines. This page overrides that: it is meant to be found.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * NOT LEGAL ADVICE. The factual claims below are accurate to how this system
 * behaves today — every one of them is checkable against the code, and the
 * comments say where. The wording still needs a lawyer before you publish it,
 * and the bracketed values must be filled in.
 * ────────────────────────────────────────────────────────────────────────────
 */

import type { Metadata } from 'next';
import { H, Legal, UL } from '@/components/legal';

export const metadata: Metadata = {
  title: 'Privacy — Veto Protocol',
  description: 'What Veto Protocol accesses, what it stores, and what it never stores.',
  robots: { index: true, follow: true },
};

export default function PrivacyPage() {
  return (
    <Legal title="Privacy policy" updated="24 September 2026">
      <p>
        Veto Protocol sits between an AI assistant and the applications you connect to it, and
        decides — on every single request — whether that assistant may do what it is asking to do.
        This policy explains what that involves for your data.
      </p>
      <p>
        It is written to be specific. Where we say we do not store something, that means the system
        has no place to put it, not that we have chosen not to look.
      </p>

      <H>Who we are</H>
      <p>
        [LEGAL ENTITY NAME], [ADDRESS]. Questions about this policy or about your data:{' '}
        <a href="mailto:privacy@example.com" style={{ color: 'var(--text)' }}>
          privacy@example.com
        </a>
        .
      </p>

      <H>What we access</H>
      <p>When you sign in, we receive your email address, name and a stable account identifier.</p>
      <p>
        When you connect a Google service, we request <strong>read-only</strong> access to that one
        service, and only when you activate it. Connecting Drive does not give us your email.
      </p>
      <UL>
        <li>
          <code>drive.readonly</code> — so an assistant you authorise can list and read files you
          have granted it
        </li>
        <li>
          <code>gmail.readonly</code> — so it can search your mailbox and read messages you have
          granted it
        </li>
        <li>
          <code>calendar.readonly</code> — so it can list and read events you have granted it
        </li>
      </UL>
      <p>
        We never request write, send or delete permission for any of these services. The product
        cannot modify your data because it never asks to be able to.
      </p>

      <H>What we store</H>
      <UL>
        <li>Your account identifier, email and name.</li>
        <li>
          An encrypted credential for each service you connect, so an assistant can act while you
          are not watching. It is encrypted with a key scoped to your workspace.
        </li>
        <li>
          The rules and grants you configure — which assistant may do what, to which resource, under
          which conditions.
        </li>
        <li>
          A record of every decision: the time, the assistant, the action, which resource was named,
          the answer, and the reason for it.
        </li>
      </UL>

      <H>What we never store</H>
      <p>This is the part worth reading twice.</p>
      <UL>
        <li>
          <strong>We do not store the contents of your files, messages or events.</strong> When an
          assistant is allowed to read something, the content travels from Google through the
          gateway to that assistant and is not written down anywhere on the way.
        </li>
        <li>
          <strong>Content cannot enter our audit trail.</strong> Not by policy — by construction.
          The record of a decision has no field capable of holding a document body, a message body,
          a credential or a passkey challenge.
          {/* invariant 5: AuditEventInput is the control. */}
        </li>
        <li>
          <strong>We never hand back a stored credential.</strong> The credential store has no
          field that can return one; it issues a short-lived, narrowly scoped token for one action
          and nothing else.
          {/* packages/connections: Connection has no refresh-token field, deliberately. */}
        </li>
        <li>
          <strong>No location or network data.</strong> There is no field anywhere in this product
          for an IP address or a location, and presence is never inferred from one.
        </li>
      </UL>

      <H>Google user data, and the Limited Use requirements</H>
      <p>
        Our use of information received from Google APIs adheres to the{' '}
        <a
          href="https://developers.google.com/terms/api-services-user-data-policy"
          style={{ color: 'var(--text)' }}
        >
          Google API Services User Data Policy
        </a>
        , including the Limited Use requirements. Specifically:
      </p>
      <UL>
        <li>We do not sell Google user data, and we never will.</li>
        <li>We do not use it for advertising of any kind.</li>
        <li>
          We do not use it to develop, improve or train generalised artificial-intelligence or
          machine-learning models. Your data is used to carry out the request you authorised, and
          for nothing else.
        </li>
        <li>
          Humans do not read it, except where you have explicitly asked us to, where it is necessary
          for security purposes or to comply with applicable law, or where the data is aggregated
          and anonymised.
        </li>
      </UL>

      <H>Where your data goes</H>
      <p>
        The purpose of this product is to pass information to an AI assistant that you choose and
        connect. When you authorise a request, the content of what was requested is delivered to
        that assistant — which is operated by whoever makes it, not by us, under their terms and
        their privacy policy.
      </p>
      <p>
        This is the point of the product and it is worth being plain about: we do not control what
        your assistant does with what it receives. What we control is whether it receives anything
        at all, on what terms, and whether you can see and stop it. Every request is decided
        individually, recorded, and refusable.
      </p>
      <p>
        Beyond that, we share data only with the infrastructure providers that run the service, and
        where the law requires it.
      </p>

      <H>How long we keep it</H>
      <UL>
        <li>Credentials: until you disconnect the service, or the account is closed.</li>
        <li>
          Decision records: retained as a security log, because an audit trail you can delete
          piecemeal is not an audit trail. Removed when the workspace is deleted.
        </li>
        <li>Rules and grants: until you delete them.</li>
      </UL>

      <H>Your control</H>
      <UL>
        <li>
          <strong>Disconnect a service</strong> at any time from Connections. Access stops
          immediately.
        </li>
        <li>
          <strong>Revoke an assistant</strong> from Agents. Its access ends everywhere within
          seconds, including sessions already running.
        </li>
        <li>
          <strong>Emergency lock</strong> from Presence. Everything stops at once.
        </li>
        <li>
          <strong>Delete your workspace</strong> by writing to the address above. Credentials and
          records are removed.
        </li>
        <li>
          You may also revoke our access directly from your{' '}
          <a href="https://myaccount.google.com/permissions" style={{ color: 'var(--text)' }}>
            Google account permissions
          </a>{' '}
          page.
        </li>
      </UL>
      <p>
        Depending on where you live you may also have rights to access, correct, export or erase
        your personal data. Write to the address above and we will answer.
      </p>

      <H>Security</H>
      <p>
        Credentials are encrypted at rest with a key scoped to your workspace. Every request is
        authorised individually against your rules before anything is fetched. Sensitive actions can
        require a passkey — your fingerprint, face or security key — and only the person who
        delegated the access can approve them. Records are tamper-evident.
      </p>
      <p>
        No system is perfect. If you believe you have found a security problem, please write to{' '}
        <a href="mailto:security@example.com" style={{ color: 'var(--text)' }}>
          security@example.com
        </a>
        .
      </p>

      <H>Changes</H>
      <p>
        If we change this policy in a way that materially affects how your data is handled, we will
        tell you before it takes effect. The date at the top always reflects the current version.
      </p>
    </Legal>
  );
}
