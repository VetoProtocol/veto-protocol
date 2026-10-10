/**
 * Agent Fingerprints — which software has been connecting as each agent.
 *
 * The question no other screen answers. `/audit` records every decision and
 * `/consent` records what each agent may reach; neither says whether the
 * *thing holding the credential* changed.
 *
 * ## The copy is part of the feature
 *
 * Everything here derives from a `User-Agent`, which the client chooses to
 * send. Somebody who steals a gateway token can send the same string. The page
 * therefore says, in plain words, that this spots a change and does not prove
 * who called — a screen implying a check it is not performing is the same
 * mistake as a comment claiming a control that does not exist, and this
 * codebase has already paid for that one.
 */

import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, listAgentFingerprints, type FingerprintView } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { JudgeClient, SetMode } from './forms';

export const dynamic = 'force-dynamic';

const cell: React.CSSProperties = {
  padding: '11px 14px 11px 0',
  borderBottom: '1px solid var(--border)',
  fontSize: 12,
  verticalAlign: 'top',
};

const head: React.CSSProperties = {
  textAlign: 'left',
  padding: '0 14px 6px 0',
  borderBottom: '1px solid var(--text)',
  fontSize: 9,
  letterSpacing: '0.14em',
  textTransform: 'uppercase',
  color: 'var(--text-dim)',
  fontWeight: 600,
};

const STATUS_TONE: Record<FingerprintView['status'], Tone> = {
  pinned: 'allow',
  seen: 'challenge',
  refused: 'deny',
};

const STATUS_WORD: Record<FingerprintView['status'], string> = {
  pinned: 'trusted',
  seen: 'undecided',
  refused: 'refused',
};

const MODE_WORD: Record<string, string> = {
  observe: 'recording only',
  challenge: 'asks you about new software',
  deny: 'refuses new software',
};

const day = (iso: string): string => iso.slice(0, 10);

/** The product, as a person would say it. `(absent)` is not a product name. */
function clientName(f: FingerprintView): string {
  if (f.product === '(absent)') return 'sent no name';
  if (f.product === '(unparsable)') return 'unrecognised name';
  return f.client_title ?? (f.channel === null ? f.product : `${f.product} (${f.channel})`);
}

/** The version span, which is a note and never an alarm. */
function versions(f: FingerprintView): string {
  if (f.last_version === null) return '—';
  if (f.first_version === null || f.first_version === f.last_version) return f.last_version;
  return `${f.first_version} → ${f.last_version}`;
}

export default async function FingerprintsPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let view;
  try {
    view = await listAgentFingerprints(session.credential);
  } catch (error) {
    // 402 is the tier, not a fault. Typing the URL on a free workspace lands
    // here — the sidebar hides the link and the API refuses the request, and
    // only the second of those is a control.
    if (error instanceof ApiError && error.failure.status === 402) {
      return (
        <Panel title="AGENT FINGERPRINTS" meta="PRO">
          <div
            style={{
              padding: '20px 22px 24px',
              color: 'var(--text-dim)',
              fontSize: 12.5,
              lineHeight: 1.75,
              maxWidth: 620,
            }}
          >
            <p style={{ margin: '0 0 10px', color: 'var(--text)' }}>
              Know when the software using an agent changes.
            </p>
            <p style={{ margin: '0 0 10px' }}>
              Every agent connects from a particular program. This records which one, when it first
              appeared and when it was last used — and can require your approval, or refuse
              outright, when something new shows up on a credential.
            </p>
            <p style={{ margin: 0 }}>
              Part of the Pro plan for this workspace.
            </p>
          </div>
        </Panel>
      );
    }

    return (
      <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
        <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
          {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
        </div>
      </Panel>
    );
  }

  const live = view.agents.filter((a) => a.status !== 'revoked');
  const undecided = view.agents.flatMap((a) => a.fingerprints.filter((f) => f.status === 'seen'));
  const enforcing = view.agents.filter((a) => a.fingerprint_mode !== 'observe').length;

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/fingerprints
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            {live.length} {live.length === 1 ? 'agent' : 'agents'}
          </h1>
          {undecided.length > 0 ? (
            <Chip tone="challenge">{`${String(undecided.length)} undecided`}</Chip>
          ) : null}
          {enforcing > 0 ? (
            <Chip tone="allow">{`${String(enforcing)} enforcing`}</Chip>
          ) : (
            <Chip tone="neutral">recording only</Chip>
          )}
        </div>

        <p style={{ color: 'var(--text-dim)', maxWidth: 680, marginTop: 12, fontSize: 12.5, lineHeight: 1.7 }}>
          Which program has been connecting as each agent. The first one an agent ever used is
          trusted automatically; anything that turns up afterwards is listed here for you to decide
          about.
        </p>
        <p style={{ color: 'var(--text-faint)', maxWidth: 680, marginTop: 8, fontSize: 11.5, lineHeight: 1.7 }}>
          <strong style={{ color: 'var(--text-dim)' }}>What this does and does not do.</strong> A
          program says what it is; nothing here can check that claim. So this reliably tells you
          when the software on a credential <em>changed</em>, and it cannot stop someone who copies
          a stolen token <em>and</em> imitates the program it was stolen from. It raises the cost of
          a stolen credential. It does not remove it.
        </p>
      </div>

      {view.agents.length === 0 ? (
        <Panel title="NOTHING YET" meta="FINGERPRINTS">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            No agents are registered in this workspace.
          </div>
        </Panel>
      ) : null}

      {view.agents.map((agent) => (
        <Panel key={agent.agent_id} title={agent.client_id.toUpperCase()} meta={agent.provider.toUpperCase()}>
          <div style={{ padding: '16px 18px 4px' }}>
            <div style={{ display: 'flex', gap: 14, alignItems: 'baseline', flexWrap: 'wrap' }}>
              <code style={{ fontSize: 11, color: 'var(--text-dim)' }}>{agent.agent_id}</code>
              {agent.status === 'revoked' ? <Chip tone="deny">revoked</Chip> : null}
              <span style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>
                {MODE_WORD[agent.fingerprint_mode] ?? agent.fingerprint_mode}
              </span>
            </div>

            <div style={{ marginTop: 12 }}>
              <SetMode agentId={agent.agent_id} current={agent.fingerprint_mode} />
            </div>
          </div>

          {agent.fingerprints.length === 0 ? (
            <div style={{ padding: '10px 18px 20px', color: 'var(--text-faint)', fontSize: 12 }}>
              Nothing has connected as this agent yet.
            </div>
          ) : (
            <div style={{ margin: '12px 18px 20px', overflowX: 'auto' }}>
              <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 620 }}>
                <thead>
                  <tr>
                    <th style={head}>client</th>
                    <th style={head}>version</th>
                    <th style={head}>first seen</th>
                    <th style={head}>last seen</th>
                    <th style={head}>requests</th>
                    <th style={head}>standing</th>
                    <th style={head} aria-label="actions" />
                  </tr>
                </thead>
                <tbody>
                  {agent.fingerprints.map((f) => (
                    <tr key={f.fingerprint}>
                      <td style={{ ...cell, color: 'var(--text)' }}>{clientName(f)}</td>
                      <td style={{ ...cell, color: 'var(--text-dim)' }}>{versions(f)}</td>
                      <td style={{ ...cell, color: 'var(--text-dim)' }}>{day(f.first_seen_at)}</td>
                      <td style={{ ...cell, color: 'var(--text-dim)' }}>{day(f.last_seen_at)}</td>
                      <td style={{ ...cell, color: 'var(--text-dim)' }}>{f.sightings}</td>
                      <td style={cell}>
                        <Chip tone={STATUS_TONE[f.status]}>{STATUS_WORD[f.status]}</Chip>
                      </td>
                      <td style={cell}>
                        <JudgeClient
                          agentId={agent.agent_id}
                          fingerprint={f.fingerprint}
                          status={f.status}
                          enforcing={agent.fingerprint_mode !== 'observe'}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      ))}
    </>
  );
}
