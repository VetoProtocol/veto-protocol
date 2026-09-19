import { notFound, redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, getDecision, type DecisionView } from '@/lib/api';
import { currentSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

const TONE: Record<string, Tone> = {
  allow: 'allow',
  challenge: 'challenge',
  deny: 'deny',
  unavailable: 'deny',
  not_evaluated: 'neutral',
};

/**
 * The nine steps of §3.3, and which of them owns each one.
 *
 * Steps 3, 4 and 6 are Veto's own authority and sit outside Permit
 * (invariant 3) — showing the owner beside each step is the clearest way to
 * make that visible to somebody who has only been told it.
 *
 * `stage` maps a reason code back to the step that produced it. Two steps have
 * no code of their own: normalisation refuses with an argument error the
 * precheck stage owns, and the audit write cannot fail the request.
 */
const STEPS: ReadonlyArray<{
  n: number;
  title: string;
  owner: 'Veto' | 'Permit';
  stage: string | null;
  detail: string;
}> = [
  {
    n: 1,
    title: 'Identity resolved',
    owner: 'Veto',
    stage: 'identity',
    detail: 'human, agent and session bound',
  },
  {
    n: 2,
    title: 'Action normalised',
    owner: 'Veto',
    stage: null,
    detail: 'arguments validated against a strict schema',
  },
  {
    n: 3,
    title: 'Session, presence, lock',
    owner: 'Veto',
    stage: 'session',
    detail: 'checked before policy is consulted',
  },
  {
    n: 4,
    title: 'Deterministic prechecks',
    owner: 'Veto',
    stage: 'precheck',
    detail: 'tool allowlist, resource scope, volume',
  },
  {
    n: 5,
    title: 'permit.check',
    owner: 'Permit',
    stage: 'policy',
    detail: 'relationship and attributes only',
  },
  {
    n: 6,
    title: 'Veto risk checks',
    owner: 'Veto',
    stage: 'risk',
    detail: 'intent, sensitive arguments, destination',
  },
  {
    n: 7,
    title: 'Result emitted',
    owner: 'Veto',
    stage: 'approval',
    detail: 'allow, deny or challenge',
  },
  {
    n: 8,
    title: 'Upstream call',
    owner: 'Veto',
    stage: 'credential',
    detail: 'narrowest token, exactly what was approved',
  },
  {
    n: 9,
    title: 'Audit written',
    owner: 'Veto',
    stage: null,
    detail: 'hash chained to its predecessor',
  },
];

export default async function DecisionPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  const { id } = await params;

  let decision: DecisionView;
  try {
    decision = await getDecision(session.credential, id);
  } catch (error) {
    if (error instanceof ApiError && error.failure.status === 404) notFound();
    return (
      <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
        <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
          {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
        </div>
      </Panel>
    );
  }

  const stoppedAt =
    STEPS.find((s) => s.stage !== null && s.stage === decision.reason_stage)?.n ?? null;
  const allowed = decision.veto_result === 'allow';

  /** What happened at a step, given where the decision came out. */
  const statusOf = (n: number): { word: string; tone: Tone } => {
    if (stoppedAt !== null && n === stoppedAt) {
      return {
        word: allowed ? 'passed' : decision.veto_result === 'deny' ? 'stopped' : 'held',
        tone: TONE[decision.veto_result] ?? 'neutral',
      };
    }
    if (stoppedAt !== null && n > stoppedAt && !allowed) return { word: 'not reached', tone: 'neutral' };
    // Step 8 only runs on an allow, whatever else happened.
    if (n === 8 && !allowed) return { word: 'not reached', tone: 'neutral' };
    return { word: 'passed', tone: 'allow' };
  };

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/decisions/{decision.id}
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            {decision.veto_result === 'allow'
              ? 'Allowed'
              : decision.veto_result === 'deny'
                ? 'Denied'
                : 'Challenged'}
          </h1>
          <Chip tone={TONE[decision.veto_result] ?? 'neutral'}>{decision.reason_code}</Chip>
        </div>
        <p style={{ color: 'var(--text-dim)', maxWidth: 680, marginTop: 12, fontSize: 12.5 }}>
          {decision.agent_id} asked to {decision.action}{' '}
          <span style={{ color: 'var(--text)' }}>{decision.resource_ref ?? 'a resource'}</span> using{' '}
          {decision.tool}. {decision.reason_message}
          {allowed ? '' : ' Nothing was sent upstream.'}
        </p>
      </div>

      <div
        style={{
          display: 'grid',
          gap: 18,
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          alignItems: 'start',
        }}
      >
        <Panel
          title="PIPELINE"
          meta={`9 STEPS${decision.latency_ms === null ? '' : ` · ${decision.latency_ms} MS TOTAL`}`}
        >
          <div>
            {STEPS.map((step) => {
              const status = statusOf(step.n);
              const here = step.n === stoppedAt;
              return (
                <div
                  key={step.n}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 14,
                    padding: '12px 18px',
                    borderTop: '1px solid var(--border)',
                    background: here ? 'var(--bg-raised)' : 'transparent',
                  }}
                >
                  <span
                    style={{
                      color: 'var(--text-faint)',
                      fontSize: 11,
                      flex: '0 0 14px',
                      paddingTop: 2,
                    }}
                  >
                    {step.n}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: 12.5 }}>{step.title}</span>
                    <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
                      {' · '}
                      {step.owner}
                    </span>
                    <div style={{ color: 'var(--text-dim)', fontSize: 11.5, marginTop: 3 }}>
                      {step.detail}
                    </div>
                  </div>
                  <span
                    style={{
                      fontSize: 11,
                      whiteSpace: 'nowrap',
                      color:
                        status.tone === 'neutral' ? 'var(--text-faint)' : `var(--${status.tone})`,
                    }}
                  >
                    {status.word}
                  </span>
                </div>
              );
            })}
          </div>
          <div
            style={{
              borderTop: '1px solid var(--border)',
              padding: '12px 18px',
              color: 'var(--text-faint)',
              fontSize: 11,
              lineHeight: 1.7,
            }}
          >
            {/* Said plainly rather than shown as nine invented numbers. The
                pipeline measures itself end to end; per-step timing is
                instrumentation that does not exist yet. */}
            Only the total is measured. Which step decided is derived from the reason code — the
            per-step timings a full trace would show are not recorded yet.
          </div>
        </Panel>

        <Panel title="RECORD" meta={decision.id.replace(/^dec_/, '')}>
          <dl style={{ margin: 0, padding: '14px 18px', display: 'grid', gap: 10, fontSize: 11.5 }}>
            <Row label="permit_result">
              <Chip tone={TONE[decision.permit_result] ?? 'neutral'}>{decision.permit_result}</Chip>
            </Row>
            <Row label="veto_result">
              <Chip tone={TONE[decision.veto_result] ?? 'neutral'}>{decision.veto_result}</Chip>
            </Row>
            <div
              style={{
                color: 'var(--text-faint)',
                fontSize: 11,
                lineHeight: 1.7,
                borderBottom: '1px solid var(--border)',
                paddingBottom: 10,
              }}
            >
              Both are stored. Permit answers one question; the decision is Veto&rsquo;s.
            </div>
            <Row label="policy version">{decision.policy_version ?? '—'}</Row>
            <Row label="correlation">{decision.request_id}</Row>
            <Row label="agent">{decision.agent_id}</Row>
            <Row label="on behalf of">{decision.human_id}</Row>
            <Row label="at">{decision.created_at.replace('T', ' ').slice(0, 19)}</Row>
          </dl>
        </Panel>
      </div>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
      <dt style={{ color: 'var(--text-dim)', flex: '0 0 96px' }}>{label}</dt>
      <dd style={{ margin: 0, flex: 1, minWidth: 0, wordBreak: 'break-all' }}>{children}</dd>
    </div>
  );
}
