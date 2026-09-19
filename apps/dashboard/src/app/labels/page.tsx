import { redirect } from 'next/navigation';
import { Nav } from '@/components/nav';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, listLabels, type LabelView } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { RemoveLabel, SetLabelForm } from './forms';

export const dynamic = 'force-dynamic';

/**
 * The chip tone tracks how much a level restricts, not how alarming it sounds.
 * `public` and `internal` add nothing, so they are neutral rather than green —
 * green would read as "allowed", and a label never allows anything.
 */
const TONE: Record<LabelView['sensitivity'], Tone> = {
  public: 'neutral',
  internal: 'neutral',
  confidential: 'challenge',
  restricted: 'deny',
};

const ADDS: Record<LabelView['sensitivity'], string> = {
  public: 'nothing',
  internal: 'nothing',
  confidential: 'you must be at your desk',
  restricted: 'at your desk, and state a purpose',
};

export default async function LabelsPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let labels;
  try {
    labels = (await listLabels(session.credential)).labels;
  } catch (error) {
    return (
      <>
        <Nav active="labels" />
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  // Longest pattern first, which is the order the matcher resolves them in.
  // Showing them any other way would misrepresent which one wins.
  const ordered = [...labels].sort(
    (a, b) => Number(b.exact) - Number(a.exact) || b.pattern.length - a.pattern.length,
  );

  const protecting = labels.filter(
    (l) => l.sensitivity === 'confidential' || l.sensitivity === 'restricted',
  ).length;

  return (
    <>
      <Nav active="labels" />

      <Panel title="LABELS" meta="SENSITIVITY / §4.2">
        <div style={{ padding: '22px 18px 6px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/labels
          </p>
          <h1 className="headline" style={{ fontSize: 30 }}>
            {protecting} protected
            <span style={{ color: 'var(--text-faint)' }}> · {labels.length} labelled</span>
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 12, fontSize: 12.5 }}>
            A label marks how protected something is, so you say it once instead of repeating it in
            every rule. It only ever <span style={{ color: 'var(--text)' }}>adds</span> a
            requirement — nothing here grants access, and a resource no rule allows stays denied
            whatever it is labelled.
          </p>
        </div>

        {ordered.length === 0 ? (
          <div
            style={{
              margin: '4px 18px 22px',
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            Nothing is labelled. Sensitive resources are whatever your rules happen to guard.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <caption className="label" style={{ textAlign: 'left', padding: '10px 18px 6px' }}>
                Most specific first — that is the one that applies
              </caption>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)' }}>
                  {['', 'resource', 'match', 'level', 'adds', 'note', ''].map((h, i) => (
                    <th
                      key={i}
                      scope="col"
                      className="label"
                      style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 400 }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ordered.map((label, index) => (
                  <tr key={label.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 14px', color: 'var(--text-faint)', width: 40 }}>
                      {String(index + 1).padStart(2, '0')}
                    </td>
                    <th
                      scope="row"
                      style={{
                        padding: '12px 14px',
                        textAlign: 'left',
                        fontWeight: 400,
                        wordBreak: 'break-all',
                      }}
                    >
                      {label.pattern}
                      <span style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}>
                        {label.resource_type}
                      </span>
                    </th>
                    <td
                      style={{ padding: '12px 14px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}
                    >
                      {label.exact ? 'exact' : 'and below'}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <Chip tone={TONE[label.sensitivity]}>{label.sensitivity}</Chip>
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {ADDS[label.sensitivity]}
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {label.note ?? '—'}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <RemoveLabel labelId={label.id} pattern={label.pattern} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="APPLY A LABEL" meta="ADDS A REQUIREMENT">
        <SetLabelForm />
      </Panel>

      <Panel title="HOW MATCHING WORKS" meta="MOST SPECIFIC WINS">
        <div style={{ padding: 18, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.8 }}>
          <p style={{ margin: '0 0 12px' }}>
            The longest match applies, so a narrower label can be less restrictive than a broader
            one without the answer depending on what order you added them in:
          </p>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            <li>
              <span style={{ color: 'var(--text)' }}>/Finance</span> marked confidential — the whole
              folder needs you present
            </li>
            <li>
              <span style={{ color: 'var(--text)' }}>/Finance/Public</span> marked public — the menu
              in there does not
            </li>
            <li>
              <span style={{ color: 'var(--text)' }}>/Finance/payroll.csv</span> marked restricted,
              exact — that one file needs a stated purpose too
            </li>
          </ul>
          <p style={{ margin: '12px 0 0' }}>
            Where a rule and a label both ask about presence, the stricter of the two applies. A
            loose label cannot undo a strict rule.
          </p>
        </div>
      </Panel>
    </>
  );
}
