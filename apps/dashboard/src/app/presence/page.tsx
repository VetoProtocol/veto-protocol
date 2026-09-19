import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip } from '@/components/chip';
import { ApiError, getEmergencyLock, getPresence } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { PresenceControls, EmergencyLock } from './controls';

export const dynamic = 'force-dynamic';

/** §7.2, in the order they narrow: what each state actually costs you. */
const STATES = [
  ['active', 'Low-risk actions inside scope are allowed.'],
  ['away', 'Sensitive reads and every write require approval.'],
  ['locked', 'Everything is denied.'],
  ['automation', 'Only the named workflow, tools, resources and limits.'],
] as const;

export default async function PresencePage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let presence;
  let locked: boolean;
  try {
    // The lock is workspace-wide; presence is per person. Both are read here so
    // the page never shows one without the other.
    const [p, lock] = await Promise.all([
      getPresence(session.credential),
      getEmergencyLock(session.credential),
    ]);
    presence = p;
    locked = lock.locked;
  } catch (error) {
    return (
      <>
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/presence
        </p>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 16, flexWrap: 'wrap' }}>
          <h1 className="headline" style={{ fontSize: 30, margin: 0, textTransform: 'capitalize' }}>
            {presence.state}
          </h1>
          <span style={{ color: 'var(--text-faint)', fontSize: 12.5 }}>
            · since {presence.changed_at.slice(11, 16)} UTC
          </span>
          <Chip tone="neutral">{`${presence.assurance} assurance`}</Chip>
        </div>
        <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 12, fontSize: 12.5 }}>
          Presence is a signal, never proof of intent. It is never inferred from IP address or
          geolocation, and it can never authorise on its own.
          {presence.expires_at === null
            ? ' This state does not expire.'
            : ` Decays to away at ${presence.expires_at.slice(11, 16)} UTC.`}
        </p>
      </div>

      <Panel title="PRESENCE" meta="STATE MACHINE">
        <div style={{ padding: 18 }}>
          {/* The four §7.2 states side by side, with the live one lit. Showing
              all four at once is the point: what each state costs you is the
              thing somebody needs before they choose one. */}
          <div
            style={{
              display: 'grid',
              gap: 12,
              gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
            }}
          >
            {STATES.map(([state, meaning]) => {
              const on = state === presence.state;
              return (
                <div
                  key={state}
                  {...(on ? { 'aria-current': 'true' as const } : {})}
                  style={{
                    border: `1px solid ${on ? 'var(--text)' : 'var(--border)'}`,
                    background: on ? 'var(--bg-raised)' : 'transparent',
                    padding: '14px 16px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span
                      aria-hidden="true"
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        background: on ? 'var(--text)' : 'var(--border-strong)',
                      }}
                    />
                    <span style={{ fontSize: 12.5, color: on ? 'var(--text)' : 'var(--text-dim)' }}>
                      {state}
                    </span>
                  </div>
                  <div
                    style={{
                      color: 'var(--text-dim)',
                      fontSize: 11.5,
                      marginTop: 9,
                      lineHeight: 1.6,
                    }}
                  >
                    {meaning}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <PresenceControls current={presence.state} />
      </Panel>

      <Panel title="EMERGENCY LOCK" meta="WORKSPACE-WIDE">
        <div style={{ padding: 18 }}>
          <div style={{ display: 'flex', gap: 24, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <p
              style={{
                flex: '1 1 320px',
                margin: 0,
                color: 'var(--text-dim)',
                fontSize: 12.5,
                lineHeight: 1.7,
              }}
            >
              Denies every protected action in this workspace immediately, kills every approved
              request still outstanding, and drops every live agent session. Checked at step 3 of
              the pipeline — before policy is consulted, so an in-flight session cannot outrun it.
              <br />
              <br />
              Unlocking is not the reverse. It lets people ask again; it does not hand back what
              the lock took.
            </p>
            <div style={{ width: 280, flex: '0 0 280px' }}>
              <EmergencyLock locked={locked} />
              <div style={{ color: 'var(--text-faint)', fontSize: 11, marginTop: 10 }}>
                takes effect on the next request, within five seconds
              </div>
            </div>
          </div>
        </div>
      </Panel>
    </>
  );
}
