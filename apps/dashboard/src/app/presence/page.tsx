import { redirect } from 'next/navigation';
import { Nav } from '@/components/nav';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, getEmergencyLock, getPresence } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { PresenceControls, EmergencyLock } from './controls';

export const dynamic = 'force-dynamic';

const TONE: Record<string, Tone> = {
  active: 'allow',
  away: 'challenge',
  locked: 'deny',
  automation: 'neutral',
};

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
        <Nav active="presence" />
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
      <Nav active="presence" />

      <Panel title="PRESENCE" meta="SIGNAL / NOT PROOF">
        <div style={{ padding: '22px 18px 6px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/presence
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <h1 className="headline" style={{ fontSize: 30 }}>
              You are {presence.state}
            </h1>
            <Chip tone={TONE[presence.state] ?? 'neutral'}>{presence.state}</Chip>
            <Chip tone="neutral">{`${presence.assurance} assurance`}</Chip>
          </div>
          <p style={{ color: 'var(--text-dim)', maxWidth: 640, marginTop: 12, fontSize: 12.5 }}>
            Presence tells a policy which of its rules applies. It never grants anything on its own,
            and it is never inferred from your address or location.
            {presence.expires_at === null
              ? ' This state does not expire.'
              : ` Decays to away at ${presence.expires_at.slice(11, 16)} UTC.`}
          </p>
        </div>
        <PresenceControls current={presence.state} />
      </Panel>

      <Panel title="EMERGENCY LOCK" meta="WORKSPACE-WIDE">
        <EmergencyLock locked={locked} />
      </Panel>
    </>
  );
}
