import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import {
  ApiError,
  getHierarchyJob,
  listConnections,
  type ConnectionView,
  type HierarchyJob,
} from '@/lib/api';
import { currentSession } from '@/lib/session';
import { RevokeConnection, SyncGithub, SyncHierarchy } from './forms';
import { describeWalk } from './walk-state';

export const dynamic = 'force-dynamic';

/**
 * Outcomes of the consent round trip, looked up by code.
 *
 * The query string never reaches the page as text. Both routes that redirect
 * here handle values a stranger chose — a `state` parameter, an `error`
 * parameter from Google — and a crafted link must not be able to print its own
 * sentence above a "connect" button.
 */
const ERRORS: Record<string, string> = {
  session: 'Your session expired before that finished. Sign in and try again.',
  unconfigured:
    'That service is not set up on this server yet. An operator needs to add the credentials.',
  unavailable: 'The control plane could not be reached at all. Nothing was connected.',
  rejected:
    'The control plane refused that request. If the dashboard and the API were deployed at different times, restarting the API usually fixes it — the server log names the reason.',
  expired: 'That attempt timed out. Five minutes is the window; start it again.',
  declined: 'You declined at the provider\u2019s screen. Nothing was connected.',
  refused: 'The provider refused that authorization. Nothing was connected.',
  mismatch: 'That response did not match the attempt that started here, so it was rejected.',
  // Google and Slack both land here. GitHub's equivalent is `nouserauth`
  // below: a different cause with a different fix, so a different message.
  nocode: 'The provider sent no authorization code back. Nothing was connected.',
  exchange: 'That authorization could not be completed. Start again, and grant offline access.',
  unknownservice:
    'That is not a service this dashboard knows how to connect. Nothing was connected — and nothing else was connected in its place.',
  noinstallation:
    'GitHub sent no installation back. Nothing was connected. If you cancelled on the GitHub screen, that is why.',
  // Distinct from `nocode`, which Google and Slack share. This one almost always means a
  // settings change was missed rather than anything the person did wrong, so it
  // says which setting.
  nouserauth:
    'GitHub did not confirm who owns that installation, so nothing was connected. The GitHub App needs \u201cRequest user authorization (OAuth) during installation\u201d switched on.',
};

/**
 * What to say after a successful connect.
 *
 * Keyed by provider, because this used to be one hardcoded sentence about
 * Google and GitHub had been a first-class provider for weeks — so connecting
 * a repository reported that "Google" had granted something. A message that
 * names the wrong system is worse than a vague one: it makes somebody doubt
 * what actually happened.
 *
 * `ok` is what older callbacks sent and is kept so a redirect already in flight
 * during a deploy still lands on something true.
 */
const CONNECTED: Record<string, string> = {
  google: 'Connected. What Google actually granted is listed below.',
  github: 'Connected. The repositories and permissions you picked are listed below.',
  slack: 'Connected. Add the bot to a channel to let an agent read it \u2014 a Slack install on its own reaches no conversation.',
  ok: 'Connected. What the provider actually granted is listed below.',
};

const STATUS_TONE: Record<string, Tone> = {
  active: 'allow',
  expired: 'challenge',
  revoked: 'deny',
};

/** Scope URLs are unreadable at a glance. This is what each one actually permits. */
const SCOPE_MEANING: Record<string, string> = {
  'https://www.googleapis.com/auth/drive.readonly': 'read Drive files — no writing, no deleting',
  'https://www.googleapis.com/auth/gmail.readonly': 'read and search mail — no sending, no deleting',
  'https://www.googleapis.com/auth/calendar.readonly':
    'read the calendar — no creating, changing or cancelling',
};

/**
 * One button per service (§9.1).
 *
 * Activated separately, never together. Google merges grants on the same OAuth
 * client, so connecting Gmail after Drive leaves the account holding both —
 * which is the user's decision made twice, and the point. What must not happen
 * is one screen asking for everything before either feature exists.
 */
const SERVICES = [
  {
    key: 'drive',
    label: 'Connect Google Drive',
    href: '/connections/google/start?service=drive',
    detail: 'Read-only. Files and folders.',
  },
  {
    key: 'gmail',
    label: 'Connect Gmail',
    href: '/connections/google/start?service=gmail',
    detail: 'Read-only. Searching and reading; there is no send permission to grant.',
  },
  {
    key: 'calendar',
    label: 'Connect Calendar',
    href: '/connections/google/start?service=calendar',
    detail: 'Read-only. Creating and changing events come later, behind an approval.',
  },
  {
    // A different provider, not a fourth Google service. GitHub is installed
    // rather than authorised: you pick the repositories on GitHub's own screen,
    // and nothing on this side can widen that afterwards.
    key: 'github',
    label: 'Connect GitHub',
    href: '/connections/github/start',
    detail: 'Read-only. You choose which repositories; code, issues and pull requests.',
  },
  {
    // A third provider. The grant is made on Slack's side, by inviting the bot
    // to a channel — so the detail says that rather than implying this screen
    // is where access is chosen.
    key: 'slack',
    label: 'Connect Slack',
    href: '/connections/slack/start?service=channels',
    detail:
      'Read-only, public channels. An agent reads a channel only once you invite the bot to it.',
  },
  {
    key: 'slack_private',
    label: 'Connect Slack private channels',
    href: '/connections/slack/start?service=private_channels',
    detail: 'A separate decision from public channels, and a separate consent screen.',
  },
] as const;

export default async function ConnectionsPage({
  searchParams,
}: {
  searchParams: Promise<{ connected?: string; error?: string }>;
}) {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  const { connected, error } = await searchParams;

  let connections: ConnectionView[];
  // The most recent folder walk, if there has been one. A 404 means there has
  // not; anything else is not worth failing the page over, because this panel
  // is a progress note rather than the point of the screen.
  let walk: HierarchyJob | null = null;
  try {
    connections = (await listConnections(session.credential)).connections;
  } catch (failure) {
    return (
      <>
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {failure instanceof ApiError ? failure.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  try {
    walk = await getHierarchyJob(session.credential);
  } catch {
    walk = null;
  }

  const live = connections.filter((c) => c.status === 'active');

  return (
    <>

      <Panel title="CONNECTIONS" meta="GOOGLE · GITHUB / §9">
        <div style={{ padding: '22px 18px 18px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/connections
          </p>
          <h1 className="headline" style={{ fontSize: 30 }}>
            {live.length} connected
            <span style={{ color: 'var(--text-faint)' }}> · {connections.length} total</span>
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 12, fontSize: 12.5 }}>
            Connecting an account lets Veto reach it{' '}
            <span style={{ color: 'var(--text)' }}>on an agent&rsquo;s behalf</span> — and only when
            a decision says yes. The credential is stored encrypted and never handed to an agent;
            each allowed call gets a fresh short-lived token instead.
          </p>

          {connected ? (
            <p
              role="status"
              style={{
                margin: '16px 0 0',
                padding: '10px 12px',
                border: '1px solid var(--allow)',
                background: 'var(--allow-bg)',
                color: 'var(--allow)',
                fontSize: 12.5,
              }}
            >
              {CONNECTED[connected] ?? CONNECTED['ok']}
            </p>
          ) : null}

          {error ? (
            <p
              role="alert"
              style={{
                margin: '16px 0 0',
                padding: '10px 12px',
                border: '1px solid var(--deny)',
                background: 'var(--deny-bg)',
                color: 'var(--deny)',
                fontSize: 12.5,
              }}
            >
              {ERRORS[error] ?? 'That did not complete. Nothing was connected.'}
            </p>
          ) : null}

          <div style={{ display: 'grid', gap: 12, marginTop: 18 }}>
            {SERVICES.map((service, index) => (
              <div key={service.key} style={{ display: 'grid', gap: 5, justifyItems: 'start' }}>
                <a
                  href={service.href}
                  style={{
                    display: 'inline-block',
                    padding: '9px 18px',
                    fontSize: 12,
                    // Only the first is the filled button. Two equally loud
                    // calls to action would suggest connecting both is the
                    // expected thing to do, and §9.1 says the opposite.
                    background: index === 0 ? 'var(--text)' : 'transparent',
                    color: index === 0 ? 'var(--bg)' : 'var(--text)',
                    border: `1px solid ${index === 0 ? 'var(--text)' : 'var(--border-strong)'}`,
                  }}
                >
                  {service.label}
                </a>
                <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{service.detail}</span>
              </div>
            ))}
          </div>
          <p style={{ color: 'var(--text-faint)', fontSize: 11.5, margin: '14px 0 0' }}>
            Connect them one at a time, and only the ones you need. Each one is a separate trip to
            Google, and each grants only what that feature reads.
          </p>
        </div>
      </Panel>

      {live.length > 0 ? (
        <Panel title="FOLDER STRUCTURE" meta="SO A GRANT REACHES WHAT IS INSIDE">
          <div style={{ padding: 18 }}>
            <p style={{ color: 'var(--text-dim)', fontSize: 12.5, margin: '0 0 16px', maxWidth: 620 }}>
              Granting a folder is meant to reach the files inside it. Permit works that out from a
              record of what contains what — and it has no way to know your Drive&rsquo;s shape
              unless somebody looks. Until then a grant on a folder reaches the folder and nothing
              else.
            </p>
            {walk ? (
              <div
                style={{
                  margin: '0 0 16px',
                  padding: '11px 13px',
                  border: '1px solid var(--border-strong)',
                  background: 'var(--bg-raised)',
                  fontSize: 12.5,
                  color: walk.status === 'failed' ? 'var(--deny)' : 'var(--text-dim)',
                }}
                // Announced, because on a slow walk this is the only thing that
                // changes when somebody reloads to find out what happened.
                role="status"
              >
                <span className="label" style={{ marginRight: 8, color: 'var(--text-faint)' }}>
                  {walk.status === 'running' ? 'RUNNING' : walk.status === 'done' ? 'LAST WALK' : 'FAILED'}
                </span>
                {describeWalk(walk)}
              </div>
            ) : null}
            <SyncHierarchy />
            {/* The GitHub half. Shown beside the Drive walk because they answer
                the same question for two providers: where does this thing sit,
                so that a grant on the container reaches it. */}
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16, marginTop: 4 }}>
              <SyncGithub />
            </div>
          </div>
        </Panel>
      ) : null}

      <Panel title="STORED CREDENTIALS" meta="NONE OF THEM LEAVE THE SERVER">
        {connections.length === 0 ? (
          <div
            style={{
              margin: '18px',
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            Nothing connected. An agent asking for a Drive file will be denied for want of a
            credential, which is the correct answer rather than an error.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr>
                  {['provider', 'status', 'what it permits', 'connected', ''].map((h) => (
                    <th
                      key={h}
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
                {connections.map((connection) => (
                  <tr key={connection.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <th
                      scope="row"
                      style={{ padding: '14px', textAlign: 'left', fontWeight: 400 }}
                    >
                      {connection.provider}
                      <span style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}>
                        {connection.id}
                      </span>
                    </th>
                    <td style={{ padding: '14px' }}>
                      <Chip tone={STATUS_TONE[connection.status] ?? 'neutral'}>
                        {connection.status}
                      </Chip>
                    </td>
                    <td style={{ padding: '14px', color: 'var(--text-dim)' }}>
                      {connection.scopes.length === 0 ? (
                        'Google reported no scopes'
                      ) : (
                        <ul style={{ margin: 0, paddingLeft: 16 }}>
                          {connection.scopes.map((scope) => (
                            <li key={scope}>
                              {SCOPE_MEANING[scope] ?? scope.replace(/^https:\/\/www\.googleapis\.com\/auth\//, '')}
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td
                      style={{ padding: '14px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}
                    >
                      {new Date(connection.created_at).toISOString().replace('T', ' ').slice(0, 16)}
                    </td>
                    <td style={{ padding: '14px' }}>
                      {connection.status === 'revoked' ? (
                        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>—</span>
                      ) : (
                        <RevokeConnection connectionId={connection.id} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="WHAT CONNECTING DOES NOT DO" meta="WORTH BEING EXPLICIT">
        <div style={{ padding: 18, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.8 }}>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            <li>
              It does not give any agent access. Every call is still decided, and{' '}
              <span style={{ color: 'var(--text)' }}>no rule means denied</span>.
            </li>
            <li>
              It does not hand a token to an agent. Agents talk to the gateway; the gateway mints a
              short-lived token for one allowed call and keeps it.
            </li>
            <li>
              It does not survive disconnecting. The stored credential is destroyed here first, then
              revoked at Google — so an outage there still leaves it dead.
            </li>
          </ul>
        </div>
      </Panel>
    </>
  );
}
