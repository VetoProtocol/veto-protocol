import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import {
  ApiError,
  listDeliveries,
  listEndpoints,
  type DeliveryView,
  type EndpointView,
} from '@/lib/api';
import { currentSession } from '@/lib/session';
import { AddEndpointForm, DeliverNow, StopEndpoint } from './forms';

export const dynamic = 'force-dynamic';

const DELIVERY_TONE: Record<DeliveryView['status'], Tone> = {
  delivered: 'allow',
  pending: 'challenge',
  failed: 'deny',
};

const when = (iso: string): string => new Date(iso).toISOString().replace('T', ' ').slice(0, 19);

export default async function AlertsPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let endpoints: EndpointView[];
  let deliveries: DeliveryView[];
  try {
    [endpoints, deliveries] = await Promise.all([
      listEndpoints(session.credential).then((r) => r.endpoints),
      listDeliveries(session.credential, 25).then((r) => r.deliveries),
    ]);
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

  const live = endpoints.filter((e) => e.status === 'active');
  const waiting = deliveries.filter((d) => d.status === 'pending').length;
  const failed = deliveries.filter((d) => d.status === 'failed').length;

  return (
    <>

      <Panel title="ALERTS" meta="WEBHOOKS / §5.4">
        <div style={{ padding: '22px 18px 18px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/alerts
          </p>
          <h1 className="headline" style={{ fontSize: 30 }}>
            {live.length} listening
            {failed > 0 ? (
              <span style={{ color: 'var(--deny)' }}> · {failed} could not be delivered</span>
            ) : null}
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 12, fontSize: 12.5 }}>
            Veto posts a signed message to a URL you own when something happens you would want to
            know about without watching this screen. Every message says{' '}
            <span style={{ color: 'var(--text)' }}>what happened and to which named thing</span> —
            never a document, an argument, a token or a challenge.
          </p>
        </div>

        {endpoints.length === 0 ? (
          <div
            style={{
              margin: '4px 18px 22px',
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            Nothing is listening. Locks, revocations and refusals are all still recorded in the{' '}
            <a href="/audit" style={{ color: 'var(--text)' }}>
              audit timeline
            </a>{' '}
            — but nobody finds out unless they look.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)' }}>
                  {['url', 'status', 'sending', ''].map((h) => (
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
                {endpoints.map((endpoint) => (
                  <tr key={endpoint.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <th
                      scope="row"
                      style={{
                        padding: '12px 14px',
                        textAlign: 'left',
                        fontWeight: 400,
                        wordBreak: 'break-all',
                      }}
                    >
                      {endpoint.url}
                      <span style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}>
                        added {when(endpoint.created_at)}
                      </span>
                    </th>
                    <td style={{ padding: '12px 14px' }}>
                      <Chip tone={endpoint.status === 'active' ? 'allow' : 'neutral'}>
                        {endpoint.status}
                      </Chip>
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {endpoint.events.length === 0 ? (
                        'nothing'
                      ) : (
                        <ul style={{ margin: 0, paddingLeft: 16 }}>
                          {endpoint.events.map((event) => (
                            <li key={event}>{event}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      {endpoint.status === 'active' ? (
                        <StopEndpoint endpointId={endpoint.id} />
                      ) : (
                        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="ADD AN ENDPOINT" meta="THE SECRET IS SHOWN ONCE">
        <AddEndpointForm />
      </Panel>

      <Panel title="RECENT DELIVERIES" meta="WHAT ARRIVED, AND WHAT DID NOT">
        <div style={{ padding: '18px 18px 0' }}>
          <DeliverNow waiting={waiting} />
        </div>

        {deliveries.length === 0 ? (
          <div
            style={{
              margin: 18,
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            Nothing sent yet. An event only reaches this list once something happens that an
            endpoint above subscribed to.
          </div>
        ) : (
          <div style={{ overflowX: 'auto', marginTop: 16 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <caption className="label" style={{ textAlign: 'left', padding: '0 18px 8px' }}>
                Newest first. A failed row is kept, not cleaned up.
              </caption>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)' }}>
                  {['event', 'status', 'tries', 'what they said', 'when'].map((h) => (
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
                {deliveries.map((delivery) => (
                  <tr key={delivery.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <th
                      scope="row"
                      style={{ padding: '12px 14px', textAlign: 'left', fontWeight: 400 }}
                    >
                      {delivery.event_type}
                      <span style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}>
                        {delivery.event_id}
                      </span>
                    </th>
                    <td style={{ padding: '12px 14px' }}>
                      <Chip tone={DELIVERY_TONE[delivery.status]}>{delivery.status}</Chip>
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {delivery.attempts}
                      {delivery.status === 'pending' && delivery.attempts > 0 ? (
                        <span
                          style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}
                        >
                          next {when(delivery.next_attempt_at)}
                        </span>
                      ) : null}
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {delivery.last_error ??
                        (delivery.last_status === null ? '—' : delivery.last_status)}
                    </td>
                    <td
                      style={{
                        padding: '12px 14px',
                        color: 'var(--text-dim)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {when(delivery.occurred_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="CHECKING A DELIVERY" meta="FOUR STEPS, IN THIS ORDER">
        <div style={{ padding: 18, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.8 }}>
          <p style={{ margin: '0 0 12px' }}>
            Three headers arrive with every request. The signature is{' '}
            <code>HMAC-SHA256(secret, &ldquo;id.timestamp.body&rdquo;)</code>, base64url.
          </p>
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              The <span style={{ color: 'var(--text)' }}>timestamp</span> is inside your tolerance —
              five minutes is what the sender assumes. Without this a captured request replays
              forever.
            </li>
            <li>
              The <span style={{ color: 'var(--text)' }}>version prefix</span> is one you know.
              Refuse <code>v2=</code> rather than guessing.
            </li>
            <li>
              The <span style={{ color: 'var(--text)' }}>signature</span> matches, compared in
              constant time, over the raw body — before any parse and re-serialise.
            </li>
            <li>
              The <span style={{ color: 'var(--text)' }}>event id</span> is one you have not already
              processed.
            </li>
          </ol>
          <p style={{ margin: '12px 0 0' }}>
            Step 4 is the one people skip. A retry keeps its event id and takes a <em>fresh</em>{' '}
            timestamp — it has to, or every attempt after the first would fail step 1 — so the id,
            not the timestamp, is what tells you a delivery is a duplicate.{' '}
            <code>@veto/webhooks</code> exports the verifier the tests check the sender against.
          </p>
        </div>
      </Panel>
    </>
  );
}
