/**
 * Calendar through the gateway (spec §9.1).
 *
 * The property worth testing here is the **bounded window**. A schema can check
 * that two timestamps are timestamps; only step 8 can check that they are not
 * two years apart. "Everything I have ever done" and "my week" are the same
 * request shape, and the difference between them is §12.1's
 * split-the-bulk-request scenario applied to time rather than to count.
 *
 * Also here: the fact that no write tool exists to be authorized by accident
 * (§9.1 defers create/update to a later release, behind a step-up approval).
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createConnection,
  CALENDAR_READONLY_SCOPE,
  DRIVE_READONLY_SCOPE,
  MAX_WINDOW_DAYS,
  type CalendarEvent,
  type CalendarReader,
  type DriveEntry,
  type DriveFile,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createGateway } from '../src/app.ts';
import { RPC } from '../src/jsonrpc.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_cal${s}`;
const USER = `usr_cal${s}`;
const AGENT = `agt_cal${s}`;

const EVENT = 'evt0001';

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

const minted: string[][] = [];
const exchange: UpstreamTokenExchange = {
  async refresh(_token, scopes) {
    minted.push([...scopes]);
    return {
      accessToken: 'ya29.fake',
      expiresAt: new Date(Date.now() + 300_000),
      scopes: [...scopes],
    };
  },
  async revoke() {},
};

const sample = (id: string, description: string | null): CalendarEvent => ({
  id,
  summary: 'Board review',
  start: '2026-10-01T09:00:00Z',
  end: '2026-10-01T10:00:00Z',
  location: 'Room 3',
  organizer: 'chair@example.com',
  attendeeCount: 4,
  description,
});

const windows: Array<{ timeMin: string; timeMax: string }> = [];
const eventReads: string[] = [];
const calendar: CalendarReader = {
  async listEvents(_token, window): Promise<readonly CalendarEvent[]> {
    windows.push(window);
    return [sample(EVENT, null)];
  },
  async readEvent(_token, id, fields): Promise<CalendarEvent> {
    eventReads.push(id);
    return sample(id, fields.includes('description') ? 'Dial-in details' : null);
  },
};

const drive: DriveReader = {
  async listFolder(): Promise<readonly DriveEntry[]> {
    // Not exercised by this file; present because the port requires it.
    return [];
  },
  async readFile(_token, fileId): Promise<DriveFile> {
    return { id: fileId, name: fileId, mimeType: 'text/plain', modifiedTime: null, content: 'x' };
  },
};

const iso = (daysFromNow: number): string =>
  new Date(Date.UTC(2026, 9, 1) + daysFromNow * 24 * 60 * 60 * 1000).toISOString();

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seedAgent(pool, WS, USER, AGENT, 'claude-desktop');

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into presence (workspace_id,user_id,state,source) values ($1,$2,'active','test')`,
      [WS, USER],
    );

    for (const action of ['search', 'read']) {
      await db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,$4,$5,'{}'::jsonb,'allow','polv_cal')`,
        [
          `pol_${suffix()}${suffix()}`,
          WS,
          AGENT,
          action,
          JSON.stringify({ type: 'google_calendar', ids: [USER] }),
        ],
      );
    }

    await createConnection(db, wrapper, {
      workspaceId: WS,
      userId: USER,
      provider: 'google',
      scopes: [DRIVE_READONLY_SCOPE, CALENDAR_READONLY_SCOPE],
      refreshToken: 'refresh-token-value',
    });
  });

  policy.allow(WS, AGENT, 'search', 'google_calendar', USER);
  policy.allow(WS, AGENT, 'read', 'google_calendar', USER);

  app = createGateway({
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: 'https://gateway.veto.example',
    authorizationServer: 'https://app.veto.example',
    execute: { wrapper, exchange, drive, calendar },
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const call = (name: string, args: Record<string, unknown>) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    headers: { authorization: `Bearer ${gatewayToken(WS, USER, AGENT)}` },
    payload: rpc('tools/call', { name, arguments: args }),
  });

describe('the calendar tools', () => {
  it('lists read-only tools and nothing that changes anything', async () => {
    const tools = (
      await app.inject({
        method: 'POST',
        url: '/mcp',
        headers: { authorization: `Bearer ${gatewayToken(WS, USER, AGENT)}` },
        payload: rpc('tools/list'),
      })
    ).json().result.tools as Array<{ name: string }>;

    const names = tools.map((t) => t.name);
    expect(names).toContain('google_calendar.list_events');
    expect(names).toContain('google_calendar.read_event');
    // §9.1 defers create and update to a later release, behind a step-up
    // approval. There is no tool to authorize by accident.
    for (const verb of ['create', 'update', 'delete', 'respond']) {
      expect(
        names.some((n) => n.includes(verb)),
        verb,
      ).toBe(false);
    }
  });

  it('lists a week', async () => {
    const body = (
      await call('google_calendar.list_events', { time_min: iso(0), time_max: iso(7) })
    ).json();

    expect(body.error).toBeUndefined();
    const returned = JSON.parse(body.result.content[0].text) as {
      events: Array<Record<string, unknown>>;
    };
    expect(returned.events[0]).toMatchObject({ id: EVENT, summary: 'Board review' });
    // A listing carries no description, the same way a mail search carries no
    // body.
    expect(returned.events[0]?.['description']).toBeNull();
  });

  it('mints a Calendar-only token even though the account also holds Drive', async () => {
    minted.length = 0;
    await call('google_calendar.list_events', { time_min: iso(0), time_max: iso(1) });
    expect(minted[0]).toEqual([CALENDAR_READONLY_SCOPE]);
  });
});

describe('the window is bounded', () => {
  it('refuses a window wider than the limit', async () => {
    const body = (
      await call('google_calendar.list_events', {
        time_min: iso(0),
        time_max: iso(MAX_WINDOW_DAYS + 1),
      })
    ).json();

    // "Everything I have ever done" and "my week" are the same request shape.
    // The schema cannot tell them apart; step 8 can.
    expect(body.error.code).toBe(RPC.DENIED);
  });

  it('accepts a window exactly at the limit', async () => {
    const body = (
      await call('google_calendar.list_events', {
        time_min: iso(0),
        time_max: iso(MAX_WINDOW_DAYS),
      })
    ).json();
    expect(body.error).toBeUndefined();
  });

  it('refuses a backwards window', async () => {
    const body = (
      await call('google_calendar.list_events', { time_min: iso(7), time_max: iso(0) })
    ).json();
    expect(body.error.code).toBe(RPC.DENIED);
  });

  it('refuses a missing end, rather than defaulting to forever', async () => {
    // A default here would be a silent widening of what somebody asked for.
    const body = (await call('google_calendar.list_events', { time_min: iso(0) })).json();
    expect(body.error.code).toBe(RPC.INVALID_PARAMS);
  });

  it('refuses a time that is not a time', async () => {
    const body = (
      await call('google_calendar.list_events', { time_min: 'yesterday', time_max: iso(1) })
    ).json();
    expect(body.error.code).toBe(RPC.INVALID_PARAMS);
  });
});

describe('reading one event', () => {
  it('returns the description only when asked', async () => {
    const without = JSON.parse(
      (await call('google_calendar.read_event', { event_id: EVENT })).json().result.content[0].text,
    ) as Record<string, unknown>;
    expect(without['description']).toBeNull();

    const asked = JSON.parse(
      (await call('google_calendar.read_event', { event_id: EVENT, fields: ['description'] }))
        .json()
        .result.content[0].text,
    ) as Record<string, unknown>;
    expect(asked['description']).toBe('Dial-in details');
  });

  it('refuses an event id that could reach another path', async () => {
    for (const id of ['../../calendars/other/events', 'a b', 'e1?alt=json']) {
      const body = (await call('google_calendar.read_event', { event_id: id })).json();
      expect(body.error.code, id).toBe(RPC.INVALID_PARAMS);
    }
  });

  it('never reached upstream for any of the refused calls', () => {
    // Every refusal above happened before a credential was minted or used.
    expect(eventReads.every((id) => id === EVENT)).toBe(true);
    expect(windows.every((w) => Date.parse(w.timeMax) > Date.parse(w.timeMin))).toBe(true);
  });
});

describe('another person’s calendar', () => {
  it('cannot be named, because the calendar comes from the session', async () => {
    await call('google_calendar.list_events', { time_min: iso(0), time_max: iso(1) });

    const seen = policy.calls.filter((c) => c.resourceType === 'google_calendar');
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((c) => c.resourceKey === USER)).toBe(true);
  });
});
