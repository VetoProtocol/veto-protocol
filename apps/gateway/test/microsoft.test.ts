/**
 * Microsoft 365 through the gateway (spec §9.1, §3.3 step 8).
 *
 * **Skipped: Microsoft is off the tool catalogue.** The provider was withdrawn
 * from Iteration Two at the client's request, so `TOOLS` no longer lists the
 * four Microsoft tools and no screen offers the connection. Everything these
 * tests exercise still exists — `packages/connections/src/microsoft.ts`, the
 * Outlook reader, the broker wiring in `execute.ts` — it is simply unreachable.
 *
 * Kept rather than deleted, and skipped at the file rather than per test, so
 * that putting the four definitions back in `tools.ts` restores a suite that
 * already proved the hard property below. Deleting it would mean re-deriving
 * the §15 measurements from scratch.
 *
 * The property worth testing here is **narrowing at mint time**, because it is
 * the one that differs from Google and the one that is easy to claim and not
 * have. Microsoft's refresh grant accepts "equivalent to or a subset of" the
 * consented scopes, so a mail read must receive a token that physically cannot
 * read the calendar.
 *
 * The connection below deliberately holds **both** scopes. Asserting narrowness
 * against a mail-only connection would prove nothing: the token would be narrow
 * because there was nothing else to give. Narrowness has to be a choice, which
 * is the same reason `github.test.ts` seeds an installation with all four
 * permissions.
 *
 * Also here: the bounded window, and the refusal when the app registration is
 * absent — a tool that is listed and allowed by policy but unconfigured must
 * refuse rather than half-work.
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
  MAX_OUTLOOK_WINDOW_DAYS,
  MICROSOFT_CALENDAR_READ_SCOPE,
  MICROSOFT_MAIL_READ_SCOPE,
  MICROSOFT_OFFLINE_SCOPE,
  type DriveEntry,
  type DriveFile,
  type DriveReader,
  type OutlookEvent,
  type OutlookMessage,
  type OutlookReader,
  type OutlookSummary,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createGateway } from '../src/app.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;
let unconfigured: FastifyInstance;

const s = suffix();
const WS = `ws_ms${s}`;
const USER = `usr_ms${s}`;
const AGENT = `agt_ms${s}`;

/** Graph ids carry `=` padding, which is why the tool pattern allows it. */
const MESSAGE = 'AAMkAGI2THVSAAA=';
const EVENT = 'AAMkAGI2EVENTAAA=';

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

/** What each mint was asked for. The whole point of this file. */
const minted: string[][] = [];

const exchange: UpstreamTokenExchange = {
  async refresh(_token, scopes) {
    minted.push([...scopes]);
    return {
      accessToken: 'eyJ.fake',
      expiresAt: new Date(Date.now() + 300_000),
      scopes: [...scopes],
      // Microsoft returns a replacement every time. Returned here so the
      // broker's rotation path is exercised rather than assumed.
      rotatedRefreshToken: 'rt-rotated',
    };
  },
  async revoke() {},
};

const summary = (id: string): OutlookSummary => ({
  id,
  conversationId: 'conv-1',
  from: 'chair@example.com',
  subject: 'Board review',
  receivedAt: '2026-10-01T09:00:00Z',
  preview: 'Agenda attached',
});

const event = (id: string, body: string | null): OutlookEvent => ({
  id,
  subject: 'Board review',
  start: '2026-10-01T09:00:00',
  end: '2026-10-01T10:00:00',
  timeZone: 'UTC',
  location: 'Room 3',
  organizer: 'chair@example.com',
  attendeeCount: 4,
  body,
});

const windows: Array<{ start: string; end: string }> = [];
const outlook: OutlookReader = {
  async searchMessages(): Promise<readonly OutlookSummary[]> {
    return [summary(MESSAGE)];
  },
  async readMessage(_token, id, fields): Promise<OutlookMessage> {
    return { ...summary(id), body: fields.includes('body') ? 'Dial-in details' : null };
  },
  async listEvents(_token, window): Promise<readonly OutlookEvent[]> {
    windows.push(window);
    return [event(EVENT, null)];
  },
  async readEvent(_token, id, fields): Promise<OutlookEvent> {
    return event(id, fields.includes('body') ? 'Dial-in details' : null);
  },
};

const drive: DriveReader = {
  async listFolder(): Promise<readonly DriveEntry[]> {
    // Not exercised here; present because the port requires it.
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

    for (const type of ['outlook_mailbox', 'outlook_calendar']) {
      for (const action of ['search', 'read']) {
        await db.query(
          `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
           values ($1,$2,$3,$4,$5,'{}'::jsonb,'allow','polv_ms')`,
          [`pol_${suffix()}${suffix()}`, WS, AGENT, action, JSON.stringify({ type, ids: [USER] })],
        );
      }
    }

    // One connection holding BOTH scopes, so narrowness below is a choice.
    await createConnection(db, wrapper, {
      workspaceId: WS,
      userId: USER,
      provider: 'microsoft',
      scopes: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_MAIL_READ_SCOPE, MICROSOFT_CALENDAR_READ_SCOPE],
      refreshToken: 'refresh-token-value',
    });
  });

  for (const type of ['outlook_mailbox', 'outlook_calendar']) {
    policy.allow(WS, AGENT, 'search', type, USER);
    policy.allow(WS, AGENT, 'read', type, USER);
  }

  const common = {
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: 'https://gateway.veto.example',
    authorizationServer: 'https://app.veto.example',
  };

  app = createGateway({
    ...common,
    execute: { wrapper, exchange, drive, microsoftExchange: exchange, outlook },
  });
  // Same policies, same connection, no Microsoft wiring at all.
  unconfigured = createGateway({ ...common, execute: { wrapper, exchange, drive } });
  await Promise.all([app.ready(), unconfigured.ready()]);
});

afterAll(async () => {
  await Promise.all([app.close(), unconfigured.close()]);
  await pool.end();
  redis.disconnect();
});

const call = (name: string, args: Record<string, unknown>, instance = app) =>
  instance.inject({
    method: 'POST',
    url: '/mcp',
    headers: { authorization: `Bearer ${gatewayToken(WS, USER, AGENT)}` },
    payload: rpc('tools/call', { name, arguments: args }),
  });

const ok = (res: { json(): { result?: { isError?: boolean } } }) =>
  res.json().result?.isError !== true;

describe.skip('narrowing at mint time', () => {
  it('mints a mail token that cannot read the calendar', async () => {
    minted.length = 0;
    const res = await call('microsoft_mail.search_messages', { query: 'board' });

    expect(ok(res)).toBe(true);
    expect(minted).toHaveLength(1);
    expect(minted[0]).toContain(MICROSOFT_MAIL_READ_SCOPE);
    // The connection holds it. The token does not.
    expect(minted[0]).not.toContain(MICROSOFT_CALENDAR_READ_SCOPE);
  });

  it('mints a calendar token that cannot read mail', async () => {
    minted.length = 0;
    const res = await call('microsoft_calendar.list_events', {
      time_min: iso(0),
      time_max: iso(7),
    });

    expect(ok(res)).toBe(true);
    expect(minted).toHaveLength(1);
    expect(minted[0]).toContain(MICROSOFT_CALENDAR_READ_SCOPE);
    expect(minted[0]).not.toContain(MICROSOFT_MAIL_READ_SCOPE);
  });

  it('asks for offline access on every mint, or rotation quietly stops', async () => {
    // Microsoft issues a replacement refresh token only when `offline_access`
    // is requested. Leaving it out mints a working access token and breaks the
    // chain — a failure that surfaces days later on an idle connection.
    minted.length = 0;
    await call('microsoft_mail.read_message', { message_id: MESSAGE });

    expect(minted[0]).toContain(MICROSOFT_OFFLINE_SCOPE);
  });
});

describe.skip('the bounded window', () => {
  it('refuses a window wider than the limit', async () => {
    const res = await call('microsoft_calendar.list_events', {
      time_min: iso(0),
      time_max: iso(MAX_OUTLOOK_WINDOW_DAYS + 1),
    });

    // A volume limit, checked in step 8 rather than only in the schema: two
    // timestamps two years apart are still two timestamps.
    //
    // And specifically a *volume* code, not a connection one. Google's
    // equivalent once reported this as a credential failure, which sent the
    // user off to reconnect a working account.
    expect(res.json().error.data.reason_code).toBe('VOLUME_LIMIT_EXCEEDED');
  });

  it('accepts one inside the limit and forwards exactly it', async () => {
    windows.length = 0;
    const res = await call('microsoft_calendar.list_events', {
      time_min: iso(0),
      time_max: iso(7),
    });

    expect(ok(res)).toBe(true);
    expect(windows).toEqual([{ start: iso(0), end: iso(7) }]);
  });

  it('refuses a backwards window', async () => {
    const res = await call('microsoft_calendar.list_events', {
      time_min: iso(7),
      time_max: iso(0),
    });
    expect(res.json().error.data.reason_code).toBe('ARGUMENT_SCHEMA_INVALID');
  });
});

describe.skip('what the tools will not do', () => {
  it('has no tool that writes, sends or deletes', async () => {
    const tools = (
      await app.inject({
        method: 'POST',
        url: '/mcp',
        headers: { authorization: `Bearer ${gatewayToken(WS, USER, AGENT)}` },
        payload: rpc('tools/list'),
      })
    ).json().result.tools as Array<{ name: string }>;

    const microsoft = tools.filter((t) => t.name.startsWith('microsoft_'));
    expect(microsoft).toHaveLength(4);
    for (const tool of microsoft) {
      expect(tool.name).not.toMatch(/send|create|update|delete|write|reply/);
    }
  });

  it('returns no body from a search, however the search is phrased', async () => {
    // "What is there" and "what does it say" are separately authorized calls.
    const res = await call('microsoft_mail.search_messages', { query: 'board' });
    const text = res.json().result.content[0].text;

    expect(text).toContain('Board review');
    expect(text).not.toContain('Dial-in details');
  });

  it('withholds the body unless it was among the approved fields', async () => {
    const without = await call('microsoft_mail.read_message', { message_id: MESSAGE });
    const withBody = await call('microsoft_mail.read_message', {
      message_id: MESSAGE,
      fields: ['body'],
    });

    expect(without.json().result.content[0].text).not.toContain('Dial-in details');
    expect(withBody.json().result.content[0].text).toContain('Dial-in details');
  });

  it('refuses an id outside the alphabet the tool accepts', async () => {
    // `/` and `+` are rejected so a caller cannot smuggle a path segment or a
    // query string into the URL step 8 builds.
    const res = await call('microsoft_mail.read_message', { message_id: 'AAMk/../../etc' });
    expect(res.json().error.data.reason_code).toBe('ARGUMENT_SCHEMA_INVALID');
  });
});

describe.skip('when Microsoft is not configured', () => {
  it('refuses the tool rather than half-working', async () => {
    // Policy allows it, the connection exists, the tool is listed — and the
    // server has no exchange and no reader. The honest answer is a refusal.
    const res = await call('microsoft_mail.search_messages', { query: 'board' }, unconfigured);

    // Not a policy refusal and not a credential one: the server simply cannot
    // carry this out, and says so with the code that means exactly that.
    expect(res.json().error.data.reason_code).toBe('TOOL_NOT_ALLOWED');
  });
});
