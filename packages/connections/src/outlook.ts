/**
 * Outlook mail and calendar over Microsoft Graph, read only (§9.1, §3.3 step 8).
 *
 * The Graph counterpart of `gmail.ts` and `calendar.ts`, and it keeps their
 * rules rather than inventing new ones:
 *
 *   * **search** returns headers. It answers "what is there".
 *   * **read** returns one item by id, with the body only when asked for.
 *   * **list** returns events in a bounded window.
 *   * there is no send, no create, no update and no delete, and no scope for
 *     any of them — so sending is not something this code declines to do, it
 *     is something it cannot do.
 *
 * Both halves live in one file because they are one provider reached through
 * one base URL with one token shape. Google needed two files because Gmail and
 * Calendar are two different APIs.
 *
 * ## `/me`, never a named mailbox
 *
 * Every path here is `/me/...` — the mailbox and the calendar of the account
 * that consented. Graph will happily serve `/users/{id}/messages` to a token
 * with the right permission, and an agent able to name a user id would reach a
 * colleague's mail. There is no user argument anywhere in this module, so that
 * is not a mistake somebody can make later. The same rule `calendar.ts` keeps
 * by only ever asking for `primary`.
 *
 * ## What comes back is hostile input
 *
 * An email or an invitation is written by whoever sent it, and may carry
 * instructions addressed to the model — §12.1's first scenario. That is fine:
 * whatever the model does next arrives as a new tool call and gets a new
 * decision. What must never happen is this module treating a message as
 * anything but bytes to hand back. It does not re-read arguments from one,
 * follow links in it, or log it.
 *
 * ## Graph throttles, and that is not a credential problem
 *
 * Graph answers 429 with `Retry-After` under load. It is surfaced as itself
 * rather than retried here: a retry inside step 8 spends the §11 latency budget
 * on a call the decision has already been made for, and a 429 reported as a
 * failure is honest where a slow success is not.
 */

import { GRAPH_API_URL } from './microsoft.ts';

const MAIL_BASE = `${GRAPH_API_URL}/me/messages`;
const EVENTS_BASE = `${GRAPH_API_URL}/me/events`;
const CALENDAR_VIEW = `${GRAPH_API_URL}/me/calendarView`;

/**
 * The widest window a single list may cover.
 *
 * The calendar's version of a volume limit, and the same number Google's uses.
 * A schema can check that two timestamps are timestamps; only step 8 can check
 * that they are not two years apart.
 *
 * Named for its provider rather than shared with `calendar.ts`: both go through
 * the one barrel in `index.ts`, and two `export *` sources offering the same
 * name drop it from the barrel rather than failing, so every importer would
 * break at once with no file to blame.
 */
export const MAX_OUTLOOK_WINDOW_DAYS = 90;

/** The most items one call may return, whatever a later caller passes. */
export const MAX_OUTLOOK_PAGE_SIZE = 100;

/** What a mail search returns. Headers only — never the body (§11). */
export interface OutlookSummary {
  readonly id: string;
  readonly conversationId: string | null;
  readonly from: string | null;
  readonly subject: string | null;
  /** Graph's ISO-8601, e.g. `2026-10-20T09:23:21Z`. */
  readonly receivedAt: string | null;
  /** Graph's own short preview. Content, so it is returned and never logged. */
  readonly preview: string | null;
}

export interface OutlookMessage extends OutlookSummary {
  /** Present only when 'body' was among the approved fields. */
  readonly body: string | null;
}

export interface OutlookEvent {
  readonly id: string;
  readonly subject: string | null;
  /** Graph returns a local time plus a zone; both are kept, unparsed. */
  readonly start: string | null;
  readonly end: string | null;
  readonly timeZone: string | null;
  readonly location: string | null;
  readonly organizer: string | null;
  /** How many people, not who. A guest list is other people's data (§11). */
  readonly attendeeCount: number;
  /** Present only when 'body' was among the approved fields. */
  readonly body: string | null;
}

export interface OutlookReader {
  searchMessages(
    accessToken: string,
    query: string,
    pageSize: number,
  ): Promise<readonly OutlookSummary[]>;

  readMessage(
    accessToken: string,
    messageId: string,
    fields: readonly string[],
  ): Promise<OutlookMessage>;

  listEvents(
    accessToken: string,
    window: { readonly start: string; readonly end: string },
    pageSize: number,
  ): Promise<readonly OutlookEvent[]>;

  readEvent(accessToken: string, eventId: string, fields: readonly string[]): Promise<OutlookEvent>;
}

export class GraphError extends Error {
  readonly status: number;

  // Not a parameter property: see the note in apps/api/src/errors.ts.
  constructor(status: number) {
    super(`Microsoft Graph request failed (${status})`);
    this.name = 'GraphError';
    this.status = status;
  }
}

interface RawMessage {
  id?: unknown;
  conversationId?: unknown;
  subject?: unknown;
  bodyPreview?: unknown;
  receivedDateTime?: unknown;
  from?: { emailAddress?: { address?: unknown } };
  body?: { content?: unknown };
}

interface RawEvent {
  id?: unknown;
  subject?: unknown;
  bodyPreview?: unknown;
  start?: { dateTime?: unknown; timeZone?: unknown };
  end?: { dateTime?: unknown };
  location?: { displayName?: unknown };
  organizer?: { emailAddress?: { address?: unknown } };
  attendees?: unknown;
  body?: { content?: unknown };
}

const str = (value: unknown): string | null => (typeof value === 'string' ? value : null);

/** Clamped here as well as in the tool schema — step 8 must not widen a decision. */
const bound = (pageSize: number): number => Math.max(1, Math.min(pageSize, MAX_OUTLOOK_PAGE_SIZE));

async function graphGet(url: string, accessToken: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: {
      authorization: `Bearer ${accessToken}`,
      // Graph returns HTML bodies by default. Text is the smaller, less
      // surprising thing to hand a model, and it cannot carry a tracking pixel
      // or a script.
      prefer: 'outlook.body-content-type="text"',
    },
  });
  if (!response.ok) throw new GraphError(response.status);
  return await response.json();
}

export function createOutlookReader(): OutlookReader {
  return {
    async searchMessages(accessToken, query, pageSize): Promise<readonly OutlookSummary[]> {
      const top = bound(pageSize);

      // `$search` rather than `$filter`: the tool takes a phrase, and a filter
      // would need a field name the caller does not supply. Graph wants the
      // phrase quoted, and `URLSearchParams` escapes it — a value reaching the
      // query unescaped would let a caller append their own `$` parameters and
      // widen the read.
      const url = `${MAIL_BASE}?${new URLSearchParams({
        $search: `"${query.replace(/"/g, '')}"`,
        $top: String(top),
        $select: 'id,conversationId,subject,bodyPreview,receivedDateTime,from',
      }).toString()}`;

      const body = (await graphGet(url, accessToken)) as { value?: unknown };
      const items = Array.isArray(body.value) ? (body.value as RawMessage[]) : [];

      // A search never carries bodies. "What is there" is a different question
      // from "what does it say", and they are separately authorized calls.
      return items.slice(0, top).map((raw) => toSummary(raw));
    },

    async readMessage(accessToken, messageId, fields): Promise<OutlookMessage> {
      const raw = (await graphGet(
        `${MAIL_BASE}/${encodeURIComponent(messageId)}`,
        accessToken,
      )) as RawMessage;

      // The decision authorised one message id. An answer about a different one
      // is not the approved resource — the same check drive.ts, gmail.ts and
      // calendar.ts make.
      if (typeof raw.id === 'string' && raw.id !== messageId) throw new GraphError(409);

      return {
        ...toSummary(raw, messageId),
        body: fields.includes('body') ? str(raw.body?.content) : null,
      };
    },

    async listEvents(accessToken, window, pageSize): Promise<readonly OutlookEvent[]> {
      const top = bound(pageSize);

      // `calendarView` rather than `/events`: it expands a recurring series
      // into its occurrences, so a window means what a reader thinks it means
      // rather than "the series definition". The same reason Google's listing
      // passes `singleEvents=true`.
      const url = `${CALENDAR_VIEW}?${new URLSearchParams({
        startDateTime: window.start,
        endDateTime: window.end,
        $top: String(top),
        $orderby: 'start/dateTime',
        $select: 'id,subject,start,end,location,organizer,attendees',
      }).toString()}`;

      const body = (await graphGet(url, accessToken)) as { value?: unknown };
      const items = Array.isArray(body.value) ? (body.value as RawEvent[]) : [];

      return items.slice(0, top).map((raw) => toEvent(raw, []));
    },

    async readEvent(accessToken, eventId, fields): Promise<OutlookEvent> {
      const raw = (await graphGet(
        `${EVENTS_BASE}/${encodeURIComponent(eventId)}`,
        accessToken,
      )) as RawEvent;

      if (typeof raw.id === 'string' && raw.id !== eventId) throw new GraphError(409);

      return toEvent(raw, fields, eventId);
    },
  };
}

function toSummary(raw: RawMessage, fallbackId = ''): OutlookSummary {
  return {
    id: str(raw.id) ?? fallbackId,
    conversationId: str(raw.conversationId),
    from: str(raw.from?.emailAddress?.address),
    subject: str(raw.subject),
    receivedAt: str(raw.receivedDateTime),
    preview: str(raw.bodyPreview),
  };
}

function toEvent(raw: RawEvent, fields: readonly string[], fallbackId = ''): OutlookEvent {
  return {
    id: str(raw.id) ?? fallbackId,
    subject: str(raw.subject),
    start: str(raw.start?.dateTime),
    end: str(raw.end?.dateTime),
    timeZone: str(raw.start?.timeZone),
    location: str(raw.location?.displayName),
    organizer: str(raw.organizer?.emailAddress?.address),
    // A count, never the list. Who else is invited is other people's data and
    // is not needed to decide anything (§11 data minimisation).
    attendeeCount: Array.isArray(raw.attendees) ? raw.attendees.length : 0,
    body: fields.includes('body') ? str(raw.body?.content) : null,
  };
}
