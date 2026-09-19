/**
 * Google Calendar, read only (spec §9.1, §3.3 step 8).
 *
 * §9.1: "Begin read-only; create/update requires step-up approval in later
 * releases." So there is no create, no update, no delete and no respond-to-
 * invitation here, and the scope requested is `calendar.readonly`. A later
 * release adds writes behind a challenge; nothing about this file needs to
 * remember not to write, because it cannot.
 *
 * Two operations:
 *
 *   * **list** events in a bounded window. Answers "what is happening".
 *   * **read** one event by id.
 *
 * ## One person's calendar
 *
 * Only `primary` — the calendar belonging to the connected account. A Google
 * user can often see colleagues' calendars, and an agent that could name a
 * calendar id would reach them. There is no calendar argument anywhere in this
 * module, so that is not a mistake somebody can make later.
 *
 * ## Event text is hostile input
 *
 * An invitation is written by whoever sent it. A description can carry
 * instructions addressed to the model, exactly like an email body — §12.1's
 * first scenario applies here too. Whatever the model does next arrives as a
 * new tool call and gets a new decision. This module hands back bytes and does
 * not re-read arguments from them, follow links in them, or log them.
 */

const CALENDAR_BASE = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

/** The widest window a single list may cover. */
export const MAX_WINDOW_DAYS = 90;

export interface CalendarEvent {
  readonly id: string;
  readonly summary: string | null;
  /** RFC3339, or a bare date for an all-day event — Google returns either. */
  readonly start: string | null;
  readonly end: string | null;
  readonly location: string | null;
  readonly organizer: string | null;
  /** How many people, not who. A guest list is other people's data (§11). */
  readonly attendeeCount: number;
  /** Present only when 'description' was among the approved fields. */
  readonly description: string | null;
}

export interface CalendarReader {
  listEvents(
    accessToken: string,
    window: { timeMin: string; timeMax: string },
    pageSize: number,
  ): Promise<readonly CalendarEvent[]>;

  readEvent(
    accessToken: string,
    eventId: string,
    fields: readonly string[],
  ): Promise<CalendarEvent>;
}

export class CalendarError extends Error {
  readonly status: number;

  // Not a parameter property: see the note in apps/api/src/errors.ts.
  constructor(status: number) {
    super(`Calendar request failed (${status})`);
    this.name = 'CalendarError';
    this.status = status;
  }
}

interface RawEvent {
  id?: string;
  summary?: string;
  description?: string;
  location?: string;
  start?: { dateTime?: string; date?: string };
  end?: { dateTime?: string; date?: string };
  organizer?: { email?: string };
  attendees?: unknown[];
}

export function createCalendarReader(): CalendarReader {
  return {
    async listEvents(accessToken, window, pageSize): Promise<readonly CalendarEvent[]> {
      // Clamped here as well as in the tool schema. A decision authorised a
      // bounded read and step 8 must not widen it, whatever a later caller
      // passes.
      const bounded = Math.max(1, Math.min(pageSize, 100));

      const response = await fetch(
        `${CALENDAR_BASE}?${new URLSearchParams({
          timeMin: window.timeMin,
          timeMax: window.timeMax,
          maxResults: String(bounded),
          // Recurring events expand into their occurrences, so a window means
          // what a reader thinks it means rather than "the series definition".
          singleEvents: 'true',
          orderBy: 'startTime',
        }).toString()}`,
        { headers: { authorization: `Bearer ${accessToken}` } },
      );

      if (!response.ok) throw new CalendarError(response.status);

      const body = (await response.json()) as { items?: RawEvent[] };

      // A listing never carries descriptions. The same rule as a mail search:
      // "what is happening" is a different question from "what does it say",
      // and they are separately authorized calls.
      return (body.items ?? []).slice(0, bounded).map((item) => toEvent(item, []));
    },

    async readEvent(accessToken, eventId, fields): Promise<CalendarEvent> {
      const response = await fetch(`${CALENDAR_BASE}/${encodeURIComponent(eventId)}`, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new CalendarError(response.status);

      const raw = (await response.json()) as RawEvent;

      // The decision authorised one event id. An answer about a different one
      // is not the approved resource — the same check drive.ts and gmail.ts
      // make.
      if (typeof raw.id === 'string' && raw.id !== eventId) throw new CalendarError(409);

      return toEvent(raw, fields, eventId);
    },
  };
}

function toEvent(raw: RawEvent, fields: readonly string[], fallbackId = ''): CalendarEvent {
  return {
    id: typeof raw.id === 'string' ? raw.id : fallbackId,
    summary: typeof raw.summary === 'string' ? raw.summary : null,
    start: raw.start?.dateTime ?? raw.start?.date ?? null,
    end: raw.end?.dateTime ?? raw.end?.date ?? null,
    location: typeof raw.location === 'string' ? raw.location : null,
    organizer: typeof raw.organizer?.email === 'string' ? raw.organizer.email : null,
    // A count, never the list. Who else is invited is other people's data and
    // is not needed to decide anything (§11 data minimisation).
    attendeeCount: Array.isArray(raw.attendees) ? raw.attendees.length : 0,
    description:
      fields.includes('description') && typeof raw.description === 'string'
        ? raw.description
        : null,
  };
}
