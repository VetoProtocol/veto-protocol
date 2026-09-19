/**
 * Gmail, read only (spec §9.1, §3.3 step 8).
 *
 * §9.1: "Separate search/read from sending; keep sending out of the initial
 * MVP." There is no send function here, and the scope requested is
 * `gmail.readonly`, so sending is not something this code declines to do — it
 * is something it cannot do.
 *
 * Two operations, deliberately distinct:
 *
 *   * **search** returns ids and headers. It answers "what is there".
 *   * **read** returns one message by id, optionally with its body.
 *
 * Step 8 forwards exactly what was authorised (§5.3), so both take their inputs
 * from the decision and build the request here. The URL is constructed from a
 * fixed base; a destination that came from the caller would be an SSRF hole in
 * the one component holding a live credential inside the perimeter.
 *
 * ## The body that comes back is hostile input
 *
 * More obviously here than anywhere else. An email is written by a stranger and
 * may contain instructions addressed to the model — §12.1's first scenario is
 * exactly this. That is fine: whatever the model does next arrives as a new
 * tool call and gets a new decision. What must never happen is this module
 * treating a message as anything but bytes to hand back. It does not re-read
 * arguments from it, follow links in it, or log it.
 */

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';

/** What a search returns. Headers only — never the body (§11 data minimisation). */
export interface GmailSummary {
  readonly id: string;
  readonly threadId: string | null;
  readonly from: string | null;
  readonly subject: string | null;
  readonly date: string | null;
  /** Gmail's own short preview. Content, so it is returned and never logged. */
  readonly snippet: string | null;
}

export interface GmailMessage extends GmailSummary {
  /** Present only when 'body' was among the approved fields. */
  readonly body: string | null;
}

export interface GmailReader {
  searchMessages(
    accessToken: string,
    query: string,
    pageSize: number,
  ): Promise<readonly GmailSummary[]>;

  readMessage(
    accessToken: string,
    messageId: string,
    fields: readonly string[],
  ): Promise<GmailMessage>;
}

export class GmailError extends Error {
  readonly status: number;

  // Not a parameter property: see the note in apps/api/src/errors.ts.
  constructor(status: number) {
    super(`Gmail request failed (${status})`);
    this.name = 'GmailError';
    this.status = status;
  }
}

/** Headers worth carrying. Anything else Gmail returns is dropped, not forwarded. */
const HEADERS_WANTED = ['From', 'Subject', 'Date'] as const;

interface RawHeader {
  name?: string;
  value?: string;
}

interface RawPart {
  mimeType?: string;
  body?: { data?: string; size?: number };
  parts?: RawPart[];
}

interface RawMessage extends RawPart {
  id?: string;
  threadId?: string;
  snippet?: string;
  payload?: RawPart & { headers?: RawHeader[] };
}

export function createGmailReader(): GmailReader {
  return {
    async searchMessages(accessToken, query, pageSize): Promise<readonly GmailSummary[]> {
      // `maxResults` is clamped by the tool schema before this is reached, and
      // again here: a decision authorised a bounded read, and step 8 must not
      // widen it even if a later caller passes something larger.
      const bounded = Math.max(1, Math.min(pageSize, 50));

      const list = await fetch(
        `${GMAIL_BASE}?${new URLSearchParams({
          q: query,
          maxResults: String(bounded),
        }).toString()}`,
        { headers: { authorization: `Bearer ${accessToken}` } },
      );
      if (!list.ok) throw new GmailError(list.status);

      const body = (await list.json()) as { messages?: Array<{ id?: string }> };
      const ids = (body.messages ?? [])
        .map((m) => m.id)
        .filter((id): id is string => typeof id === 'string')
        .slice(0, bounded);

      // Gmail's list endpoint returns ids and nothing else, so each summary is
      // a second request. `format=metadata` with an explicit header list is the
      // narrowest thing that answers "what is there" — it cannot return a body.
      const summaries: GmailSummary[] = [];
      for (const id of ids) {
        const response = await fetch(`${GMAIL_BASE}/${encodeURIComponent(id)}?${metadataQuery()}`, {
          headers: { authorization: `Bearer ${accessToken}` },
        });
        // One unreadable message does not fail the search. A message can vanish
        // between the list and the fetch, and reporting an outage for that
        // would be wrong.
        if (!response.ok) continue;
        summaries.push(toSummary((await response.json()) as RawMessage, id));
      }

      return summaries;
    },

    async readMessage(accessToken, messageId, fields): Promise<GmailMessage> {
      const wantsBody = fields.includes('body');

      // `full` is the only format that carries a body, so asking for it is the
      // observable difference between a metadata read and a content read. A
      // decision that did not approve `body` cannot produce a request that
      // could return one.
      const query = wantsBody ? 'format=full' : metadataQuery();

      const response = await fetch(`${GMAIL_BASE}/${encodeURIComponent(messageId)}?${query}`, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new GmailError(response.status);

      const raw = (await response.json()) as RawMessage;

      // The decision authorised one message id. If Gmail answered about a
      // different one, that is not the approved resource and must not be
      // returned — the same check `drive.ts` makes for a file.
      if (typeof raw.id === 'string' && raw.id !== messageId) throw new GmailError(409);

      return {
        ...toSummary(raw, messageId),
        body: wantsBody ? extractText(raw.payload) : null,
      };
    },
  };
}

const metadataQuery = (): string =>
  `format=metadata&${HEADERS_WANTED.map((h) => `metadataHeaders=${h}`).join('&')}`;

function toSummary(raw: RawMessage, fallbackId: string): GmailSummary {
  const headers = raw.payload?.headers ?? [];
  const header = (name: string): string | null => {
    const found = headers.find((h) => h.name?.toLowerCase() === name.toLowerCase());
    return typeof found?.value === 'string' ? found.value : null;
  };

  return {
    id: typeof raw.id === 'string' ? raw.id : fallbackId,
    threadId: typeof raw.threadId === 'string' ? raw.threadId : null,
    from: header('From'),
    subject: header('Subject'),
    date: header('Date'),
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

/**
 * The first text part of a MIME tree.
 *
 * Depth-limited. A malformed or hostile message can nest parts arbitrarily, and
 * an unbounded walk over attacker-shaped structure is a denial of service
 * against the process holding a live credential.
 */
function extractText(part: RawPart | undefined, depth = 0): string | null {
  if (!part || depth > 8) return null;

  if (part.mimeType?.startsWith('text/') && typeof part.body?.data === 'string') {
    return Buffer.from(part.body.data, 'base64url').toString('utf8');
  }

  for (const child of part.parts ?? []) {
    const found = extractText(child, depth + 1);
    if (found !== null) return found;
  }

  // A message with no text part — all attachments, say. Null rather than an
  // empty string, so "there was nothing" and "it was blank" stay distinct.
  return null;
}
