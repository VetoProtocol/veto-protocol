/**
 * Reading Slack conversations (spec §15).
 *
 * ## What a bot can see, and why that is the grant boundary
 *
 * Every call here runs as the bot, and a bot reads only the conversations it
 * has been invited to. That is not a limitation worked around — it is the
 * boundary this integration sells. A customer grants a channel by adding the
 * bot to it, in the place they already manage membership, one channel at a
 * time.
 *
 * So `listChannels` returns what the installation can reach rather than every
 * channel in the workspace, and a history read of a channel the bot is not in
 * fails at Slack rather than here. Both are correct.
 *
 * ## Messages are the content this product exists to protect
 *
 * A channel history is the most exposing thing Veto reads anywhere — more so
 * than a Drive file, because it is unguarded conversation nobody wrote for an
 * audience. Three consequences, all deliberate:
 *
 *   - listing a channel returns names and ids, never a message;
 *   - a history read is bounded by count *and* by window, so "read everything
 *     since the beginning" is not expressible;
 *   - nothing here resolves a user id to a name. A name is personal data this
 *     feature does not need, and §11 says do not collect what you do not need.
 *     Ids pass through as Slack gave them.
 *
 * ## Slack answers 200 for failures
 *
 * `{"ok": false, "error": "..."}` with HTTP 200, exactly as the token exchange
 * does. Checked on `ok`, and the error code is carried because
 * `not_in_channel` and `channel_not_found` are different facts: one means the
 * bot was never invited, the other that the id is wrong, and an operator
 * needs to tell them apart.
 */

import { SLACK_API_URL } from './slack.ts';

/** One page, and the ceiling on any caller's request. */
export const MAX_CHANNELS = 200;
export const MAX_MESSAGES = 100;

/**
 * How far back a single history read may reach.
 *
 * The calendar's `MAX_WINDOW_DAYS` applied to conversation. A schema can check
 * that two timestamps are timestamps; only a bound like this can check they
 * are not two years apart, which is the difference between reading a thread
 * and exporting a workspace.
 */
export const MAX_HISTORY_DAYS = 31;

export interface SlackChannel {
  /** `C…`. Fits Permit's instance-key grammar without translation. */
  readonly id: string;
  readonly name: string;
  readonly isPrivate: boolean;
  /** Whether the bot is in it — which is whether it can be read at all. */
  readonly botIsMember: boolean;
}

export interface SlackMessage {
  /** Slack's message id, which is also its timestamp. */
  readonly ts: string;
  /** The author's Slack id. Never resolved to a name here. */
  readonly userId: string | null;
  readonly text: string;
  /** Present when the message is a reply. */
  readonly threadTs: string | null;
}

export interface ChannelReader {
  /** Conversations this installation can reach. */
  listChannels(accessToken: string, pageSize: number): Promise<readonly SlackChannel[]>;
  /** Messages in one conversation, bounded by count and by window. */
  readHistory(
    accessToken: string,
    channelId: string,
    oldest: Date,
    latest: Date,
    pageSize: number,
  ): Promise<readonly SlackMessage[]>;
}

export class SlackError extends Error {
  /** Slack's own code: `not_in_channel`, `channel_not_found`, `ratelimited`. */
  readonly code: string;

  constructor(code: string) {
    super(`Slack request failed (${code})`);
    this.name = 'SlackError';
    this.code = code;
  }
}

interface SlackBody {
  ok?: unknown;
  error?: unknown;
  channels?: unknown;
  messages?: unknown;
}

async function get(accessToken: string, path: string, query: Record<string, string>) {
  const url = new URL(`${SLACK_API_URL}/${path}`);
  url.search = new URLSearchParams(query).toString();

  const response = await fetch(url, {
    headers: {
      authorization: `Bearer ${accessToken}`,
      accept: 'application/json',
    },
  });

  // A transport failure is still a failure, even though Slack's refusals
  // arrive as 200s.
  if (!response.ok) throw new SlackError(`http_${String(response.status)}`);

  const body = (await response.json()) as SlackBody;
  if (body.ok !== true) {
    throw new SlackError(typeof body.error === 'string' ? body.error : 'unknown');
  }
  return body;
}

const str = (value: unknown): string => (typeof value === 'string' ? value : '');

export function createChannelReader(): ChannelReader {
  return {
    async listChannels(accessToken, pageSize) {
      const bounded = Math.max(1, Math.min(pageSize, MAX_CHANNELS));

      const body = await get(accessToken, 'conversations.list', {
        limit: String(bounded),
        // Both kinds, because which ones come back is decided by the scopes
        // the installation actually holds — asking for private channels
        // without `groups:read` simply returns none rather than failing.
        types: 'public_channel,private_channel',
        exclude_archived: 'true',
      });

      const raw = Array.isArray(body.channels) ? body.channels : [];

      return raw.map((entry) => {
        const channel = entry as Record<string, unknown>;
        return {
          id: str(channel['id']),
          name: str(channel['name']),
          isPrivate: channel['is_private'] === true,
          // Surfaced rather than filtered out. A channel the bot is not in is
          // one an operator may want to grant next, and hiding it would make
          // the list look like the whole workspace when it is not.
          botIsMember: channel['is_member'] === true,
        };
      });
    },

    async readHistory(accessToken, channelId, oldest, latest, pageSize) {
      const bounded = Math.max(1, Math.min(pageSize, MAX_MESSAGES));

      const body = await get(accessToken, 'conversations.history', {
        channel: channelId,
        // Slack wants epoch seconds as a string.
        oldest: String(Math.floor(oldest.getTime() / 1000)),
        latest: String(Math.floor(latest.getTime() / 1000)),
        limit: String(bounded),
        inclusive: 'true',
      });

      const raw = Array.isArray(body.messages) ? body.messages : [];

      return raw.map((entry) => {
        const message = entry as Record<string, unknown>;
        return {
          ts: str(message['ts']),
          // An id, never a name. Resolving it would mean collecting personal
          // data this feature does not need.
          userId: typeof message['user'] === 'string' ? message['user'] : null,
          text: str(message['text']),
          threadTs: typeof message['thread_ts'] === 'string' ? message['thread_ts'] : null,
        };
      });
    },
  };
}
