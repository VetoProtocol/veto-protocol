/**
 * The tool catalogue.
 *
 * Listing a tool is not granting it. §8 and invariant 9 are explicit that a
 * tool listed earlier proves nothing about the call being made now, so this
 * file describes what *exists* and says nothing about what any agent may do.
 * The authorization decision happens at `tools/call`, every time, for every
 * caller.
 *
 * Schemas are strict — `additionalProperties: false` and bounded strings —
 * because arguments are validated before policy evaluation, not after. An
 * argument set that cannot be validated cannot be digested, and an approval
 * that is not bound to an exact argument set is not single-use in any
 * meaningful way (invariants 6 and 9).
 *
 * Read-only by design. §9.1 starts with the narrowest read scopes and keeps
 * writes out of the MVP — there is no tool here that changes anything, and no
 * send tool at all, so "do not send mail" is not a rule anybody has to write.
 */

export interface ToolDefinition {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  /** The §4.2 action this maps to, used when the pipeline lands in phase 3. */
  readonly action: string;
  readonly resourceType: string;
}

/** `2026-10-01T09:00:00Z`, with optional fractional seconds and offset form. */
const RFC3339 = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$';

export const TOOLS: readonly ToolDefinition[] = [
  {
    name: 'google_drive.read_file',
    title: 'Read a Drive file',
    description:
      'Read the content or metadata of one Google Drive file the user has granted access to. ' +
      'Every call is authorized individually.',
    action: 'read',
    resourceType: 'google_file',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['file_id'],
      properties: {
        file_id: { type: 'string', minLength: 1, maxLength: 200 },
        fields: {
          type: 'array',
          maxItems: 8,
          items: { type: 'string', enum: ['name', 'content', 'mimeType', 'modifiedTime', 'owners'] },
        },
        // Not a permission and not trusted. §7.3 and FR-11 make declared intent
        // a risk signal only: it can raise a challenge, never authorise one.
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'google_drive.list_folder',
    title: 'List a Drive folder',
    description:
      'List the files in one Google Drive folder. Listing a folder is a separate permission ' +
      'from reading the files inside it. Use folder_id "root" for the top of My Drive.',
    action: 'read',
    resourceType: 'google_folder',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['folder_id'],
      properties: {
        // Required, and deliberately not defaulted to "root". A default would
        // widen a request nobody made — the same reason a calendar listing
        // refuses a missing end rather than reaching back to the beginning of
        // time. Named here so a caller does not have to guess the string.
        folder_id: {
          type: 'string',
          minLength: 1,
          maxLength: 200,
          description: 'Drive folder id, or "root" for the top of My Drive.',
        },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'google_gmail.search_messages',
    title: 'Search mail',
    description:
      'Find messages in the connected mailbox. Returns ids, senders, subjects and dates — ' +
      'never message bodies. Reading a message is a separate, separately authorized call.',
    action: 'search',
    resourceType: 'gmail_mailbox',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['query'],
      properties: {
        // Gmail's own search syntax. Passed through as one opaque string: it is
        // a query, not a destination, and nothing here interprets it.
        query: { type: 'string', minLength: 1, maxLength: 500 },
        page_size: { type: 'integer', minimum: 1, maximum: 50 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'google_gmail.read_message',
    title: 'Read one message',
    description:
      'Read one message from the connected mailbox by id. Ask for the body only when you need ' +
      'it. Every call is authorized individually.',
    action: 'read',
    resourceType: 'gmail_mailbox',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['message_id'],
      properties: {
        // Gmail ids are hex. Constrained so a caller cannot smuggle a path
        // segment or a query string into the URL step 8 builds.
        message_id: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9_-]+$' },
        fields: {
          type: 'array',
          maxItems: 5,
          items: { type: 'string', enum: ['from', 'subject', 'date', 'snippet', 'body'] },
        },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'google_calendar.list_events',
    title: 'List calendar events',
    description:
      'List events in a bounded time window from the connected calendar. Returns times, ' +
      'titles, locations and how many people are invited — never event descriptions, and ' +
      'never who the other guests are. Reading one event is a separate call.',
    action: 'search',
    resourceType: 'google_calendar',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      // Both ends required. "Everything from the beginning of time" is not a
      // request this tool can express, which is the point of a bounded window.
      required: ['time_min', 'time_max'],
      properties: {
        // RFC3339, as a pattern rather than `format: 'date-time'`. The
        // gateway's AJV runs in strict mode with no format vocabulary
        // registered, so a format keyword throws at compile time instead of
        // validating anything — and a regex says out loud what is accepted.
        time_min: { type: 'string', pattern: RFC3339, maxLength: 40 },
        time_max: { type: 'string', pattern: RFC3339, maxLength: 40 },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'google_calendar.read_event',
    title: 'Read one event',
    description:
      'Read one event from the connected calendar by id. Ask for the description only when ' +
      'you need it. Every call is authorized individually.',
    action: 'read',
    resourceType: 'google_calendar',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['event_id'],
      properties: {
        // Constrained so a caller cannot smuggle a path segment or a query
        // string into the URL step 8 builds.
        event_id: { type: 'string', minLength: 1, maxLength: 1024, pattern: '^[A-Za-z0-9_-]+$' },
        fields: {
          type: 'array',
          maxItems: 6,
          items: {
            type: 'string',
            enum: ['summary', 'start', 'end', 'location', 'organizer', 'description'],
          },
        },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },

  {
    name: 'github_repo.list_repos',
    title: 'List repositories',
    description:
      'List the repositories the installation can see \u2014 the ones chosen when the app was ' +
      'installed. Names and ids only. Every call is authorized individually.',
    action: 'search',
    resourceType: 'github_account',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: [],
      properties: {
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_repo.list_directory',
    title: 'List a directory',
    description:
      'List the files and folders at one path in a repository. Listing is a separate ' +
      'permission from reading. Every call is authorized individually.',
    action: 'read',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id'],
      properties: {
        // GitHub's numeric id, not `owner/repo`: the policy layer's instance
        // keys have no room for a slash, and an id survives a rename.
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        path: { type: 'string', minLength: 1, maxLength: 400, pattern: '^[^\\\\]+$' },
        ref: { type: 'string', minLength: 1, maxLength: 255, pattern: '^[A-Za-z0-9._/-]+$' },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_repo.read_file',
    title: 'Read a file',
    description:
      'Read one file from a repository at a given path. Large and binary files are refused ' +
      'rather than truncated silently. Every call is authorized individually.',
    action: 'read',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id', 'path'],
      properties: {
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        path: { type: 'string', minLength: 1, maxLength: 400, pattern: '^[^\\\\]+$' },
        ref: { type: 'string', minLength: 1, maxLength: 255, pattern: '^[A-Za-z0-9._/-]+$' },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_issue.search',
    title: 'Search issues',
    description:
      'Find issues and pull requests in one repository. Returns titles, authors, labels and ' +
      'state \u2014 never bodies. Every call is authorized individually.',
    action: 'search',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id', 'query'],
      properties: {
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        // The repository qualifier is prepended by step 8, so a query cannot
        // reach a repository the decision did not name.
        query: { type: 'string', minLength: 1, maxLength: 256 },
        page_size: { type: 'integer', minimum: 1, maximum: 50 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_issue.read',
    title: 'Read an issue',
    description:
      'Read one issue, including its comments. Every call is authorized individually.',
    action: 'read',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id', 'issue_number'],
      properties: {
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        issue_number: { type: 'integer', minimum: 1, maximum: 999999 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_pull.read',
    title: 'Read a pull request',
    description:
      'Read one pull request: its description, branches and state. The changed lines are a ' +
      'separate call. Every call is authorized individually.',
    action: 'read',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id', 'pull_number'],
      properties: {
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        pull_number: { type: 'integer', minimum: 1, maximum: 999999 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'github_pull.read_diff',
    title: 'Read the changes in a pull request',
    description:
      'Read which lines changed in one pull request. Bounded by file count and total size; ' +
      'what was dropped is reported. Every call is authorized individually.',
    action: 'read',
    resourceType: 'github_repo',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['repo_id', 'pull_number'],
      properties: {
        repo_id: { type: 'string', minLength: 1, maxLength: 20, pattern: '^[0-9]+$' },
        pull_number: { type: 'integer', minimum: 1, maximum: 999999 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },

  {
    name: 'slack_channel.list_channels',
    title: 'List Slack channels',
    description:
      'List the conversations this installation can see. Names and ids only \u2014 never a ' +
      'message. A channel can be read only if the bot was invited to it, and that is shown. ' +
      'Every call is authorized individually.',
    action: 'search',
    resourceType: 'slack_workspace',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: [],
      properties: {
        page_size: { type: 'integer', minimum: 1, maximum: 200 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'slack_channel.read_history',
    title: 'Read a channel',
    description:
      'Read messages from one channel in a bounded time window. The bot must have been ' +
      'invited to that channel. Author ids are returned, never names. Every call is ' +
      'authorized individually.',
    action: 'read',
    resourceType: 'slack_channel',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['channel_id', 'oldest', 'latest'],
      properties: {
        // Slack's own id shape. A value that cannot be one should not travel
        // as far as the API.
        channel_id: { type: 'string', pattern: '^[CGD][A-Z0-9]{1,20}$' },
        oldest: { type: 'string', pattern: RFC3339 },
        latest: { type: 'string', pattern: RFC3339 },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },

  // Microsoft 365. The mailbox and the calendar belong to the session's human
  // and are read from `GatewaySession`, so no tool here has a field anybody
  // could put somebody else's address in — the same rule the Google pair keeps.
  //
  // Graph ids are long base64-ish strings that routinely carry `=` padding,
  // which is why the pattern below is wider than Gmail's. It is still a closed
  // alphabet: a caller must not be able to smuggle a path segment or a query
  // string into the URL step 8 builds. If a real tenant ever returns an id
  // containing `+` or `/`, this pattern rejects it and the tool refuses rather
  // than mangling the request — stated here because it is the one thing about
  // these ids a live call has not yet confirmed (`docs/microsoft-setup.md`).
  {
    name: 'microsoft_mail.search_messages',
    title: 'Search Outlook mail',
    description:
      'Find messages in the connected Microsoft 365 mailbox. Returns ids, senders, subjects ' +
      'and dates — never message bodies. Reading a message is a separate, separately ' +
      'authorized call.',
    action: 'search',
    resourceType: 'outlook_mailbox',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['query'],
      properties: {
        // A search phrase, passed through as one opaque string. It is a query,
        // not a destination, and nothing here interprets it.
        query: { type: 'string', minLength: 1, maxLength: 500 },
        page_size: { type: 'integer', minimum: 1, maximum: 50 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'microsoft_mail.read_message',
    title: 'Read one Outlook message',
    description:
      'Read one message from the connected Microsoft 365 mailbox by id. Ask for the body only ' +
      'when you need it. Every call is authorized individually.',
    action: 'read',
    resourceType: 'outlook_mailbox',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['message_id'],
      properties: {
        message_id: { type: 'string', minLength: 1, maxLength: 512, pattern: '^[A-Za-z0-9_=-]+$' },
        fields: {
          type: 'array',
          maxItems: 5,
          items: { type: 'string', enum: ['from', 'subject', 'date', 'preview', 'body'] },
        },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'microsoft_calendar.list_events',
    title: 'List Outlook calendar events',
    description:
      'List events in a bounded time window from the connected Microsoft 365 calendar. ' +
      'Returns times, titles, locations and how many people are invited — never event ' +
      'bodies, and never who the other guests are. Reading one event is a separate call.',
    action: 'search',
    resourceType: 'outlook_calendar',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      // Both ends required, as for Google. "Everything from the beginning of
      // time" is not a request this tool can express.
      required: ['time_min', 'time_max'],
      properties: {
        time_min: { type: 'string', pattern: RFC3339, maxLength: 40 },
        time_max: { type: 'string', pattern: RFC3339, maxLength: 40 },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
  {
    name: 'microsoft_calendar.read_event',
    title: 'Read one Outlook event',
    description:
      'Read one event from the connected Microsoft 365 calendar by id. Ask for the body only ' +
      'when you need it. Every call is authorized individually.',
    action: 'read',
    resourceType: 'outlook_calendar',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['event_id'],
      properties: {
        event_id: { type: 'string', minLength: 1, maxLength: 512, pattern: '^[A-Za-z0-9_=-]+$' },
        fields: {
          type: 'array',
          maxItems: 6,
          items: {
            type: 'string',
            enum: ['subject', 'start', 'end', 'location', 'organizer', 'body'],
          },
        },
        declared_intent: { type: 'string', maxLength: 500 },
      },
    },
  },
];

export const findTool = (name: string): ToolDefinition | undefined =>
  TOOLS.find((tool) => tool.name === name);

/** The wire shape MCP expects from `tools/list`. */
export const toolListing = () =>
  TOOLS.map((tool) => ({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
  }));
