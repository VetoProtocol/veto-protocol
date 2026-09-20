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
