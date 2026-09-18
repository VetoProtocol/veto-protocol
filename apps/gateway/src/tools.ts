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
 * Read-only by design for stage 2. §9.1 starts with the narrowest read scopes
 * and keeps writes out of the MVP.
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
      'from reading the files inside it.',
    action: 'read',
    resourceType: 'google_folder',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['folder_id'],
      properties: {
        folder_id: { type: 'string', minLength: 1, maxLength: 200 },
        page_size: { type: 'integer', minimum: 1, maximum: 100 },
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
