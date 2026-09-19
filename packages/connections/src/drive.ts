/**
 * Google Drive, read only (spec §9.1, §3.3 step 8).
 *
 * Step 8 forwards **exactly** the approved operation and resource — no
 * widening (§5.3). So this takes a file id and a field list and builds the
 * request from them; there is no parameter a caller can pass that turns a
 * one-file read into something larger, because the decision that authorised it
 * named that one file.
 *
 * The URL is constructed here from a fixed base. A destination that came from
 * the caller would be an SSRF hole in the one component that holds a live
 * credential and sits inside the network perimeter.
 */

export interface DriveFile {
  readonly id: string;
  readonly name: string | null;
  readonly mimeType: string | null;
  readonly modifiedTime: string | null;
  /** Present only when 'content' was among the approved fields. */
  readonly content: string | null;
}

/** One entry in a folder. Names and types, never contents. */
export interface DriveEntry {
  readonly id: string;
  readonly name: string | null;
  readonly mimeType: string | null;
  readonly modifiedTime: string | null;
}

export interface DriveReader {
  readFile(accessToken: string, fileId: string, fields: readonly string[]): Promise<DriveFile>;

  /**
   * What is in one folder.
   *
   * Listing is a separate permission from reading, so this returns names and
   * ids and never content — the §12.1 scenario where an agent authorized for
   * one file asks for the whole folder is exactly this distinction.
   */
  listFolder(
    accessToken: string,
    folderId: string,
    pageSize: number,
  ): Promise<readonly DriveEntry[]>;
}

const DRIVE_BASE = 'https://www.googleapis.com/drive/v3/files';

/** Metadata fields we know how to ask for. Anything else is dropped, not forwarded. */
const METADATA_FIELDS = new Set(['name', 'mimeType', 'modifiedTime', 'owners']);

export class DriveError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`Drive request failed (${status})`);
    this.name = 'DriveError';
    this.status = status;
  }
}

export function createDriveReader(): DriveReader {
  return {
    async listFolder(accessToken, folderId, pageSize): Promise<readonly DriveEntry[]> {
      // Clamped here as well as in the tool schema: the decision authorised a
      // bounded read and step 8 must not widen it.
      const bounded = Math.max(1, Math.min(pageSize, 100));

      // The query names the parent, so a caller cannot turn one folder into a
      // whole-Drive search by supplying a cleverer id.
      const response = await fetch(
        `${DRIVE_BASE}?${new URLSearchParams({
          q: `'${folderId.replace(/'/g, "\\'")}' in parents and trashed = false`,
          pageSize: String(bounded),
          fields: 'files(id,name,mimeType,modifiedTime)',
        }).toString()}`,
        { headers: { authorization: `Bearer ${accessToken}` } },
      );
      if (!response.ok) throw new DriveError(response.status);

      const body = (await response.json()) as {
        files?: Array<Record<string, unknown>>;
      };

      return (body.files ?? []).slice(0, bounded).map((f) => ({
        id: typeof f['id'] === 'string' ? f['id'] : '',
        name: typeof f['name'] === 'string' ? f['name'] : null,
        mimeType: typeof f['mimeType'] === 'string' ? f['mimeType'] : null,
        modifiedTime: typeof f['modifiedTime'] === 'string' ? f['modifiedTime'] : null,
      }));
    },

    async readFile(accessToken, fileId, fields): Promise<DriveFile> {
      const wantsContent = fields.includes('content');
      const metadata = fields.filter((f) => METADATA_FIELDS.has(f));

      // Always fetch the id, so the response can be checked against what was
      // authorised rather than trusted to be it.
      const fieldParam = ['id', ...metadata].join(',');

      const metaResponse = await fetch(
        `${DRIVE_BASE}/${encodeURIComponent(fileId)}?fields=${encodeURIComponent(fieldParam)}`,
        { headers: { authorization: `Bearer ${accessToken}` } },
      );
      if (!metaResponse.ok) throw new DriveError(metaResponse.status);

      const meta = (await metaResponse.json()) as Record<string, unknown>;

      // The decision authorised one file id. If Drive answered about a
      // different one — a redirect, a shortcut, an alias — that is not the
      // approved resource and must not be returned.
      if (typeof meta['id'] === 'string' && meta['id'] !== fileId) {
        throw new DriveError(409);
      }

      let content: string | null = null;
      if (wantsContent) {
        const body = await fetch(`${DRIVE_BASE}/${encodeURIComponent(fileId)}?alt=media`, {
          headers: { authorization: `Bearer ${accessToken}` },
        });
        if (!body.ok) throw new DriveError(body.status);
        content = await body.text();
      }

      return {
        id: fileId,
        name: typeof meta['name'] === 'string' ? meta['name'] : null,
        mimeType: typeof meta['mimeType'] === 'string' ? meta['mimeType'] : null,
        modifiedTime: typeof meta['modifiedTime'] === 'string' ? meta['modifiedTime'] : null,
        content,
      };
    },
  };
}
