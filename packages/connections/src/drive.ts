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

export interface DriveReader {
  readFile(accessToken: string, fileId: string, fields: readonly string[]): Promise<DriveFile>;
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
