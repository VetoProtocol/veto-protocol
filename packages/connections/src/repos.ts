/**
 * GitHub repositories and files, read only (spec §9.1, §3.3 step 8).
 *
 * Step 8 forwards **exactly** the approved operation and resource — no
 * widening (§5.3). So every function here takes a repository id and builds the
 * request from it; there is no parameter that turns a one-file read into
 * something larger, because the decision that authorised it named one file.
 *
 * ## Why a numeric id and not `owner/repo`
 *
 * Permit resource-instance keys must match `^[A-Za-z0-9\-_]+$`, and
 * `owner/repo` contains a slash. Real Drive ids fit that grammar and repository
 * **ids** do too, so the id is what the policy layer sees — the same choice,
 * for the same reason, as `google_file`.
 *
 * GitHub's content endpoints want the name, though, so `resolveRepo` trades the
 * id for one. That lookup goes to GitHub and never to the caller: an agent able
 * to assert "repository 42 is actually `victim/secrets`" would be choosing what
 * to read by argument, which is the escalation `/v1/grants/sync` already
 * refuses for a file's parent.
 */

const GITHUB_API = 'https://api.github.com';

/** A listing is bounded in step 8, not only in the schema. */
export const MAX_ENTRIES = 100;

/**
 * A file is bounded too. A repository can hold a hundred-megabyte blob, and
 * "read one file" should not be able to mean that.
 */
export const MAX_FILE_BYTES = 512 * 1024;

export interface RepoSummary {
  readonly id: string;
  readonly fullName: string | null;
  readonly isPrivate: boolean;
  readonly defaultBranch: string | null;
  readonly updatedAt: string | null;
}

/** One entry in a directory. Names and types, never contents. */
export interface TreeEntry {
  readonly name: string;
  readonly path: string;
  readonly type: string;
  readonly size: number | null;
}

export interface RepoFile {
  readonly repoId: string;
  readonly path: string;
  readonly ref: string | null;
  readonly size: number | null;
  /** Present only when the file was text and inside the size bound. */
  readonly content: string | null;
  /** Why content is absent, when it is. Never a silent empty string. */
  readonly omitted: 'too_large' | 'not_a_file' | 'binary' | null;
}

export interface RepoReader {
  /** Repositories this installation can see — the ones the installer picked. */
  listRepos(accessToken: string, pageSize: number): Promise<readonly RepoSummary[]>;
  /** What is in one directory. Listing is a separate permission from reading. */
  listDirectory(
    accessToken: string,
    repoId: string,
    path: string,
    ref: string | null,
    pageSize: number,
  ): Promise<readonly TreeEntry[]>;
  readFile(accessToken: string, repoId: string, path: string, ref: string | null): Promise<RepoFile>;
}

export class RepoError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`GitHub request failed (${status})`);
    this.name = 'RepoError';
    this.status = status;
  }
}

function headers(accessToken: string): Record<string, string> {
  return {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
  };
}

/**
 * Encode a repository path without destroying its separators.
 *
 * `encodeURIComponent` would turn every `/` into `%2F` and the content endpoint
 * would stop finding anything. Each segment is encoded on its own instead, and
 * `..` is dropped — a path is not a way to climb out of a repository.
 */
function encodePath(path: string): string {
  return path
    .split('/')
    .filter((segment) => segment !== '' && segment !== '.' && segment !== '..')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

/**
 * Trade a repository id for its `owner/name`.
 *
 * GitHub is the authority for this, not the request. Exported so step 8 can
 * reuse one lookup across a call rather than repeating it.
 */
export async function resolveRepo(accessToken: string, repoId: string): Promise<RepoSummary> {
  const response = await fetch(`${GITHUB_API}/repositories/${encodeURIComponent(repoId)}`, {
    headers: headers(accessToken),
  });
  if (!response.ok) throw new RepoError(response.status);

  const body = (await response.json()) as Record<string, unknown>;

  // The decision authorised one repository id. If GitHub answered about a
  // different one — a redirect after a transfer, a rename — that is not the
  // approved resource and must not be returned.
  if (typeof body['id'] === 'number' && String(body['id']) !== repoId) {
    throw new RepoError(409);
  }

  return {
    id: repoId,
    fullName: typeof body['full_name'] === 'string' ? body['full_name'] : null,
    isPrivate: body['private'] === true,
    defaultBranch: typeof body['default_branch'] === 'string' ? body['default_branch'] : null,
    updatedAt: typeof body['updated_at'] === 'string' ? body['updated_at'] : null,
  };
}

export function createRepoReader(): RepoReader {
  return {
    async listRepos(accessToken, pageSize): Promise<readonly RepoSummary[]> {
      const bounded = Math.max(1, Math.min(pageSize, MAX_ENTRIES));

      // The installation's own repositories. There is no parameter here a
      // caller could use to ask about an account that did not install the app.
      const response = await fetch(
        `${GITHUB_API}/installation/repositories?per_page=${String(bounded)}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const body = (await response.json()) as { repositories?: Array<Record<string, unknown>> };

      return (body.repositories ?? []).slice(0, bounded).map((r) => ({
        id: typeof r['id'] === 'number' ? String(r['id']) : '',
        fullName: typeof r['full_name'] === 'string' ? r['full_name'] : null,
        isPrivate: r['private'] === true,
        defaultBranch: typeof r['default_branch'] === 'string' ? r['default_branch'] : null,
        updatedAt: typeof r['updated_at'] === 'string' ? r['updated_at'] : null,
      }));
    },

    async listDirectory(accessToken, repoId, path, ref, pageSize): Promise<readonly TreeEntry[]> {
      const bounded = Math.max(1, Math.min(pageSize, MAX_ENTRIES));
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      const query = ref === null ? '' : `?ref=${encodeURIComponent(ref)}`;
      const response = await fetch(
        `${GITHUB_API}/repos/${repo.fullName}/contents/${encodePath(path)}${query}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const body: unknown = await response.json();
      // A directory answers with an array; a file answers with an object. Asking
      // to list a file is a malformed request, not an empty directory.
      if (!Array.isArray(body)) throw new RepoError(415);

      return body.slice(0, bounded).map((e) => {
        const entry = e as Record<string, unknown>;
        return {
          name: typeof entry['name'] === 'string' ? entry['name'] : '',
          path: typeof entry['path'] === 'string' ? entry['path'] : '',
          type: typeof entry['type'] === 'string' ? entry['type'] : '',
          size: typeof entry['size'] === 'number' ? entry['size'] : null,
        };
      });
    },

    async readFile(accessToken, repoId, path, ref): Promise<RepoFile> {
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      const query = ref === null ? '' : `?ref=${encodeURIComponent(ref)}`;
      const response = await fetch(
        `${GITHUB_API}/repos/${repo.fullName}/contents/${encodePath(path)}${query}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const body: unknown = await response.json();
      if (Array.isArray(body)) {
        // A directory. Say so rather than returning nothing and letting the
        // caller conclude the file was empty.
        return { repoId, path, ref, size: null, content: null, omitted: 'not_a_file' };
      }

      const file = body as Record<string, unknown>;
      const size = typeof file['size'] === 'number' ? file['size'] : null;

      if (size !== null && size > MAX_FILE_BYTES) {
        return { repoId, path, ref, size, content: null, omitted: 'too_large' };
      }

      const encoded = typeof file['content'] === 'string' ? file['content'] : null;
      if (encoded === null) {
        return { repoId, path, ref, size, content: null, omitted: 'binary' };
      }

      const raw = Buffer.from(encoded, 'base64');
      if (raw.length > MAX_FILE_BYTES) {
        return { repoId, path, ref, size, content: null, omitted: 'too_large' };
      }

      // Whatever is in here is hostile input. It goes to the caller and nowhere
      // else — not logged, not audited, and never re-read as instructions
      // (invariant 5, and the note at the top of execute.ts).
      return { repoId, path, ref, size, content: raw.toString('utf8'), omitted: null };
    },
  };
}
