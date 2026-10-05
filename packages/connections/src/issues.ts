/**
 * GitHub issues and pull requests, read only (spec §9.1, §3.3 step 8).
 *
 * One module because GitHub models a pull request as an issue with extra parts:
 * the same number space, the same comment thread, and separate endpoints only
 * for the review and the diff. Splitting them would mean two copies of the same
 * id handling for no gain.
 *
 * ## This is the richest injection surface in the product
 *
 * A Drive file has to be shared with someone before it can carry a hostile
 * instruction. An issue on a public repository can be opened by anyone in the
 * world, and its body lands in a model's context the moment an agent is asked
 * "what bugs are open". §12.1's first scenario applies here with more force
 * than it does to Drive.
 *
 * The design answer is unchanged and is not in this file: whatever a model does
 * after reading an issue arrives as a new tool call and gets a new decision.
 * What this module must not do is help — it returns text and nothing else, and
 * nothing here re-reads that text, follows a link in it, or logs it.
 */

import { RepoError, resolveRepo } from './repos.ts';

const GITHUB_API = 'https://api.github.com';

/** Bounded in step 8, not only in the schema. */
export const MAX_RESULTS = 50;

/** A review thread can run to hundreds of comments; a read is not an export. */
export const MAX_COMMENTS = 30;

/**
 * A diff is the one thing here with no natural ceiling — a dependency bump can
 * be a hundred thousand lines. Bounded by files and by bytes, because either
 * can be the big one.
 */
export const MAX_DIFF_FILES = 50;
export const MAX_DIFF_BYTES = 256 * 1024;

export interface IssueSummary {
  readonly number: number;
  readonly title: string | null;
  readonly state: string | null;
  readonly author: string | null;
  readonly isPullRequest: boolean;
  readonly labels: readonly string[];
  readonly updatedAt: string | null;
}

export interface IssueComment {
  readonly author: string | null;
  readonly createdAt: string | null;
  readonly body: string;
}

export interface IssueDetail extends IssueSummary {
  readonly body: string;
  readonly comments: readonly IssueComment[];
  /** True when more comments exist than were returned. */
  readonly truncated: boolean;
}

export interface PullRequestDetail extends IssueSummary {
  readonly body: string;
  readonly baseRef: string | null;
  readonly headRef: string | null;
  readonly merged: boolean;
  readonly changedFiles: number | null;
}

export interface DiffFile {
  readonly path: string;
  readonly status: string | null;
  readonly additions: number | null;
  readonly deletions: number | null;
  /** Absent when the file was binary or the budget ran out. */
  readonly patch: string | null;
}

export interface PullRequestDiff {
  readonly number: number;
  readonly files: readonly DiffFile[];
  /** True when files or patches were dropped to stay inside the bounds. */
  readonly truncated: boolean;
}

export interface IssueReader {
  search(
    accessToken: string,
    repoId: string,
    query: string,
    pageSize: number,
  ): Promise<readonly IssueSummary[]>;
  readIssue(accessToken: string, repoId: string, issueNumber: number): Promise<IssueDetail>;
  readPullRequest(
    accessToken: string,
    repoId: string,
    pullNumber: number,
  ): Promise<PullRequestDetail>;
  readDiff(accessToken: string, repoId: string, pullNumber: number): Promise<PullRequestDiff>;
}

function headers(accessToken: string): Record<string, string> {
  return {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
  };
}

const text = (value: unknown): string | null => (typeof value === 'string' ? value : null);
const num = (value: unknown): number | null => (typeof value === 'number' ? value : null);

function summarise(raw: Record<string, unknown>): IssueSummary {
  const user = raw['user'] as Record<string, unknown> | undefined;
  const labels = Array.isArray(raw['labels']) ? raw['labels'] : [];

  return {
    number: num(raw['number']) ?? 0,
    title: text(raw['title']),
    state: text(raw['state']),
    author: text(user?.['login']),
    // GitHub marks a pull request by the presence of this object on an issue.
    isPullRequest: raw['pull_request'] !== undefined,
    labels: labels
      .map((l) => (typeof l === 'string' ? l : text((l as Record<string, unknown>)['name'])))
      .filter((l): l is string => l !== null),
    updatedAt: text(raw['updated_at']),
  };
}

export function createIssueReader(): IssueReader {
  return {
    async search(accessToken, repoId, query, pageSize): Promise<readonly IssueSummary[]> {
      const bounded = Math.max(1, Math.min(pageSize, MAX_RESULTS));
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      // The repository qualifier is prepended here rather than taken from the
      // caller's query. A search string is otherwise a way to reach a
      // repository the decision never authorised, and the installation token
      // would happily answer for any repository it can see.
      const response = await fetch(
        `${GITHUB_API}/search/issues?${new URLSearchParams({
          q: `repo:${repo.fullName} ${query}`,
          per_page: String(bounded),
        }).toString()}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const body = (await response.json()) as { items?: Array<Record<string, unknown>> };
      return (body.items ?? []).slice(0, bounded).map(summarise);
    },

    async readIssue(accessToken, repoId, issueNumber): Promise<IssueDetail> {
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      const base = `${GITHUB_API}/repos/${repo.fullName}/issues/${String(issueNumber)}`;
      const response = await fetch(base, { headers: headers(accessToken) });
      if (!response.ok) throw new RepoError(response.status);

      const raw = (await response.json()) as Record<string, unknown>;
      // The decision named one issue number. If GitHub answered about another,
      // that is not the approved resource.
      if (num(raw['number']) !== issueNumber) throw new RepoError(409);

      const commentsResponse = await fetch(`${base}/comments?per_page=${String(MAX_COMMENTS)}`, {
        headers: headers(accessToken),
      });
      if (!commentsResponse.ok) throw new RepoError(commentsResponse.status);

      const rawComments: unknown = await commentsResponse.json();
      const comments = (Array.isArray(rawComments) ? rawComments : [])
        .slice(0, MAX_COMMENTS)
        .map((entry) => {
          const c = entry as Record<string, unknown>;
          return {
            author: text((c['user'] as Record<string, unknown> | undefined)?.['login']),
            createdAt: text(c['created_at']),
            body: text(c['body']) ?? '',
          };
        });

      return {
        ...summarise(raw),
        body: text(raw['body']) ?? '',
        comments,
        truncated: (num(raw['comments']) ?? 0) > comments.length,
      };
    },

    async readPullRequest(accessToken, repoId, pullNumber): Promise<PullRequestDetail> {
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      const response = await fetch(
        `${GITHUB_API}/repos/${repo.fullName}/pulls/${String(pullNumber)}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const raw = (await response.json()) as Record<string, unknown>;
      if (num(raw['number']) !== pullNumber) throw new RepoError(409);

      const base = raw['base'] as Record<string, unknown> | undefined;
      const head = raw['head'] as Record<string, unknown> | undefined;

      return {
        ...summarise(raw),
        isPullRequest: true,
        body: text(raw['body']) ?? '',
        baseRef: text(base?.['ref']),
        headRef: text(head?.['ref']),
        merged: raw['merged'] === true,
        changedFiles: num(raw['changed_files']),
      };
    },

    async readDiff(accessToken, repoId, pullNumber): Promise<PullRequestDiff> {
      const repo = await resolveRepo(accessToken, repoId);
      if (repo.fullName === null) throw new RepoError(404);

      const response = await fetch(
        `${GITHUB_API}/repos/${repo.fullName}/pulls/${String(pullNumber)}/files?per_page=${String(
          MAX_DIFF_FILES,
        )}`,
        { headers: headers(accessToken) },
      );
      if (!response.ok) throw new RepoError(response.status);

      const raw: unknown = await response.json();
      const all = Array.isArray(raw) ? raw : [];

      // Two budgets, because either can be the one that blows up: a thousand
      // one-line changes, or one generated file the size of a book.
      const files: DiffFile[] = [];
      let budget = MAX_DIFF_BYTES;

      for (const item of all.slice(0, MAX_DIFF_FILES)) {
        const entry = item as Record<string, unknown>;
        const patch = text(entry['patch']);
        const keep = patch !== null && patch.length <= budget;
        if (keep && patch !== null) budget -= patch.length;

        files.push({
          path: text(entry['filename']) ?? '',
          status: text(entry['status']),
          additions: num(entry['additions']),
          deletions: num(entry['deletions']),
          // A dropped patch still leaves its filename and counts, so the caller
          // learns the file changed rather than that it did not exist.
          patch: keep ? patch : null,
        });
      }

      return {
        number: pullNumber,
        files,
        truncated: all.length > files.length || files.some((f) => f.patch === null),
      };
    },
  };
}
