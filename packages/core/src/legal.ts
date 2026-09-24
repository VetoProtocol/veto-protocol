/**
 * The published legal documents, and which version of each is in force.
 *
 * Here rather than beside the route that serves it, because two places need the
 * same answer and they are in different applications: the control plane records
 * what a person agreed to, and the gateway refuses to act for a person who has
 * not. A copy in each would be a copy that drifts — this codebase has been bitten
 * three times by exactly that shape, and the third one silently broke Drive.
 *
 * Dates, not hashes or file timestamps. A version has to be the thing a person
 * can see at the top of the page they read, and it must not change when somebody
 * reflows a paragraph: raising it re-prompts every user, so it should cost a
 * deliberate decision rather than a stray commit.
 *
 * `apps/api/test/legal.test.ts` asserts these match the dates rendered on the
 * pages themselves.
 */

export const LEGAL_DOCUMENTS = ['terms', 'privacy'] as const;

export type LegalDocument = (typeof LEGAL_DOCUMENTS)[number];

export const CURRENT_LEGAL_VERSIONS: Readonly<Record<LegalDocument, string>> = {
  terms: '2026-09-24',
  privacy: '2026-09-24',
};
