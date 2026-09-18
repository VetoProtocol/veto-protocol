/**
 * Shared state shape for the agent forms.
 *
 * Deliberately not in `actions.ts`. A `'use server'` module may export **only
 * async functions** — every export becomes a callable server endpoint, so a
 * plain object has no meaning there and Next refuses the module at runtime. The
 * type would have been erased harmlessly; the `EMPTY` constant beside it was
 * the problem.
 *
 * `next build` did not catch it. The check runs when the module is required, so
 * the page compiled, deployed, and then failed on first render.
 */

export interface ActionState {
  readonly error: string | null;
  readonly notice: string | null;
}

export const EMPTY: ActionState = { error: null, notice: null };
