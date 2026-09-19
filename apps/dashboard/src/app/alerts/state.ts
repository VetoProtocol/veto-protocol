/**
 * Form state for the alerts screen.
 *
 * Its own file, for the same reason `agents/action-state.ts` is: a `'use server'`
 * module may export **only** async functions — every export becomes a callable
 * endpoint — so a constant declared beside the actions is refused at runtime.
 * `next build` does not catch it; the page compiles and then fails on first
 * render. `test/use-server.test.ts` is the guard.
 *
 * `secret` is separate from `notice` rather than folded into it. It is returned
 * exactly once, it needs to be selectable and monospaced rather than embedded
 * in a sentence, and keeping it its own field means a reload — which clears the
 * action result — takes it away. That disappearance is the intended behaviour:
 * there is no route that reads the secret back, so the only copy is the one the
 * operator saves now.
 */

export interface AlertState {
  readonly error: string | null;
  readonly notice: string | null;
  readonly secret: string | null;
}

export const EMPTY_ALERT: AlertState = { error: null, notice: null, secret: null };
