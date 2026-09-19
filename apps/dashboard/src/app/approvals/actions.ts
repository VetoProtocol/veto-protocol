'use server';

import { revalidatePath } from 'next/cache';
import {
  ApiError,
  approvalChallenge,
  enrolPasskey,
  passkeyRegistrationOptions,
  resolveApproval,
} from '@/lib/api';
import { currentSession } from '@/lib/session';

/**
 * The browser half of a ceremony cannot happen on the server, so these actions
 * are the two ends: fetch what the device must sign, and hand the signature
 * back. The signing itself happens in the client component, where the
 * authenticator is.
 */

export async function fetchRegistrationOptions(): Promise<Record<string, unknown>> {
  const session = await currentSession();
  if (!session) throw new Error('signed out');
  return passkeyRegistrationOptions(session.credential);
}

export async function completeRegistration(
  response: unknown,
  label: string,
): Promise<{ ok: boolean; message: string }> {
  const session = await currentSession();
  if (!session) return { ok: false, message: 'Your session has expired. Sign in again.' };

  try {
    await enrolPasskey(session.credential, {
      response,
      ...(label.trim() === '' ? {} : { label: label.trim() }),
    });
    revalidatePath('/approvals');
    return { ok: true, message: 'Passkey enrolled.' };
  } catch (error) {
    return { ok: false, message: describe(error) };
  }
}

export async function fetchApprovalChallenge(approvalId: string): Promise<Record<string, unknown>> {
  const session = await currentSession();
  if (!session) throw new Error('signed out');
  return approvalChallenge(session.credential, approvalId);
}

export async function submitResolution(
  approvalId: string,
  decision: 'approved' | 'denied',
  assertion: unknown,
): Promise<{ ok: boolean; message: string }> {
  const session = await currentSession();
  if (!session) return { ok: false, message: 'Your session has expired. Sign in again.' };

  try {
    const result = await resolveApproval(session.credential, approvalId, { decision, assertion });
    revalidatePath('/approvals');
    return { ok: true, message: `Approval ${result.status}.` };
  } catch (error) {
    return { ok: false, message: describe(error) };
  }
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.failure.code) {
      case 'APPROVER_NOT_DELEGATOR':
        // Covers every refusal the resolve route gives, deliberately: it does
        // not distinguish "not yours" from "does not exist" from "bad
        // signature", and neither should this.
        return 'That approval could not be resolved with this device.';
      case 'APPROVAL_REPLAYED':
        return 'That signature has already been used.';
      case 'APPROVAL_EXPIRED':
        return 'That approval has expired. The agent will have to ask again.';
      default:
        return error.failure.message;
    }
  }
  return 'Something went wrong talking to the control plane.';
}
