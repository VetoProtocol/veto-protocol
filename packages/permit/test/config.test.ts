import { describe, expect, it } from 'vitest';
import { PermitConfigError, permitConfigFromEnv } from '../src/config.ts';

const base = { PERMIT_API_KEY: 'permit_key_placeholder' } as NodeJS.ProcessEnv;

describe('permitConfigFromEnv', () => {
  it('refuses to build without an API key', () => {
    expect(() => permitConfigFromEnv({})).toThrow(PermitConfigError);
    expect(() => permitConfigFromEnv({ PERMIT_API_KEY: '   ' })).toThrow(/not set/);
  });

  it('defaults the PDP to the hosted URL', () => {
    expect(permitConfigFromEnv(base).pdpUrl).toBe('https://cloudpdp.api.permit.io');
    expect(permitConfigFromEnv({ ...base, PERMIT_PDP_URL: '' }).pdpUrl).toBe(
      'https://cloudpdp.api.permit.io',
    );
  });

  it('prefers a local PDP when one is configured', () => {
    const config = permitConfigFromEnv({ ...base, PERMIT_PDP_URL: 'http://localhost:7766' });
    expect(config.pdpUrl).toBe('http://localhost:7766');
  });

  it('rejects a nonsense timeout rather than silently falling back', () => {
    // A typo'd timeout that quietly became the default would hide a
    // misconfiguration in exactly the setting that bounds the §11 budget.
    expect(() => permitConfigFromEnv({ ...base, PERMIT_TIMEOUT_MS: '0' })).toThrow(PermitConfigError);
    expect(() => permitConfigFromEnv({ ...base, PERMIT_TIMEOUT_MS: '-1' })).toThrow(PermitConfigError);
    expect(() => permitConfigFromEnv({ ...base, PERMIT_TIMEOUT_MS: 'soon' })).toThrow(PermitConfigError);
    expect(() => permitConfigFromEnv({ ...base, PERMIT_TIMEOUT_MS: '1.5' })).toThrow(PermitConfigError);
  });

  it('applies defaults inside the authorization budget', () => {
    const config = permitConfigFromEnv(base);
    expect(config.timeoutMs).toBe(5_000);
    expect(config.factsSyncTimeoutMs).toBe(10_000);
  });
});
