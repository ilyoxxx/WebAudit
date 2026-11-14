import { describe, it, expect } from 'vitest';
import hsts from '../hsts';
import type { ScanContext } from '../../../types';

function baseCtx(overrides: Partial<ScanContext['http']> = {}): ScanContext {
  return {
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    http: {
      status: 200,
      headers: {},
      bodyHtml: '',
      redirected: false,
      timingMs: 100,
      ...overrides,
    },
    tls: null,
    dns: { a: [], aaaa: [], mx: [], txt: [] },
    cookies: [],
    robotsTxt: null,
    mentionsLegalesDetected: false,
  };
}

describe('security/hsts', () => {
  it('fail si le header est absent', () => {
    const result = hsts.evaluate(baseCtx());
    expect(result.status).toBe('fail');
    expect(result.messageKey).toBe('security.hsts.missing');
  });

  it('warn si max-age est trop court', () => {
    const ctx = baseCtx({ headers: { 'strict-transport-security': 'max-age=3600' } });
    const result = hsts.evaluate(ctx);
    expect(result.status).toBe('warn');
  });

  it('pass si max-age est suffisant', () => {
    const ctx = baseCtx({
      headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
    });
    const result = hsts.evaluate(ctx);
    expect(result.status).toBe('pass');
  });
});
