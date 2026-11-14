import { describe, it, expect } from 'vitest';
import dmarc from '../dmarc-record';
import spf from '../spf-record';
import type { ScanContext } from '../../../types';

function ctx(dns: Partial<ScanContext['dns']>): ScanContext {
  return {
    url: 'https://example.com', finalUrl: 'https://example.com',
    http: { status: 200, headers: {}, bodyHtml: '', redirected: false, timingMs: 1 },
    tls: null, dns: { a: [], aaaa: [], mx: ['mx.example.com'], txt: [], ...dns },
    cookies: [], robotsTxt: null, mentionsLegalesDetected: false,
  };
}

describe('security/dmarc-record', () => {
  it('na sans MX', () => expect(dmarc.evaluate(ctx({ mx: [] })).status).toBe('na'));
  it('fail sans DMARC', () => expect(dmarc.evaluate(ctx({ dmarc: [] })).status).toBe('fail'));
  it('warn avec p=none', () => expect(dmarc.evaluate(ctx({ dmarc: ['v=DMARC1; p=none'] })).status).toBe('warn'));
  it('pass avec p=reject', () => expect(dmarc.evaluate(ctx({ dmarc: ['v=DMARC1; p=reject; rua=mailto:a@b.c'] })).status).toBe('pass'));
  it('pass avec p=quarantine', () => expect(dmarc.evaluate(ctx({ dmarc: ['v=DMARC1;p=quarantine'] })).status).toBe('pass'));
});

describe('security/spf-record permissif', () => {
  it('fail sur +all et ?all', () => {
    expect(spf.evaluate(ctx({ txt: ['v=spf1 +all'] })).status).toBe('fail');
    expect(spf.evaluate(ctx({ txt: ['v=spf1 include:x.com ?all'] })).status).toBe('fail');
  });
  it('pass sur -all et ~all', () => {
    expect(spf.evaluate(ctx({ txt: ['v=spf1 include:x.com -all'] })).status).toBe('pass');
    expect(spf.evaluate(ctx({ txt: ['v=spf1 ~all'] })).status).toBe('pass');
  });
});
