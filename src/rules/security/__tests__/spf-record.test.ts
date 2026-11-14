import { describe, it, expect } from 'vitest';
import spfRecord from '../spf-record';
import type { ScanContext } from '../../../types';

function baseCtx(dns: Partial<ScanContext['dns']> = {}): ScanContext {
  return {
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    http: {
      status: 200,
      headers: {},
      bodyHtml: '',
      redirected: false,
      timingMs: 100,
    },
    tls: null,
    dns: {
      a: [],
      aaaa: [],
      mx: [],
      txt: [],
      ...dns,
    },
    cookies: [],
    robotsTxt: null,
    mentionsLegalesDetected: false,
  };
}

describe('security/spf-record', () => {
  it('is not applicable when the domain has no MX records', () => {
    const result = spfRecord.evaluate(baseCtx({ txt: ['v=spf1 -all'] }));

    expect(result.status).toBe('na');
    expect(result.messageKey).toBe('security.spf_record.not_applicable');
  });

  it('fails when a mail domain has no SPF TXT record', () => {
    const result = spfRecord.evaluate(baseCtx({ mx: ['mail.example.com'], txt: [] }));

    expect(result.status).toBe('fail');
    expect(result.messageKey).toBe('security.spf_record.missing');
    expect(result.remediationKey).toBe('security.spf_record.remediation');
  });

  it('ignores unrelated TXT records', () => {
    const result = spfRecord.evaluate(
      baseCtx({ mx: ['mail.example.com'], txt: ['google-site-verification=token'] }),
    );

    expect(result.status).toBe('fail');
  });

  it('passes when an SPF TXT record is present', () => {
    const spf = 'v=SPF1 include:_spf.example.com ~all';
    const result = spfRecord.evaluate(baseCtx({ mx: ['mail.example.com'], txt: [spf] }));

    expect(result.status).toBe('pass');
    expect(result.messageKey).toBe('security.spf_record.ok');
    expect(result.evidence).toBe(spf);
  });
});
