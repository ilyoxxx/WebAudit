import { describe, it, expect } from 'vitest';
import robotsTxtPresent from '../robots-txt-present';
import type { ScanContext } from '../../../types';

function baseCtx(robotsTxt: string | null): ScanContext {
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
    dns: { a: [], aaaa: [], mx: [], txt: [] },
    cookies: [],
    robotsTxt,
    mentionsLegalesDetected: false,
  };
}

describe('seo/robots-txt-present', () => {
  it('warn si robots.txt est absent', () => {
    const result = robotsTxtPresent.evaluate(baseCtx(null));

    expect(result.status).toBe('warn');
    expect(result.messageKey).toBe('seo.robots_txt_present.missing');
    expect(result.remediationKey).toBe('seo.robots_txt_present.remediation');
  });

  it('pass si robots.txt est disponible', () => {
    const robotsTxt = 'User-agent: *\nDisallow: /private/\n';
    const result = robotsTxtPresent.evaluate(baseCtx(robotsTxt));

    expect(result.status).toBe('pass');
    expect(result.messageKey).toBe('seo.robots_txt_present.ok');
    expect(result.evidence).toBe(robotsTxt);
  });

  it('considère un fichier vide comme présent', () => {
    const result = robotsTxtPresent.evaluate(baseCtx(''));

    expect(result.status).toBe('pass');
  });
});
