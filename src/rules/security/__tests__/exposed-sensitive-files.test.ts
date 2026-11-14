import { describe, it, expect } from 'vitest';
import exposedSensitiveFiles from '../exposed-sensitive-files';
import type { ScanContext } from '../../../types';

function baseCtx(exposedFiles: ScanContext['exposedFiles'] = []): ScanContext {
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
    robotsTxt: null,
    mentionsLegalesDetected: false,
    exposedFiles,
  };
}

describe('security/exposed-sensitive-files', () => {
  it('pass si aucun fichier sensible exposé', () => {
    const result = exposedSensitiveFiles.evaluate(baseCtx([]));
    expect(result.status).toBe('pass');
    expect(result.messageKey).toBe('security.exposed_files.ok');
  });

  it('fail si un fichier .env est exposé', () => {
    const result = exposedSensitiveFiles.evaluate(baseCtx([{ path: '/.env', status: 200 }]));
    expect(result.status).toBe('fail');
    expect(result.messageKey).toBe('security.exposed_files.found');
    expect(result.evidence).toBe('/.env');
  });

  it('liste tous les fichiers exposés dans evidence', () => {
    const result = exposedSensitiveFiles.evaluate(
      baseCtx([
        { path: '/.env', status: 200 },
        { path: '/.git/config', status: 200 },
      ]),
    );
    expect(result.status).toBe('fail');
    expect(result.evidence).toBe('/.env, /.git/config');
  });
});
