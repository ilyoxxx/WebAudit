import { describe, it, expect } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';

process.env.DATA_DIR = path.join(os.tmpdir(), `webaudit-test-${process.pid}`);

describe('parseCookies', () => {
  it('ne plante jamais sur un cookie mal encodé (URIError: URI malformed)', async () => {
    const { parseCookies } = await import('../auth');
    expect(() => parseCookies('wa_session=%E0%A4%A; ok=1')).not.toThrow();
    const c = parseCookies('wa_session=%E0%A4%A; ok=1; __proto__=x; a=%41');
    expect(c.wa_session).toBeUndefined();
    expect(c.ok).toBe('1');
    expect(c.a).toBe('A');
    expect(Object.getPrototypeOf(c)).toBeNull();
  });

  it('borne la taille et le nombre de cookies', async () => {
    const { parseCookies } = await import('../auth');
    expect(parseCookies('a=' + 'x'.repeat(9000))).toEqual({});
    const many = Array.from({ length: 200 }, (_, i) => `c${i}=1`).join('; ');
    expect(Object.keys(parseCookies(many)).length).toBeLessThanOrEqual(64);
  });
});

describe('ipKey (contournement du quota par IPv6)', () => {
  it('regroupe un /64 IPv6 et normalise IPv4-mapped', async () => {
    const { ipKey } = await import('../rateLimit');
    expect(ipKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd')).toBe(ipKey('2001:db8:1:2::1'));
    expect(ipKey('2001:db8:1:3::1')).not.toBe(ipKey('2001:db8:1:2::1'));
    expect(ipKey('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(ipKey(undefined)).toBe('unknown');
  });
});

describe('quota gratuit', () => {
  it('bloque après la limite et ne se contourne pas en changeant la fin de l\'IPv6', async () => {
    const { takeFreeScan, FREE_SCANS_PER_DAY } = await import('../rateLimit');
    const base = '2001:db8:9:9:';
    for (let i = 0; i < FREE_SCANS_PER_DAY; i++) expect(takeFreeScan(`${base}${i}::1`).allowed).toBe(true);
    expect(takeFreeScan(`${base}ffff::2`).allowed).toBe(false);
  });
});

describe('clés API', () => {
  it('stocke des empreintes, rejette les formats invalides', async () => {
    const { generateKey, validateKey, listKeys } = await import('../apiKeys');
    const key = generateKey('test');
    expect(validateKey(key)).not.toBeNull();
    expect(validateKey(key + 'x')).toBeNull();
    expect(validateKey('')).toBeNull();
    expect(JSON.stringify(listKeys())).not.toContain(key);
  });
});

describe('sessions serveur', () => {
  it('une session détruite ne fonctionne plus', async () => {
    const { createSession, getSessionByToken, destroySession } = await import('../sessions');
    const t = createSession(42, 'alice');
    expect(getSessionByToken(t)?.login).toBe('alice');
    destroySession(t);
    expect(getSessionByToken(t)).toBeNull();
    expect(getSessionByToken('x'.repeat(43))).toBeNull();
  });
});
