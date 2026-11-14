import { describe, it, expect } from 'vitest';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import { assertPublicHost, guardedLookup, isBlockedError, isBlockedIp, parseScanTarget } from '../ssrf';
import { collectHttp } from '../../collectors/http';

describe('isBlockedIp', () => {
  it.each([
    '127.0.0.1', '127.255.255.254', '0.0.0.0', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '64:ff9b::7f00:1', '2002:7f00:1::1',
    'not-an-ip',
  ])('bloque %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111'])('autorise %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });
});

describe('parseScanTarget', () => {
  it.each([
    'http://127.0.0.1', '127.0.0.1', 'https://127.0.0.1:3000', 'http://localhost', 'localhost:3000', 'http://[::1]/',
    'http://2130706433/', 'http://0x7f.0.0.1/', 'http://0177.0.0.1/', 'http://127.1/', 'http://0/',
    'http://169.254.169.254/latest/meta-data', 'http://metadata.google.internal', 'http://redis',
    'https://app.railway.internal', 'http://printer.local', 'http://foo.localhost', 'http://user:pass@example.com',
    'https://example.com:6379', 'https://example.com:22', 'ftp://example.com', 'file:///etc/passwd',
    'javascript:alert(1)', 'gopher://example.com', 'https://exa mple.com', 'https://example.com\n.evil.com',
    'http://[::ffff:127.0.0.1]/', 'http://10.0.0.1', 'http://192.168.0.1:8080', '',
    'a'.repeat(3000),
  ])('refuse %j', (input) => {
    expect(parseScanTarget(input).ok).toBe(false);
  });

  it.each(['example.com', 'https://example.com', 'http://www.example.fr/path?x=1', 'https://example.com:443', 'sub.domain.example.org'])(
    'accepte %s',
    (input) => {
      expect(parseScanTarget(input).ok).toBe(true);
    },
  );

  it('retire le fragment', () => {
    const r = parseScanTarget('https://example.com/#secret');
    expect(r.ok && r.url.hash).toBe('');
  });
});

describe('garde réseau', () => {
  it('assertPublicHost refuse un nom qui résout vers du loopback', async () => {
    await expect(assertPublicHost('localhost')).rejects.toSatisfy(isBlockedError);
  });

  it('guardedLookup refuse la connexion vers du loopback (anti DNS-rebinding)', async () => {
    const err = await new Promise<unknown>((resolve) => guardedLookup('localhost', {}, (e) => resolve(e)));
    expect(isBlockedError(err)).toBe(true);
  });

  it('collectHttp ne contacte jamais un serveur local', async () => {
    let hit = 0;
    const srv = http.createServer((_req, res) => {
      hit++;
      res.end('secret interne');
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as AddressInfo).port;
    try {
      await expect(collectHttp(`http://127.0.0.1:${port}/`)).rejects.toThrow();
      await expect(collectHttp(`http://localhost:${port}/`)).rejects.toThrow();
      expect(hit).toBe(0);
    } finally {
      srv.close();
    }
  });
});
