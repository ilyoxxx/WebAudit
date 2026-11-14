import * as dns from 'node:dns';
import * as net from 'node:net';

/**
 * Garde anti-SSRF.
 *
 * Trois lignes de défense :
 *  1. parseScanTarget / validateUrlObject : schéma, port, identifiants, nom d'hôte (pas d'IP littérale,
 *     pas de nom interne), vérifiés sur l'URL saisie ET sur chaque redirection.
 *  2. assertPublicHost : résolution DNS préalable, refus si UNE SEULE adresse est non publique.
 *  3. guardedLookup : vérification au moment de la connexion TCP (bloque le DNS rebinding,
 *     puisque l'adresse validée est celle réellement utilisée).
 */

export class BlockedTargetError extends Error {
  readonly code = 'EBLOCKED';
  constructor(public readonly reason: string) {
    super(`blocked_target:${reason}`);
    this.name = 'BlockedTargetError';
  }
}

/** Remonte la chaîne `cause` (undici enveloppe les erreurs dans "fetch failed"). */
export function isBlockedError(err: unknown): boolean {
  let e: unknown = err;
  for (let i = 0; i < 6 && e; i++) {
    if (e instanceof BlockedTargetError) return true;
    if ((e as { code?: string }).code === 'EBLOCKED') return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

// Uniquement pour les tests automatisés (NODE_ENV=test + variable explicite). Jamais actif en production.
function testBypass(): boolean {
  return process.env.NODE_ENV === 'test' && process.env.WEBAUDIT_TEST_ALLOW_PRIVATE === '1';
}

const BLOCKED = new net.BlockList();
const V4: [string, number][] = [
  ['0.0.0.0', 8], // "ce réseau"
  ['10.0.0.0', 8], // privé
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local + métadonnées cloud (169.254.169.254)
  ['172.16.0.0', 12], // privé
  ['192.0.0.0', 24], // IETF
  ['192.0.2.0', 24], // doc
  ['192.88.99.0', 24], // 6to4 relay
  ['192.168.0.0', 16], // privé
  ['198.18.0.0', 15], // benchmark
  ['198.51.100.0', 24], // doc
  ['203.0.113.0', 24], // doc
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // réservé + broadcast
];
const V6: [string, number][] = [
  ['::', 128], // non spécifiée
  ['::1', 128], // loopback
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48],
  ['100::', 64], // discard
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // doc
  ['2002::', 16], // 6to4
  ['fc00::', 7], // ULA (privé)
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (obsolète)
  ['ff00::', 8], // multicast
];
for (const [a, p] of V4) BLOCKED.addSubnet(a, p, 'ipv4');
for (const [a, p] of V6) BLOCKED.addSubnet(a, p, 'ipv6');

export function isBlockedIp(ip: string): boolean {
  if (testBypass()) return false;
  const clean = ip.split('%')[0];
  const fam = net.isIP(clean);
  if (fam === 0) return true; // pas une IP valide : on refuse
  if (fam === 6) {
    // IPv4-mapped (::ffff:a.b.c.d) refusé en bloc, toutes écritures confondues. (Une règle de sous-réseau
    // ::ffff:0:0/96 dans BlockList bloquerait AUSSI toutes les IPv4, d'où ce test explicite.)
    try {
      if (new URL(`http://[${clean}]/`).hostname.startsWith('[::ffff:')) return true;
    } catch {
      return true;
    }
  }
  return BLOCKED.check(clean, fam === 4 ? 'ipv4' : 'ipv6');
}

const FORBIDDEN_SUFFIXES = [
  'localhost',
  'local',
  'localdomain',
  'internal',
  'intranet',
  'lan',
  'home',
  'corp',
  'private',
  'arpa',
  'onion',
  'test',
  'invalid',
  'example',
];

const OWN_HOST = (() => {
  try {
    return new URL(process.env.BASE_URL || '').hostname.toLowerCase();
  } catch {
    return '';
  }
})();

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;

function checkHostname(rawHost: string): string | null {
  const host = rawHost.toLowerCase().replace(/\.$/, '');
  if (!host) return 'empty_host';
  if (host.startsWith('[') || net.isIP(host) !== 0) return 'ip_literal';
  if (!host.includes('.')) return 'single_label';
  if (!HOST_RE.test(host)) return 'bad_host';
  const tld = host.slice(host.lastIndexOf('.') + 1);
  if (/^\d+$/.test(tld) || /^0x/i.test(tld)) return 'numeric_tld'; // formes d'IP exotiques
  if (FORBIDDEN_SUFFIXES.includes(tld)) return 'forbidden_suffix';
  if (host.endsWith('.home.arpa')) return 'forbidden_suffix';
  if (OWN_HOST && host === OWN_HOST && process.env.ALLOW_SELF_SCAN !== '1') return 'self';
  return null;
}

/** Retourne une raison de refus, ou null si l'URL est acceptable. */
export function validateUrlObject(u: URL): string | null {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'bad_protocol';
  if (testBypass()) return null;
  if (u.username || u.password) return 'credentials';
  if (u.port !== '' && u.port !== '80' && u.port !== '443') return 'bad_port';
  return checkHostname(u.hostname);
}

export type TargetResult = { ok: true; url: URL } | { ok: false; reason: string };

export function parseScanTarget(raw: string): TargetResult {
  const input = raw.trim();
  if (!input || input.length > 2048) return { ok: false, reason: 'bad_length' };
  if (/[\u0000-\u001f\u007f\s]/.test(input)) return { ok: false, reason: 'bad_chars' };

  let candidate = input;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    if (!/^https?:\/\//i.test(candidate)) return { ok: false, reason: 'bad_protocol' };
  } else {
    candidate = `https://${candidate}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, reason: 'bad_url' };
  }
  const reason = validateUrlObject(url);
  if (reason) return { ok: false, reason };
  url.hash = '';
  return { ok: true, url };
}

/** Résout le nom et refuse si l'une des adresses n'est pas publique. */
export async function assertPublicHost(hostname: string): Promise<void> {
  if (testBypass()) return;
  const addrs = await dns.promises.lookup(hostname.replace(/^\[|\]$/g, ''), { all: true, verbatim: true });
  if (addrs.length === 0) throw new BlockedTargetError('no_address');
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw new BlockedTargetError('private_address');
  }
}

type LookupCb = (err: NodeJS.ErrnoException | null, address?: unknown, family?: number) => void;

/**
 * `lookup` à injecter dans net/tls/undici : la résolution est refaite ici et l'adresse
 * validée est celle qui sert à la connexion (anti DNS-rebinding).
 */
export function guardedLookup(hostname: string, options: unknown, callback: LookupCb): void {
  const opts: dns.LookupOptions =
    typeof options === 'number' ? { family: options } : { ...((options as dns.LookupOptions) || {}) };
  const wantAll = Boolean(opts.all);
  dns.lookup(hostname, { ...opts, all: true, verbatim: true }, (err, addrs) => {
    if (err) return callback(err);
    const list = addrs as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => isBlockedIp(a.address))) {
      return callback(new BlockedTargetError('private_address'));
    }
    if (wantAll) return callback(null, list);
    callback(null, list[0].address, list[0].family);
  });
}
