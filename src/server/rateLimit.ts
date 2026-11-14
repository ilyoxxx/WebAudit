import * as net from 'node:net';
import { dataPath, readJson, writeJsonAtomic } from './storage';

const DAY_MS = 24 * 60 * 60 * 1000;

function intEnv(name: string, def: number): number {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) && v > 0 ? v : def;
}

export const FREE_SCANS_PER_DAY = intEnv('FREE_SCANS_PER_DAY', 3);
const FREE_GLOBAL_PER_DAY = intEnv('FREE_GLOBAL_PER_DAY', 500);
export const KEY_SCANS_PER_HOUR = intEnv('KEY_SCANS_PER_HOUR', 120);
const TARGET_SCANS_PER_HOUR = intEnv('TARGET_SCANS_PER_HOUR', 10);

// ---------------------------------------------------------------------------
// Identité réseau : on ne limite pas une adresse IPv6 mais son /64 (un client
// en possède des milliards, sinon le quota est contournable à l'infini).
// ---------------------------------------------------------------------------
function expandV6(addr: string): string[] {
  let a = addr;
  const m = a.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const p = m[1].split('.').map(Number);
    a = `${a.slice(0, -m[1].length)}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  const [head, tail] = a.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const fill = a.includes('::') ? new Array(Math.max(0, 8 - h.length - t.length)).fill('0') : [];
  return [...h, ...fill, ...t].map((g) => g.padStart(4, '0'));
}

export function ipKey(ip: string | undefined): string {
  const v = (ip || '').trim().toLowerCase().split('%')[0];
  if (v.startsWith('::ffff:') && net.isIPv4(v.slice(7))) return v.slice(7);
  if (net.isIPv4(v)) return v;
  if (net.isIPv6(v)) return `${expandV6(v).slice(0, 4).join(':')}::/64`;
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Limiteur à fenêtre fixe, en mémoire (rafales, échecs d'authentification, cibles).
// ---------------------------------------------------------------------------
export class WindowLimiter {
  private map = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly maxKeys = 50_000,
  ) {
    setInterval(() => this.purge(), 5 * 60 * 1000).unref();
  }

  /** Compte un événement. */
  hit(key: string): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    let e = this.map.get(key);
    if (!e || now > e.resetAt) {
      if (this.map.size >= this.maxKeys) this.purge(true);
      e = { count: 0, resetAt: now + this.windowMs };
      this.map.set(key, e);
    }
    e.count += 1;
    return { allowed: e.count <= this.max, retryAfterSec: Math.max(1, Math.ceil((e.resetAt - now) / 1000)) };
  }

  /** Sans compter : le plafond est-il déjà atteint ? */
  blocked(key: string): boolean {
    const e = this.map.get(key);
    return Boolean(e && Date.now() <= e.resetAt && e.count >= this.max);
  }

  private purge(force = false): void {
    const now = Date.now();
    for (const [k, v] of this.map) if (now > v.resetAt) this.map.delete(k);
    if (force && this.map.size >= this.maxKeys) this.map.clear();
  }
}

// ---------------------------------------------------------------------------
// Quota gratuit quotidien : persistant (survit aux redémarrages) + plafond global.
// ---------------------------------------------------------------------------
interface QuotaFile {
  entries: Record<string, { count: number; resetAt: number }>;
  global: { count: number; resetAt: number };
}

class DailyQuota {
  private file = dataPath('free-quota.json');
  private state: QuotaFile;
  private dirty = false;

  constructor() {
    this.state = readJson<QuotaFile>(this.file, { entries: {}, global: { count: 0, resetAt: 0 } });
    this.state.entries ||= {};
    this.state.global ||= { count: 0, resetAt: 0 };
    this.purge();
    setInterval(() => {
      this.purge();
      this.flush();
    }, 10_000).unref();
  }

  private purge(): void {
    const now = Date.now();
    for (const [k, v] of Object.entries(this.state.entries)) if (now > v.resetAt) delete this.state.entries[k];
    const keys = Object.keys(this.state.entries);
    if (keys.length > 200_000) this.state.entries = {};
    if (now > this.state.global.resetAt) this.state.global = { count: 0, resetAt: now + DAY_MS };
    this.dirty = true;
  }

  flush(): void {
    if (!this.dirty) return;
    try {
      writeJsonAtomic(this.file, this.state);
      this.dirty = false;
    } catch (err) {
      console.error('[webaudit] quota: écriture impossible:', (err as Error).message);
    }
  }

  take(key: string): { allowed: boolean; remaining: number; reason?: 'ip' | 'global' } {
    const now = Date.now();
    if (now > this.state.global.resetAt) this.state.global = { count: 0, resetAt: now + DAY_MS };
    if (this.state.global.count >= FREE_GLOBAL_PER_DAY) return { allowed: false, remaining: 0, reason: 'global' };

    let e = this.state.entries[key];
    if (!e || now > e.resetAt) e = this.state.entries[key] = { count: 0, resetAt: now + DAY_MS };
    if (e.count >= FREE_SCANS_PER_DAY) return { allowed: false, remaining: 0, reason: 'ip' };

    e.count += 1;
    this.state.global.count += 1;
    this.dirty = true;
    this.flush(); // écriture immédiate : un redémarrage ne remet pas le compteur à zéro
    return { allowed: true, remaining: FREE_SCANS_PER_DAY - e.count };
  }
}

const quota = new DailyQuota();
export function takeFreeScan(ip: string | undefined) {
  return quota.take(ipKey(ip));
}
export function flushQuota(): void {
  quota.flush();
}

// ---------------------------------------------------------------------------
// Limiteurs partagés
// ---------------------------------------------------------------------------
/** Échecs de clé API (anti brute-force) : 10 par 15 min et par réseau. */
export const badKeyLimiter = new WindowLimiter(10, 15 * 60 * 1000);
/** Utilisation d'une clé : plafond horaire par clé. */
export const keyUsageLimiter = new WindowLimiter(KEY_SCANS_PER_HOUR, 60 * 60 * 1000);
/** Une même cible ne peut pas être martelée via notre service (anti amplification / DoS par rebond). */
export const targetLimiter = new WindowLimiter(TARGET_SCANS_PER_HOUR, 60 * 60 * 1000);
/** Rafales par réseau sur /api/scan, tous modes confondus. */
export const scanBurstLimiter = new WindowLimiter(20, 60 * 1000);
/** Routes d'authentification et de gestion de clés. */
export const authLimiter = new WindowLimiter(30, 10 * 60 * 1000);

// ---------------------------------------------------------------------------
// Concurrence : par réseau et globale.
// ---------------------------------------------------------------------------
const MAX_GLOBAL = intEnv('MAX_CONCURRENT_SCANS', 8);
const MAX_PER_IP = 2;
let globalActive = 0;
const perIp = new Map<string, number>();

export function acquireSlot(ip: string | undefined): (() => void) | 'busy_ip' | 'busy_global' {
  const k = ipKey(ip);
  const n = perIp.get(k) ?? 0;
  if (n >= MAX_PER_IP) return 'busy_ip';
  if (globalActive >= MAX_GLOBAL) return 'busy_global';
  perIp.set(k, n + 1);
  globalActive += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    globalActive -= 1;
    const cur = (perIp.get(k) ?? 1) - 1;
    if (cur <= 0) perIp.delete(k);
    else perIp.set(k, cur);
  };
}
