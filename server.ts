import './polyfills';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as cheerio from 'cheerio';

import { collectHttp } from '../collectors/http';
import { collectTls } from '../collectors/tls';
import { collectDns } from '../collectors/dns';
import { collectCookies } from '../collectors/cookies';
import { detectLegalNotice } from '../collectors/legal';
import { loadRules, buildReport } from '../engine/runner';
import type { ScanContext } from '../types';
import { validateKey } from './apiKeys';
import {
  FREE_SCANS_PER_DAY,
  acquireSlot,
  badKeyLimiter,
  flushQuota,
  ipKey,
  keyUsageLimiter,
  scanBurstLimiter,
  takeFreeScan,
  targetLimiter,
} from './rateLimit';
import { registerAuth } from './auth';
import { assertPublicHost, BlockedTargetError, isBlockedError, parseScanTarget } from '../security/ssrf';

const app = express();

// Nombre de proxys de confiance devant l'appli (Railway = 1). Si un CDN s'ajoute (Cloudflare, etc.),
// passer TRUST_PROXY=2 : sinon tous les visiteurs partageraient la même "IP" et le même quota.
const trustProxy = parseInt(process.env.TRUST_PROXY || '1', 10);
app.set('trust proxy', Number.isFinite(trustProxy) && trustProxy >= 0 ? trustProxy : 1);
app.disable('x-powered-by');
app.disable('etag');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const SECURE_SITE = (process.env.BASE_URL || '').startsWith('https://');
const SCAN_DEADLINE_MS = 60_000;

const rules = loadRules();
console.log(`[webaudit] ${rules.length} règle(s) chargée(s): ${rules.map((r) => r.id).join(', ')}`);

// ---------------------------------------------------------------------------
// En-têtes de sécurité (sur toutes les réponses)
// ---------------------------------------------------------------------------
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  'upgrade-insecure-requests',
].join('; ');

app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  if (SECURE_SITE) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  if (req.path.startsWith('/api') || req.path.startsWith('/auth')) {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});

app.use(express.json({ limit: '4kb', strict: true, type: 'application/json' }));
registerAuth(app);

const staticOpts = { dotfiles: 'deny' as const, index: 'index.html', redirect: false };
app.use(express.static(path.join(__dirname, '..', '..', 'public'), staticOpts));
app.use('/locales', express.static(path.join(__dirname, '..', '..', 'locales'), staticOpts));

function detectMentionsLegales(html: string): boolean {
  const $ = cheerio.load(html);
  const linkTexts = $('a')
    .map((_, el) => $(el).text().toLowerCase())
    .get();
  return linkTexts.some(
    (t) => t.includes('mentions légales') || t.includes('mentions legales') || t.includes('legal notice'),
  );
}

const SENSITIVE_PATHS = ['/.env', '/.git/config', '/wp-config.php.bak', '/config.php.bak', '/.DS_Store'];

async function collectExposedFiles(baseUrl: string): Promise<{ path: string; status: number }[]> {
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (p) => {
      try {
        const r = await collectHttp(new URL(p, baseUrl).toString());
        return { path: p, status: r.status };
      } catch {
        return { path: p, status: 0 };
      }
    }),
  );
  return results.filter((f) => f.status === 200);
}

async function runScan(url: string) {
  const [httpResult, tlsResult, dnsResult] = await Promise.all([collectHttp(url), collectTls(url), collectDns(url)]);

  const cookies = collectCookies(httpResult.headers['set-cookie']);
  const legacyLegal = detectMentionsLegales(httpResult.bodyHtml);
  const legal = await detectLegalNotice(httpResult.finalUrl || url, httpResult.bodyHtml, httpResult.status);

  let robotsTxt: string | null = null;
  try {
    const robotsResp = await collectHttp(new URL('/robots.txt', url).toString());
    robotsTxt = robotsResp.status === 200 ? robotsResp.bodyHtml : null;
  } catch {
    robotsTxt = null;
  }

  const exposedFiles = await collectExposedFiles(url);

  const ctx: ScanContext = {
    url,
    finalUrl: httpResult.finalUrl,
    http: {
      status: httpResult.status,
      headers: httpResult.headers,
      bodyHtml: httpResult.bodyHtml,
      redirected: httpResult.redirected,
      timingMs: httpResult.timingMs,
    },
    tls: tlsResult,
    dns: dnsResult,
    cookies,
    robotsTxt,
    mentionsLegalesDetected: legal.found || legacyLegal,
    mentionsLegalesInconclusive: legal.inconclusive,
    mentionsLegalesEvidence: legal.evidence,
    exposedFiles,
  };

  return buildReport(url, ctx, rules);
}

function tooMany(res: Response, error: string, message: string, retryAfterSec?: number) {
  if (retryAfterSec) res.setHeader('Retry-After', String(retryAfterSec));
  return res.status(429).json({ error, message });
}

app.post('/api/scan', async (req: Request, res: Response) => {
  const ip = req.ip;
  const net = ipKey(ip);

  // 0. Rafales : plafond par réseau, quel que soit le mode (clé ou gratuit).
  const burst = scanBurstLimiter.hit(net);
  if (!burst.allowed) return tooMany(res, 'too_many_requests', 'Trop de requêtes, réessaie dans un instant.', burst.retryAfterSec);

  // 1. Entrée : forme stricte.
  const rawUrl = req.body?.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'invalid_request', message: 'Champ "url" manquant ou invalide.' });
  }

  // 2. Cible : schéma, port, nom d'hôte (pas d'IP, pas de nom interne), puis résolution DNS publique.
  const target = parseScanTarget(rawUrl);
  if (!target.ok) {
    return res.status(400).json({ error: 'invalid_target', message: 'Adresse non valide. Saisis le nom de domaine d\'un site public.' });
  }
  try {
    await assertPublicHost(target.url.hostname);
  } catch (err) {
    if (isBlockedError(err)) {
      return res.status(400).json({ error: 'target_not_allowed', message: 'Cette adresse n\'est pas autorisée.' });
    }
    return res.status(400).json({ error: 'target_unreachable', message: 'Ce domaine est introuvable.' });
  }

  // 3. Authentification / quota.
  const header = req.headers['x-api-key'];
  if (Array.isArray(header)) {
    return res.status(400).json({ error: 'invalid_request', message: 'En-tête x-api-key invalide.' });
  }
  let remaining: number | null = null;

  if (typeof header === 'string' && header.length > 0) {
    if (badKeyLimiter.blocked(net)) {
      return tooMany(res, 'too_many_requests', 'Trop de tentatives, réessaie plus tard.', 900);
    }
    const keyId = header.length <= 128 ? validateKey(header) : null;
    if (!keyId) {
      const r = badKeyLimiter.hit(net);
      if (!r.allowed) return tooMany(res, 'too_many_requests', 'Trop de tentatives, réessaie plus tard.', r.retryAfterSec);
      return res.status(401).json({ error: 'invalid_api_key' });
    }
    const usage = keyUsageLimiter.hit(keyId);
    if (!usage.allowed) {
      return tooMany(res, 'key_rate_limited', 'Plafond horaire de cette clé atteint.', usage.retryAfterSec);
    }
  } else {
    const q = takeFreeScan(ip);
    if (!q.allowed) {
      if (q.reason === 'global') {
        return tooMany(res, 'free_capacity_reached', 'Le service gratuit est saturé aujourd\'hui. Réessaie demain ou utilise une clé API.');
      }
      return tooMany(
        res,
        'free_limit_reached',
        `Limite de ${FREE_SCANS_PER_DAY} scans gratuits/jour atteinte. Connecte-toi pour obtenir une clé API.`,
      );
    }
    remaining = q.remaining;
  }

  // 4. On ne laisse pas notre service servir à marteler un tiers.
  const host = target.url.hostname.toLowerCase().replace(/^www\./, '');
  const perTarget = targetLimiter.hit(host);
  if (!perTarget.allowed) {
    return tooMany(res, 'target_rate_limited', 'Ce site a déjà été analysé de nombreuses fois récemment.', perTarget.retryAfterSec);
  }

  // 5. Concurrence bornée.
  const slot = acquireSlot(ip);
  if (typeof slot === 'string') {
    return tooMany(res, 'busy', 'Trop d\'analyses en cours, réessaie dans quelques secondes.', 5);
  }

  if (remaining !== null) res.setHeader('X-RateLimit-Remaining', String(remaining));

  let timer: NodeJS.Timeout | undefined;
  try {
    const report = await Promise.race([
      runScan(target.url.toString()),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('scan_deadline')), SCAN_DEADLINE_MS);
      }),
    ]);
    res.json(report);
  } catch (err) {
    // Détail uniquement dans les logs : le message d'erreur réseau (ex. "ECONNREFUSED 127.0.0.1:3000")
    // révèle sinon quels ports/hôtes répondent.
    console.error('[webaudit] scan failed:', err instanceof Error ? err.message : 'unknown');
    if (isBlockedError(err) || err instanceof BlockedTargetError) {
      return res.status(400).json({ error: 'target_not_allowed', message: 'Cette adresse n\'est pas autorisée.' });
    }
    res.status(502).json({ error: 'scan_failed', message: 'Impossible d\'analyser ce site pour le moment.' });
  } finally {
    if (timer) clearTimeout(timer);
    slot();
  }
});

app.get('/api/rules', (_req, res) => {
  res.json(rules.map((r) => ({ id: r.id, category: r.category, weight: r.weight, docs: r.docs })));
});

// ---------------------------------------------------------------------------
// 404 + gestion d'erreurs : jamais de stack trace envoyée au client, jamais de crash.
// ---------------------------------------------------------------------------
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'not_found' });
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const e = err as { type?: string; status?: number; statusCode?: number };
  if (res.headersSent) return;
  if (e?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'invalid_json', message: 'Corps de requête JSON invalide.' });
  }
  if (e?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'payload_too_large' });
  }
  const status = e?.status || e?.statusCode;
  if (typeof status === 'number' && status >= 400 && status < 500) {
    return res.status(status).json({ error: 'bad_request' });
  }
  const id = crypto.randomBytes(4).toString('hex');
  console.error(`[webaudit] erreur interne #${id}:`, err instanceof Error ? err.message : 'unknown');
  res.status(500).json({ error: 'server_error', ref: id });
});

const server = app.listen(PORT, () => {
  console.log(`[webaudit] serveur démarré sur http://localhost:${PORT}`);
});

// Anti slowloris / connexions zombies.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;

process.on('unhandledRejection', (reason) => {
  console.error('[webaudit] unhandledRejection:', reason instanceof Error ? reason.message : String(reason));
});
process.on('uncaughtException', (err) => {
  console.error('[webaudit] uncaughtException:', err.message);
  flushQuota();
  process.exit(1);
});
for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    flushQuota();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
