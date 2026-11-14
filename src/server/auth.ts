import * as crypto from 'node:crypto';
import type { Express, Request, Response, NextFunction } from 'express';
import { createKeyForOwner, listKeysFor, revokeKeyById, MAX_KEYS_PER_OWNER } from './apiKeys';
import { createSession, getSessionByToken, destroySession, SESSION_TTL_MS } from './sessions';
import { authLimiter, ipKey } from './rateLimit';

const SECRET = process.env.SESSION_SECRET || '';
const CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const SECURE = BASE_URL.startsWith('https://');
const BASE_ORIGIN = (() => {
  try {
    return new URL(BASE_URL).origin;
  } catch {
    return '';
  }
})();

// Préfixe __Host- (HTTPS uniquement) : le navigateur refuse que le cookie soit posé par un sous-domaine,
// ou sans Secure / Path=/, ce qui bloque la fixation de cookie.
const PREFIX = SECURE ? '__Host-' : '';
const SESSION_COOKIE = `${PREFIX}wa_session`;
const STATE_COOKIE = `${PREFIX}wa_state`;

if (SECRET && SECRET.length < 32) {
  console.warn('[webaudit] SESSION_SECRET trop court (32 caractères minimum) : connexion GitHub désactivée.');
}
if (BASE_URL && !SECURE && process.env.NODE_ENV === 'production') {
  console.warn('[webaudit] BASE_URL n\'est pas en https:// : les cookies ne seront PAS marqués Secure.');
}

function configured(): boolean {
  return Boolean(SECRET.length >= 32 && CLIENT_ID && CLIENT_SECRET && BASE_URL);
}

function sign(value: string): string {
  const body = Buffer.from(value).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function unsign(token: string | undefined): string | null {
  if (!token || token.length > 1024) return null;
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(parts[0]).digest('base64url');
  if (!safeEqual(parts[1], expected)) return null;
  return Buffer.from(parts[0], 'base64url').toString();
}

/**
 * Lecture des cookies sans jamais lever d'exception : un cookie mal encodé
 * (ex. "a=%E0%A4%A") faisait planter tout le serveur (URIError: URI malformed).
 */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  if (!header || header.length > 8192) return out;
  const parts = header.split(';', 64);
  for (const part of parts) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const name = part.slice(0, i).trim();
    if (!/^[\w.-]{1,64}$/.test(name) || name === '__proto__') continue;
    let value = part.slice(i + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      continue; // valeur illisible : on l'ignore simplement
    }
  }
  return out;
}

function setCookie(
  res: Response,
  name: string,
  value: string,
  maxAgeSec: number,
  sameSite: 'Strict' | 'Lax' = 'Lax',
): void {
  const flags = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', `SameSite=${sameSite}`, `Max-Age=${maxAgeSec}`];
  if (maxAgeSec <= 0) flags.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  if (SECURE) flags.push('Secure');
  res.append('Set-Cookie', flags.join('; '));
}

interface AuthedSession {
  token: string;
  userId: number;
  login: string;
}

function getSession(req: Request): AuthedSession | null {
  if (!configured()) return null;
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  const s = getSessionByToken(token);
  if (!s) return null;
  return { token, userId: s.userId, login: s.login };
}

/**
 * Anti-CSRF pour les actions qui modifient l'état :
 *  - en-tête personnalisé (impossible à poser cross-origin sans préflight CORS),
 *  - Origin identique à BASE_URL si présent,
 *  - Sec-Fetch-Site same-origin/none si présent.
 */
function csrfOk(req: Request): boolean {
  if (req.headers['x-requested-with'] !== 'webaudit') return false;
  const origin = req.headers.origin;
  if (origin !== undefined && BASE_ORIGIN && origin !== BASE_ORIGIN) return false;
  const site = req.headers['sec-fetch-site'];
  if (typeof site === 'string' && site !== 'same-origin' && site !== 'none') return false;
  return true;
}

function rateGuard(req: Request, res: Response, next: NextFunction): void {
  const r = authLimiter.hit(ipKey(req.ip));
  if (!r.allowed) {
    res.setHeader('Retry-After', String(r.retryAfterSec));
    res.status(429).json({ error: 'too_many_requests' });
    return;
  }
  next();
}

const b64url = (b: Buffer) => b.toString('base64url');

export function registerAuth(app: Express): void {
  app.use(['/auth', '/api/me', '/api/keys'], rateGuard);

  app.get('/auth/github', (_req: Request, res: Response) => {
    if (!configured()) {
      return res.status(503).send('Connexion GitHub non configurée sur ce serveur.');
    }
    const state = crypto.randomBytes(24).toString('hex');
    // PKCE : le "verifier" ne quitte jamais le navigateur de l'utilisateur (cookie HttpOnly signé).
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    setCookie(res, STATE_COOKIE, sign(JSON.stringify({ s: state, v: verifier })), 600, 'Lax');
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: `${BASE_URL}/auth/github/callback`,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });

  app.get('/auth/github/callback', async (req: Request, res: Response) => {
    if (!configured()) return res.status(503).send('Connexion GitHub non configurée.');

    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const rawState = unsign(parseCookies(req.headers.cookie)[STATE_COOKIE]);
    setCookie(res, STATE_COOKIE, '', 0, 'Lax'); // usage unique

    let expected: { s?: string; v?: string } = {};
    try {
      expected = rawState ? JSON.parse(rawState) : {};
    } catch {
      expected = {};
    }

    if (
      !/^[\w.-]{10,200}$/.test(code) ||
      !/^[a-f0-9]{48}$/.test(state) ||
      !expected.s ||
      !expected.v ||
      !safeEqual(expected.s, state)
    ) {
      return res.status(400).send('Connexion refusée (état invalide). Recommence depuis le site.');
    }

    try {
      const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code,
          redirect_uri: `${BASE_URL}/auth/github/callback`,
          code_verifier: expected.v,
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (!tokenResp.ok) throw new Error('token_http');
      const tokenJson = (await tokenResp.json()) as { access_token?: string };
      if (!tokenJson.access_token || typeof tokenJson.access_token !== 'string') throw new Error('no_token');

      const userResp = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${tokenJson.access_token}`,
          'User-Agent': 'webaudit',
          Accept: 'application/vnd.github+json',
        },
        signal: AbortSignal.timeout(8000),
      });
      if (!userResp.ok) throw new Error('user_http');
      const user = (await userResp.json()) as { id?: number; login?: string };
      if (!Number.isInteger(user.id) || typeof user.login !== 'string' || !/^[\w-]{1,39}$/.test(user.login)) {
        throw new Error('no_user');
      }

      // Nouveau jeton à chaque connexion (pas de fixation de session) ; cookie Strict : jamais envoyé cross-site.
      const token = createSession(user.id as number, user.login);
      setCookie(res, SESSION_COOKIE, token, Math.floor(SESSION_TTL_MS / 1000), 'Strict');
      res.redirect('/#cles-api');
    } catch (err) {
      console.error('[webaudit] auth github failed:', err instanceof Error ? err.message : 'unknown');
      res.status(502).send('Connexion GitHub impossible pour le moment. Réessaie dans un instant.');
    }
  });

  app.post('/auth/logout', (req: Request, res: Response) => {
    if (!csrfOk(req)) return res.status(403).json({ error: 'forbidden' });
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    destroySession(token); // révocation côté serveur
    setCookie(res, SESSION_COOKIE, '', 0, 'Strict');
    res.json({ ok: true });
  });

  app.get('/api/me', (req: Request, res: Response) => {
    const s = getSession(req);
    res.json({
      configured: configured(),
      loggedIn: Boolean(s),
      login: s?.login ?? null,
      maxKeys: MAX_KEYS_PER_OWNER,
    });
  });

  app.get('/api/keys', (req: Request, res: Response) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'not_logged_in' });
    res.json({ keys: listKeysFor(`github:${s.userId}`), max: MAX_KEYS_PER_OWNER });
  });

  app.post('/api/keys', (req: Request, res: Response) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'not_logged_in' });
    if (!csrfOk(req)) return res.status(403).json({ error: 'forbidden' });
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    try {
      const key = createKeyForOwner(`github:${s.userId}`, name);
      res.status(201).json({ key, keys: listKeysFor(`github:${s.userId}`), max: MAX_KEYS_PER_OWNER });
    } catch (err) {
      if (err instanceof Error && err.message === 'key_limit_reached') {
        return res.status(409).json({
          error: 'key_limit_reached',
          message: `Limite de ${MAX_KEYS_PER_OWNER} clés atteinte. Supprime une clé pour en créer une nouvelle.`,
        });
      }
      console.error('[webaudit] create key failed:', err instanceof Error ? err.message : 'unknown');
      res.status(500).json({ error: 'server_error' });
    }
  });

  app.delete('/api/keys/:id', (req: Request, res: Response) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'not_logged_in' });
    if (!csrfOk(req)) return res.status(403).json({ error: 'forbidden' });
    if (!/^[a-f0-9]{16}$/.test(req.params.id)) return res.status(404).json({ error: 'not_found' });
    const ok = revokeKeyById(`github:${s.userId}`, req.params.id);
    if (!ok) return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true, keys: listKeysFor(`github:${s.userId}`), max: MAX_KEYS_PER_OWNER });
  });
}
