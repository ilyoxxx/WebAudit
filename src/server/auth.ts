import * as crypto from 'node:crypto';
import type { Express, Request, Response } from 'express';
import { createKeyForOwner, listKeysFor, revokeKeyById, MAX_KEYS_PER_OWNER } from './apiKeys';

const SECRET = process.env.SESSION_SECRET || '';
const CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const SECURE = BASE_URL.startsWith('https://');
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE = 'wa_session';
const STATE_COOKIE = 'wa_state';

interface Session {
  id: number;
  login: string;
  exp: number;
}

function configured(): boolean {
  return Boolean(SECRET && CLIENT_ID && CLIENT_SECRET && BASE_URL);
}

function sign(value: string): string {
  const body = Buffer.from(value).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function unsign(token: string | undefined): string | null {
  if (!token) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return Buffer.from(body, 'base64url').toString();
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setCookie(res: Response, name: string, value: string, maxAgeSec: number): void {
  const flags = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (SECURE) flags.push('Secure');
  res.append('Set-Cookie', flags.join('; '));
}

function getSession(req: Request): Session | null {
  if (!configured()) return null;
  const raw = unsign(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as Session;
    if (!s.id || !s.login || s.exp < Date.now()) return null;
    return s;
  } catch {
    return null;
  }
}

function sameSiteGuard(req: Request): boolean {
  return req.headers['x-requested-with'] === 'webaudit';
}

export function registerAuth(app: Express): void {
  app.get('/auth/github', (_req: Request, res: Response) => {
    if (!configured()) {
      return res.status(503).send('Connexion GitHub non configurée sur ce serveur.');
    }
    const state = crypto.randomBytes(16).toString('hex');
    setCookie(res, STATE_COOKIE, sign(state), 600);
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: `${BASE_URL}/auth/github/callback`,
      state,
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });

  app.get('/auth/github/callback', async (req: Request, res: Response) => {
    if (!configured()) return res.status(503).send('Connexion GitHub non configurée.');

    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const expected = unsign(parseCookies(req.headers.cookie)[STATE_COOKIE]);
    setCookie(res, STATE_COOKIE, '', 0);

    if (!code || !state || !expected || expected !== state) {
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
        }),
      });
      const tokenJson = (await tokenResp.json()) as { access_token?: string };
      if (!tokenJson.access_token) throw new Error('no_token');

      const userResp = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${tokenJson.access_token}`,
          'User-Agent': 'webaudit',
          Accept: 'application/vnd.github+json',
        },
      });
      const user = (await userResp.json()) as { id?: number; login?: string };
      if (!user.id || !user.login) throw new Error('no_user');

      const session: Session = { id: user.id, login: user.login, exp: Date.now() + SESSION_TTL_MS };
      setCookie(res, SESSION_COOKIE, sign(JSON.stringify(session)), SESSION_TTL_MS / 1000);
      res.redirect('/#cles-api');
    } catch (err) {
      console.error('[webaudit] auth github failed:', err);
      res.status(502).send('Connexion GitHub impossible pour le moment. Réessaie dans un instant.');
    }
  });

  app.post('/auth/logout', (req: Request, res: Response) => {
    if (!sameSiteGuard(req)) return res.status(403).json({ error: 'forbidden' });
    setCookie(res, SESSION_COOKIE, '', 0);
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
    res.json({ keys: listKeysFor(`github:${s.id}`), max: MAX_KEYS_PER_OWNER });
  });

  app.post('/api/keys', (req: Request, res: Response) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'not_logged_in' });
    if (!sameSiteGuard(req)) return res.status(403).json({ error: 'forbidden' });
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    try {
      const key = createKeyForOwner(`github:${s.id}`, name);
      res.status(201).json({ key, keys: listKeysFor(`github:${s.id}`), max: MAX_KEYS_PER_OWNER });
    } catch (err) {
      if (err instanceof Error && err.message === 'key_limit_reached') {
        return res.status(409).json({
          error: 'key_limit_reached',
          message: `Limite de ${MAX_KEYS_PER_OWNER} clés atteinte. Supprime une clé pour en créer une nouvelle.`,
        });
      }
      console.error('[webaudit] create key failed:', err);
      res.status(500).json({ error: 'server_error' });
    }
  });

  app.delete('/api/keys/:id', (req: Request, res: Response) => {
    const s = getSession(req);
    if (!s) return res.status(401).json({ error: 'not_logged_in' });
    if (!sameSiteGuard(req)) return res.status(403).json({ error: 'forbidden' });
    const ok = revokeKeyById(`github:${s.id}`, req.params.id);
    if (!ok) return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true, keys: listKeysFor(`github:${s.id}`), max: MAX_KEYS_PER_OWNER });
  });
}
