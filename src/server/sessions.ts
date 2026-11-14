import * as crypto from 'node:crypto';
import { dataPath, readJson, writeJsonAtomic } from './storage';

/**
 * Sessions CÔTÉ SERVEUR : le cookie ne contient qu'un jeton aléatoire opaque, le serveur ne stocke
 * que son empreinte. Déconnexion = suppression réelle (un cookie volé cesse de fonctionner),
 * contrairement à un cookie signé « sans état » qui reste valide jusqu'à expiration.
 */
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 h, durée absolue
const MAX_SESSIONS_PER_USER = 5;
const FILE = dataPath('sessions.json');

export interface SessionData {
  userId: number;
  login: string;
  exp: number;
  createdAt: number;
}

const sha = (t: string) => crypto.createHash('sha256').update(t).digest('hex');

let store: Record<string, SessionData> = readJson<Record<string, SessionData>>(FILE, {});
let dirty = false;

function purge(): void {
  const now = Date.now();
  for (const [h, s] of Object.entries(store)) {
    if (!s || typeof s.exp !== 'number' || s.exp < now) {
      delete store[h];
      dirty = true;
    }
  }
}

function flush(): void {
  if (!dirty) return;
  try {
    writeJsonAtomic(FILE, store);
    dirty = false;
  } catch (err) {
    console.error('[webaudit] sessions: écriture impossible:', (err as Error).message);
  }
}

purge();
flush();
setInterval(() => {
  purge();
  flush();
}, 60_000).unref();

export function createSession(userId: number, login: string): string {
  purge();
  // Limite par utilisateur : on supprime les plus anciennes.
  const mine = Object.entries(store)
    .filter(([, s]) => s.userId === userId)
    .sort((a, b) => a[1].createdAt - b[1].createdAt);
  while (mine.length >= MAX_SESSIONS_PER_USER) {
    const [h] = mine.shift() as [string, SessionData];
    delete store[h];
  }
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  store[sha(token)] = { userId, login, exp: now + SESSION_TTL_MS, createdAt: now };
  dirty = true;
  flush();
  return token;
}

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export function getSessionByToken(token: string | undefined): SessionData | null {
  if (!token || !TOKEN_RE.test(token)) return null;
  const s = store[sha(token)];
  if (!s) return null;
  if (s.exp < Date.now()) {
    delete store[sha(token)];
    dirty = true;
    return null;
  }
  return s;
}

export function destroySession(token: string | undefined): void {
  if (!token || !TOKEN_RE.test(token)) return;
  if (store[sha(token)]) {
    delete store[sha(token)];
    dirty = true;
    flush();
  }
}
