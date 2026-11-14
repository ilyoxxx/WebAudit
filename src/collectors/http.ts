import { fetch as undiciFetch, Agent } from 'undici';
import { BlockedTargetError, guardedLookup, validateUrlObject } from '../security/ssrf';

export interface HttpCollectResult {
  status: number;
  headers: Record<string, string>;
  bodyHtml: string;
  redirected: boolean;
  finalUrl: string;
  timingMs: number;
}

const TIMEOUT_MS = 8000; // délai TOTAL (connexion + en-têtes + corps)
const MAX_BODY_BYTES = 2_000_000;
const MAX_REDIRECTS = 5;

/**
 * Toutes les connexions sortantes passent par `guardedLookup` : même si une redirection
 * ou un DNS malveillant pointe vers 127.0.0.1, 10.x, 169.254.169.254, etc., la connexion est refusée.
 */
const agent = new Agent({
  connect: { lookup: guardedLookup as never, timeout: TIMEOUT_MS },
  headersTimeout: TIMEOUT_MS,
  bodyTimeout: TIMEOUT_MS,
  connections: 64,
});

/**
 * Les redirections sont suivies À LA MAIN : chaque saut est revalidé (schéma, port, nom d'hôte)
 * avant d'être suivi, puis la connexion elle-même est revérifiée par le lookup gardé.
 */
export async function collectHttp(url: string): Promise<HttpCollectResult> {
  const start = Date.now();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    let current = url;
    let redirected = false;
    let res: Awaited<ReturnType<typeof undiciFetch>> | undefined;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      let parsed: URL;
      try {
        parsed = new URL(current);
      } catch {
        throw new BlockedTargetError('bad_url');
      }
      const reason = validateUrlObject(parsed);
      if (reason) throw new BlockedTargetError(reason);

      res = await undiciFetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        dispatcher: agent,
        headers: {
          'user-agent': 'webaudit-bot/0.1 (+https://github.com/ilyoxxx/webaudit)',
        },
      });

      const location = res.headers.get('location');
      if ([301, 302, 303, 307, 308].includes(res.status) && location) {
        await res.body?.cancel().catch(() => undefined);
        current = new URL(location, current).toString();
        redirected = true;
        res = undefined;
        continue;
      }
      break;
    }

    if (!res) throw new Error('too_many_redirects');

    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;

    if (reader) {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.length;
          if (total > MAX_BODY_BYTES) {
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }
    }

    const bodyHtml = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf-8');

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    // Plusieurs Set-Cookie : forEach n'en garde qu'un, on les recompose pour collectCookies.
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    if (setCookies.length > 0) headers['set-cookie'] = setCookies.join(', ');

    return {
      status: res.status,
      headers,
      bodyHtml,
      redirected,
      finalUrl: current,
      timingMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}
