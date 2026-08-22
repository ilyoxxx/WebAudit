export interface HttpCollectResult {
  status: number;
  headers: Record<string, string>;
  bodyHtml: string;
  redirected: boolean;
  finalUrl: string;
  timingMs: number;
}

const TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 2_000_000;

/**
 * Utilise le fetch global de Node (18+), qui suit les redirections par défaut.
 * On évite volontairement l'API bas niveau d'undici (request/Client) dont les
 * options ont changé de forme entre versions majeures.
 */
export async function collectHttp(url: string): Promise<HttpCollectResult> {
  const start = Date.now();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': 'webaudit-bot/0.1 (+https://github.com/ilyoxxx/webaudit)',
      },
    });
  } finally {
    clearTimeout(timeoutId);
  }

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

  return {
    status: res.status,
    headers,
    bodyHtml,
    redirected: res.redirected,
    finalUrl: res.url || url,
    timingMs: Date.now() - start,
  };
}