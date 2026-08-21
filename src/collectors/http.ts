import { request } from 'undici';

export interface HttpCollectResult {
  status: number;
  headers: Record<string, string>;
  bodyHtml: string;
  redirected: boolean;
  finalUrl: string;
  timingMs: number;
}

const TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 2_000_000; // 2MB, on n'a pas besoin de plus pour parser le head/body

export async function collectHttp(url: string): Promise<HttpCollectResult> {
  const start = Date.now();

  const res = await request(url, {
    method: 'GET',
    maxRedirections: 5,
    headersTimeout: TIMEOUT_MS,
    bodyTimeout: TIMEOUT_MS,
    headers: {
      'user-agent': 'webaudit-bot/0.1 (+https://github.com/yourname/webaudit)',
    },
  });

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of res.body) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) break;
    chunks.push(chunk as Buffer);
  }

  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(res.headers)) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value ?? '');
  }

  return {
    status: res.statusCode,
    headers,
    bodyHtml: Buffer.concat(chunks).toString('utf-8'),
    redirected: res.context ? true : false,
    finalUrl: (res as unknown as { url?: string }).url ?? url,
    timingMs: Date.now() - start,
  };
}
