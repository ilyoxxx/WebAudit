import express from 'express';
import * as path from 'node:path';
import * as cheerio from 'cheerio';

import { collectHttp } from '../collectors/http';
import { collectTls } from '../collectors/tls';
import { collectDns } from '../collectors/dns';
import { collectCookies } from '../collectors/cookies';
import { loadRules, buildReport } from '../engine/runner';
import type { ScanContext } from '../types';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

const rules = loadRules();
console.log(`[webaudit] ${rules.length} règle(s) chargée(s): ${rules.map((r) => r.id).join(', ')}`);

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', '..', 'public')));
app.use('/locales', express.static(path.join(__dirname, '..', '..', 'locales')));

function normalizeUrl(input: string): string {
  if (!/^https?:\/\//i.test(input)) return `https://${input}`;
  return input;
}

function detectMentionsLegales(html: string): boolean {
  const $ = cheerio.load(html);
  const linkTexts = $('a')
    .map((_, el) => $(el).text().toLowerCase())
    .get();
  return linkTexts.some(
    (t) => t.includes('mentions légales') || t.includes('mentions legales') || t.includes('legal notice'),
  );
}

app.post('/api/scan', async (req, res) => {
  const rawUrl = req.body?.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'Missing "url" in request body' });
  }

  const url = normalizeUrl(rawUrl.trim());

  try {
    const [httpResult, tlsResult, dnsResult] = await Promise.all([
      collectHttp(url),
      collectTls(url),
      collectDns(url),
    ]);

    const cookies = collectCookies(httpResult.headers['set-cookie']);
    const mentionsLegalesDetected = detectMentionsLegales(httpResult.bodyHtml);

    let robotsTxt: string | null = null;
    try {
      const robotsResp = await collectHttp(new URL('/robots.txt', url).toString());
      robotsTxt = robotsResp.status === 200 ? robotsResp.bodyHtml : null;
    } catch {
      robotsTxt = null;
    }

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
      mentionsLegalesDetected,
    };

    const report = buildReport(url, ctx, rules);
    res.json(report);
  } catch (err) {
    console.error('[webaudit] scan failed:', err);
    res.status(502).json({
      error: 'scan_failed',
      message: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

app.get('/api/rules', (_req, res) => {
  res.json(rules.map((r) => ({ id: r.id, category: r.category, weight: r.weight, docs: r.docs })));
});

app.listen(PORT, () => {
  console.log(`[webaudit] serveur démarré sur http://localhost:${PORT}`);
});
