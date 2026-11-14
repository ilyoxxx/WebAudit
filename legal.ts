import * as cheerio from 'cheerio';
import { collectHttp } from './http';

export interface LegalResult {
  found: boolean;
  inconclusive: boolean;
  evidence: string;
  checked: number;
}

const MAX_PAGES = 25;
const MAX_DEPTH = 2;
const DEADLINE_MS = 25000;

const LEGAL_RE =
  /mentions?[\s_-]*legales?|informations?[\s_-]*legales?|legal[\s_-]*(notice|information|mentions|disclosure)|\blegal\b|imprint|impressum|aviso[\s_-]*legal|note[\s_-]*legali|mentions?[\s_-]*obligatoires?/;

const INFO_RE =
  /legal|mention|privacy|confidential|donnees|cgu|cgv|conditions|terms|contact|propos|about|imprint|impressum|cookies|rgpd|gdpr/;

const COMMON_PATHS = [
  '/mentions-legales',
  '/mentions-legales/',
  '/mentions_legales',
  '/mentions',
  '/legal',
  '/legal-notice',
  '/legal-mentions',
  '/informations-legales',
  '/imprint',
  '/impressum',
  '/fr/mentions-legales',
  '/a-propos/mentions-legales',
  '/legal/mentions-legales',
  '/cgu',
  '/conditions-generales',
  '/politique-de-confidentialite',
  '/privacy',
];

const CONTENT_WORDS = [
  'editeur',
  'hebergeur',
  'siret',
  'siren',
  'directeur de la publication',
  'responsable de la publication',
  'raison sociale',
  'capital social',
  'legal notice',
  'registered office',
  'publisher',
  'imprint',
  'impressum',
  'mentions legales',
];

const SKIP_EXT = /\.(pdf|jpe?g|png|gif|svg|webp|ico|css|js|json|xml|zip|rar|mp4|mp3|woff2?|ttf)(\?|$)/i;

function norm(s: string): string {
  return s
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function bareHost(h: string): string {
  return h.replace(/^www\./, '');
}

async function safeGet(url: string): Promise<{ status: number; body: string }> {
  try {
    const r = await Promise.race([
      collectHttp(url),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), 8000)),
    ]);
    return { status: r.status, body: r.bodyHtml ?? '' };
  } catch {
    return { status: 0, body: '' };
  }
}

function contentHits(body: string): number {
  const text = norm(body);
  let hits = 0;
  for (const w of CONTENT_WORDS) if (text.includes(w)) hits++;
  return hits;
}

function looksLikeEmptyApp(html: string): boolean {
  const $ = cheerio.load(html || '');
  $('script,style,noscript').remove();
  const text = $('body').text().replace(/\s+/g, ' ').trim();
  return text.length < 300;
}

function isBlocked(status: number): boolean {
  return status === 0 || status === 401 || status === 403 || status === 429 || status >= 500;
}

interface PageAnalysis {
  evidence?: string;
  links: { url: string; priority: number }[];
}

function analyzePage(pageUrl: string, html: string, host: string): PageAnalysis {
  const $ = cheerio.load(html || '');
  const links: { url: string; priority: number }[] = [];
  let evidence: string | undefined;

  $('a, button, [role="link"]').each((_, el) => {
    const text = norm($(el).text());
    const href = $(el).attr('href') || '';
    const label = norm(`${$(el).attr('aria-label') || ''} ${$(el).attr('title') || ''}`);
    const nhref = norm(href);

    if (!evidence && (LEGAL_RE.test(text) || LEGAL_RE.test(nhref) || LEGAL_RE.test(label))) {
      evidence = `lien « ${$(el).text().trim().slice(0, 60) || href} » trouvé sur ${pageUrl}`;
    }

    if (!href || href.startsWith('#') || /^(mailto|tel|javascript):/i.test(href)) return;
    try {
      const u = new URL(href, pageUrl);
      if (!/^https?:$/.test(u.protocol)) return;
      if (bareHost(u.hostname) !== bareHost(host)) return;
      if (SKIP_EXT.test(u.pathname)) return;
      u.hash = '';
      const inFooter = $(el).closest('footer, [class*="footer"], [id*="footer"]').length > 0;
      const interesting = INFO_RE.test(text) || INFO_RE.test(nhref);
      links.push({ url: u.toString(), priority: (inFooter ? 2 : 0) + (interesting ? 3 : 0) });
    } catch {
      /* lien invalide, on ignore */
    }
  });

  return { evidence, links };
}

export async function detectLegalNotice(
  baseUrl: string,
  html: string,
  homeStatus = 200,
): Promise<LegalResult> {
  const startedAt = Date.now();
  const timeUp = () => Date.now() - startedAt > DEADLINE_MS;

  let host = '';
  try {
    host = new URL(baseUrl).hostname;
  } catch {
    host = '';
  }

  // 1. Code brut de la page d'accueil (scripts, JSON, menus générés en JavaScript)
  const raw = norm(html || '');
  const m = raw.match(/[^"'\s<>()]*(?:mentions-?legales?|mentions_legales|legal-notice|impressum)[^"'\s<>()]*/);

  // 2. Analyse de la page d'accueil : liens + contenu
  const home = analyzePage(baseUrl, html, host);
  if (home.evidence) return { found: true, inconclusive: false, evidence: home.evidence, checked: 1 };
  if (m) {
    return {
      found: true,
      inconclusive: false,
      evidence: `référence trouvée dans le code de la page : ${m[0].slice(0, 120)}`,
      checked: 1,
    };
  }
  if (contentHits(html) >= 3) {
    return {
      found: true,
      inconclusive: false,
      evidence: `informations légales présentes directement sur ${baseUrl}`,
      checked: 1,
    };
  }

  // 3. Exploration du site : pages internes en priorité (pied de page, contact, CGU…)
  const visited = new Set<string>([baseUrl]);
  let level = home.links;
  let checked = 1;
  let fetched = 0;
  let blocked = 0;

  for (let depth = 1; depth <= MAX_DEPTH && level.length > 0 && !timeUp(); depth++) {
    const sorted = level.sort((a, b) => b.priority - a.priority);
    const toFetch: string[] = [];
    for (const l of sorted) {
      if (visited.has(l.url)) continue;
      visited.add(l.url);
      toFetch.push(l.url);
      if (visited.size >= MAX_PAGES) break;
    }

    const nextLevel: { url: string; priority: number }[] = [];
    for (let i = 0; i < toFetch.length && !timeUp(); i += 5) {
      const batch = toFetch.slice(i, i + 5);
      const results = await Promise.all(batch.map((u) => safeGet(u)));
      for (let j = 0; j < batch.length; j++) {
        checked++;
        fetched++;
        const r = results[j];
        if (isBlocked(r.status)) {
          blocked++;
          continue;
        }
        if (r.status !== 200) continue;

        const urlLooksLegal = LEGAL_RE.test(norm(batch[j]));
        const hits = contentHits(r.body);
        if ((urlLooksLegal && hits >= 1) || hits >= 3) {
          return { found: true, inconclusive: false, evidence: `page légale trouvée : ${batch[j]}`, checked };
        }
        const a = analyzePage(batch[j], r.body, host);
        if (a.evidence) return { found: true, inconclusive: false, evidence: a.evidence, checked };
        nextLevel.push(...a.links);
      }
    }
    level = nextLevel;
  }

  // 4. Sitemap (même domaine) + chemins courants
  const fromSitemap: string[] = [];
  if (!timeUp()) {
    const sitemap = await safeGet(new URL('/sitemap.xml', baseUrl).toString());
    if (sitemap.status === 200) {
      const locs = [...sitemap.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((x) => x[1]);
      for (const loc of locs) {
        try {
          if (bareHost(new URL(loc).hostname) === bareHost(host) && LEGAL_RE.test(norm(loc))) {
            fromSitemap.push(loc);
          }
        } catch {
          /* URL invalide, on ignore */
        }
        if (fromSitemap.length >= 5) break;
      }
    }
  }

  const candidates = [
    ...fromSitemap.map((u) => ({ url: u, fromSitemap: true })),
    ...COMMON_PATHS.map((p) => ({ url: new URL(p, baseUrl).toString(), fromSitemap: false })),
  ].filter((c) => !visited.has(c.url));

  for (let i = 0; i < candidates.length && !timeUp(); i += 6) {
    const batch = candidates.slice(i, i + 6);
    const results = await Promise.all(batch.map((c) => safeGet(c.url)));
    for (let j = 0; j < batch.length; j++) {
      checked++;
      fetched++;
      const r = results[j];
      if (isBlocked(r.status)) blocked++;
      if (r.status === 200 && (batch[j].fromSitemap || contentHits(r.body) >= 2)) {
        return { found: true, inconclusive: false, evidence: `page trouvée : ${batch[j].url}`, checked };
      }
    }
  }

  // 5. Rien trouvé : conclure "manquant" seulement si le site a pu être lu en entier
  const inconclusive =
    homeStatus !== 200 ||
    looksLikeEmptyApp(html) ||
    timeUp() ||
    (fetched > 0 && blocked > fetched / 2);

  return {
    found: false,
    inconclusive,
    evidence: `${checked} pages et emplacements vérifiés`,
    checked,
  };
}
