import { describe, it, expect } from 'vitest';
import metaDescription from '../meta-description';
import type { ScanContext } from '../../../types';

function baseCtx(bodyHtml: string): ScanContext {
  return {
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    http: {
      status: 200,
      headers: {},
      bodyHtml,
      redirected: false,
      timingMs: 100,
    },
    tls: null,
    dns: { a: [], aaaa: [], mx: [], txt: [] },
    cookies: [],
    robotsTxt: null,
    mentionsLegalesDetected: false,
  };
}

describe('seo/meta-description', () => {
  it('na si aucun HTML collecté', () => {
    const result = metaDescription.evaluate(baseCtx(''));
    expect(result.status).toBe('na');
  });

  it('fail si la balise est absente', () => {
    const result = metaDescription.evaluate(baseCtx('<html><head><title>t</title></head></html>'));
    expect(result.status).toBe('fail');
    expect(result.messageKey).toBe('seo.meta_description.missing');
  });

  it('warn si la balise est vide ou ne contient que des espaces', () => {
    const empty = metaDescription.evaluate(baseCtx('<meta name="description" content="">'));
    expect(empty.status).toBe('warn');
    expect(empty.messageKey).toBe('seo.meta_description.too_short');

    const blank = metaDescription.evaluate(baseCtx('<meta name="description" content="   ">'));
    expect(blank.status).toBe('warn');
  });

  it('warn si la description est trop courte (< 50 caractères)', () => {
    const result = metaDescription.evaluate(
      baseCtx('<meta name="description" content="Une page de démonstration.">'),
    );
    expect(result.status).toBe('warn');
    expect(result.messageKey).toBe('seo.meta_description.too_short');
  });

  it('warn si la description est trop longue (> 160 caractères)', () => {
    const long = 'a'.repeat(161);
    const result = metaDescription.evaluate(
      baseCtx(`<meta name="description" content="${long}">`),
    );
    expect(result.status).toBe('warn');
    expect(result.messageKey).toBe('seo.meta_description.too_long');
    expect(result.evidence).toBe('161');
  });

  it('pass si la longueur est dans les bornes [50, 160]', () => {
    const ok = 'Une description de page d\'accueil suffisamment longue pour informer sans être tronquée par les moteurs de recherche.';
    const result = metaDescription.evaluate(baseCtx(`<meta name="description" content="${ok}">`));
    expect(result.status).toBe('pass');
    expect([...ok].length).toBeGreaterThanOrEqual(50);
    expect([...ok].length).toBeLessThanOrEqual(160);
  });

  it('accepte un attribut name en majuscules (insensibilité à la casse)', () => {
    const ok = 'Une description de page suffisamment longue pour passer le contrôle de longueur minimale sans souci.';
    const result = metaDescription.evaluate(baseCtx(`<meta NAME="DESCRIPTION" content="${ok}">`));
    expect(result.status).toBe('pass');
  });

  it('prend la première balise description en cas de doublon', () => {
    const html =
      '<meta name="description" content="Première description, la seule valide, suffisamment longue pour le test.">' +
      '<meta name="description" content="court">';
    const result = metaDescription.evaluate(baseCtx(html));
    expect(result.status).toBe('pass');
  });
});
