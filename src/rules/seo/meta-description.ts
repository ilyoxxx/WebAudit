import * as cheerio from 'cheerio';
import type { Rule, ScanContext, RuleResult } from '../../types';

// Bornes couramment admises pour un extrait de page de résultats :
// en dessous, le snippet est peu informatif ; au-dessus, il est tronqué.
const MIN_LENGTH = 50;
const MAX_LENGTH = 160;

const rule: Rule = {
  id: 'seo/meta-description',
  category: 'seo',
  weight: 3,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTML/Element/meta/name/description',

  evaluate(ctx: ScanContext): RuleResult {
    if (!ctx.http.bodyHtml) {
      return { status: 'na', messageKey: 'seo.meta_description.no_html' };
    }

    const $ = cheerio.load(ctx.http.bodyHtml);
    // L'attribut name est insensible à la casse côté HTML mais pas côté
    // sélecteur CSS — on compare donc à la main plutôt qu'avec [name=...].
    const description = $('meta[name]')
      .filter((_, el) => ($(el).attr('name') ?? '').toLowerCase() === 'description')
      .first()
      .attr('content');

    if (description === undefined) {
      return {
        status: 'fail',
        messageKey: 'seo.meta_description.missing',
        remediationKey: 'seo.meta_description.remediation',
      };
    }

    const text = description.trim();
    // Longueur en points de code (les accents/emoji comptent pour un).
    const length = [...text].length;

    if (length < MIN_LENGTH) {
      return {
        status: 'warn',
        messageKey: 'seo.meta_description.too_short',
        evidence: `${length}`,
        remediationKey: 'seo.meta_description.remediation',
      };
    }

    if (length > MAX_LENGTH) {
      return {
        status: 'warn',
        messageKey: 'seo.meta_description.too_long',
        evidence: `${length}`,
        remediationKey: 'seo.meta_description.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'seo.meta_description.ok',
      evidence: `${length}`,
    };
  },
};

export default rule;
