import type { Rule, ScanContext, RuleResult } from '../../types';

/**
 * MODÈLE DE RÉFÉRENCE — copie ce fichier pour créer une nouvelle règle.
 * Une règle = une fonction pure evaluate(ctx) => RuleResult. Pas d'I/O ici,
 * les données sont déjà dans le ScanContext.
 */
const rule: Rule = {
  id: 'security/hsts',
  category: 'security',
  weight: 8,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['strict-transport-security'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.hsts.missing',
        remediationKey: 'security.hsts.remediation',
      };
    }

    const maxAgeMatch = header.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

    if (maxAge < 15552000) {
      // moins de 180 jours recommandés
      return {
        status: 'warn',
        messageKey: 'security.hsts.short_max_age',
        evidence: header,
        remediationKey: 'security.hsts.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.hsts.ok',
      evidence: header,
    };
  },
};

export default rule;
