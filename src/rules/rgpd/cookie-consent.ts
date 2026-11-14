import type { Rule, ScanContext, RuleResult } from '../../types';

/**
 * Heuristique volontairement simple : on cherche des cookies non-essentiels
 * posés AVANT tout consentement (ex: _ga, _fbp) et l'absence de tout signe
 * de CMP (bandeau de consentement) dans le HTML. Une vraie détection fine
 * nécessiterait un headless browser — hors scope, voir README (piège Puppeteer).
 */
const TRACKING_COOKIE_PREFIXES = ['_ga', '_gid', '_fbp', '_gcl', 'ajs_', '_hjid'];
const CMP_SIGNATURES = ['cookiebot', 'axeptio', 'onetrust', 'tarteaucitron', 'didomi', 'cookieconsent'];

const rule: Rule = {
  id: 'rgpd/cookie-consent',
  category: 'rgpd',
  weight: 9,
  docs: 'https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies-solutions-pour-les-outils-de-mesure-daudience',

  evaluate(ctx: ScanContext): RuleResult {
    const trackingCookiesFound = ctx.cookies.filter((c) =>
      TRACKING_COOKIE_PREFIXES.some((prefix) => c.name.toLowerCase().startsWith(prefix)),
    );

    const htmlLower = ctx.http.bodyHtml.toLowerCase();
    const cmpDetected = CMP_SIGNATURES.some((sig) => htmlLower.includes(sig));

    if (trackingCookiesFound.length > 0 && !cmpDetected) {
      return {
        status: 'fail',
        messageKey: 'rgpd.cookie_consent.tracking_without_cmp',
        evidence: trackingCookiesFound.map((c) => c.name).join(', '),
        remediationKey: 'rgpd.cookie_consent.remediation',
      };
    }

    if (trackingCookiesFound.length > 0 && cmpDetected) {
      // CMP présent mais on ne peut pas vérifier ici que le cookie a bien été
      // posé APRÈS un clic "accepter" sans rejouer le parcours utilisateur.
      return {
        status: 'warn',
        messageKey: 'rgpd.cookie_consent.cmp_present_needs_manual_check',
        evidence: trackingCookiesFound.map((c) => c.name).join(', '),
        remediationKey: 'rgpd.cookie_consent.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.cookie_consent.no_tracking_detected',
    };
  },
};

export default rule;
