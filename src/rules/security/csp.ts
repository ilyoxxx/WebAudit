import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/csp',
  category: 'security',
  weight: 9,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    // TODO: implémente la logique en te basant sur ctx.http, ctx.tls,
    // ctx.dns, ctx.cookies, ctx.robotsTxt, ctx.mentionsLegalesDetected.
    //
    // Exemple :
    // const header = ctx.http.headers['nom-du-header'];
    // if (!header) {
    //   return { status: 'fail', messageKey: 'security.csp.missing', remediationKey: 'security.csp.remediation' };
    // }

    return {
      status: 'na',
      messageKey: 'security.csp.not_implemented',
    };
  },
};

export default rule;
