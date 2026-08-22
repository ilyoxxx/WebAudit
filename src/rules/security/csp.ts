import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/csp',
  category: 'security',
  weight: 9,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    const csp = ctx.http.headers['content-security-policy'];

    if (!csp) {
      return {
        status: 'fail',
        messageKey: 'security.csp.missing',
        remediationKey: 'security.csp.remediation',
      };
    }

    if (/unsafe-inline/i.test(csp)) {
      return {
        status: 'warn',
        messageKey: 'security.csp.unsafe_inline',
        evidence: csp,
        remediationKey: 'security.csp.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.csp.ok',
      evidence: csp,
    };
  },
};

export default rule;