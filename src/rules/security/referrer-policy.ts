import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/referrer-policy',
  category: 'security',
  weight: 3,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referrer-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['referrer-policy'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.referrer_policy.missing',
        remediationKey: 'security.referrer_policy.remediation',
      };
    }

    if (header.toLowerCase().includes('unsafe-url')) {
      return {
        status: 'warn',
        messageKey: 'security.referrer_policy.unsafe_url',
        evidence: header,
        remediationKey: 'security.referrer_policy.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.referrer_policy.ok',
      evidence: header,
    };
  },
};

export default rule;