import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/x-content-type-options',
  category: 'security',
  weight: 5,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['x-content-type-options'];

    if (!header || header.toLowerCase() !== 'nosniff') {
      return {
        status: 'fail',
        messageKey: 'security.xcto.missing_or_invalid',
        evidence: header,
        remediationKey: 'security.xcto.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.xcto.ok',
      evidence: header,
    };
  },
};

export default rule;