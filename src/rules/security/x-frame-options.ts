import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/x-frame-options',
  category: 'security',
  weight: 5,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Frame-Options',

  evaluate(ctx: ScanContext): RuleResult {
    const xfo = ctx.http.headers['x-frame-options'];
    const csp = ctx.http.headers['content-security-policy'];
    const cspHasFrameAncestors = csp?.toLowerCase().includes('frame-ancestors');

    if (!xfo && !cspHasFrameAncestors) {
      return {
        status: 'fail',
        messageKey: 'security.xfo.missing',
        remediationKey: 'security.xfo.remediation',
      };
    }

    if (cspHasFrameAncestors) {
      return {
        status: 'pass',
        messageKey: 'security.xfo.covered_by_csp',
        evidence: csp,
      };
    }

    const value = xfo!.toUpperCase();
    if (value !== 'DENY' && value !== 'SAMEORIGIN') {
      return {
        status: 'warn',
        messageKey: 'security.xfo.weak_value',
        evidence: xfo,
        remediationKey: 'security.xfo.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.xfo.ok',
      evidence: xfo,
    };
  },
};

export default rule;
