import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/permissions-policy',
  category: 'security',
  weight: 4,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Permissions-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['permissions-policy'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.permissions_policy.missing',
        remediationKey: 'security.permissions_policy.remediation',
      };
    }

    const restricted = ['camera', 'microphone', 'geolocation'].filter((directive) =>
      new RegExp(`${directive}=`, 'i').test(header),
    );

    if (restricted.length < 3) {
      return {
        status: 'warn',
        messageKey: 'security.permissions_policy.partial',
        evidence: header,
        remediationKey: 'security.permissions_policy.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.permissions_policy.ok',
      evidence: header,
    };
  },
};

export default rule;
