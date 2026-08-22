import type { Rule, ScanContext, RuleResult } from '../../types';

const RESTRICTED_FEATURES = ['camera', 'microphone', 'geolocation'];

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

    const restrictsAtLeastOne = RESTRICTED_FEATURES.some((feature) => header.includes(feature));

    if (!restrictsAtLeastOne) {
      return {
        status: 'warn',
        messageKey: 'security.permissions_policy.no_sensitive_feature_restricted',
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