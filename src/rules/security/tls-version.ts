import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/tls-version',
  category: 'security',
  weight: 9,
  docs: 'https://developer.mozilla.org/fr/docs/Web/Security/Transport_Layer_Security',

  evaluate(ctx: ScanContext): RuleResult {
    if (!ctx.tls || !ctx.tls.protocol) {
      return {
        status: 'na',
        messageKey: 'security.tls_version.unavailable',
      };
    }

    const protocol = ctx.tls.protocol.toUpperCase();

    if (protocol === 'TLSV1.3') {
      return {
        status: 'pass',
        messageKey: 'security.tls_version.ok',
        evidence: protocol,
      };
    }

    if (protocol === 'TLSV1.2') {
      return {
        status: 'warn',
        messageKey: 'security.tls_version.tls12_only',
        evidence: protocol,
        remediationKey: 'security.tls_version.remediation',
      };
    }

    return {
      status: 'fail',
      messageKey: 'security.tls_version.outdated',
      evidence: protocol,
      remediationKey: 'security.tls_version.remediation',
    };
  },
};

export default rule;