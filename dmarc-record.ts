import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/dmarc-record',
  category: 'security',
  weight: 5,
  docs: 'https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/',

  evaluate(ctx: ScanContext): RuleResult {
    const dns = ctx.dns;
    if (!dns || dns.mx.length === 0) {
      return { status: 'na', messageKey: 'security.dmarc.not_applicable' };
    }

    const record = (dns.dmarc ?? []).find((r) => /^v=DMARC1/i.test(r.trim()));
    if (!record) {
      return { status: 'fail', messageKey: 'security.dmarc.missing', remediationKey: 'security.dmarc.remediation' };
    }

    const policy = record.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)/i)?.[1]?.toLowerCase();
    if (policy === 'quarantine' || policy === 'reject') {
      return { status: 'pass', messageKey: 'security.dmarc.ok', evidence: record };
    }
    return {
      status: 'warn',
      messageKey: 'security.dmarc.monitor_only',
      remediationKey: 'security.dmarc.remediation',
      evidence: record,
    };
  },
};

export default rule;
