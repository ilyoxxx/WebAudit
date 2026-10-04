import type { Rule, ScanContext, RuleResult } from '../../types';

const SPF_RECORD_RE = /^v=spf1(?:\s|$)/i;

const rule: Rule = {
  id: 'security/spf-record',
  category: 'security',
  weight: 5,
  docs: 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/',

  evaluate(ctx: ScanContext): RuleResult {
    const dns = ctx.dns;
    if (!dns || dns.mx.length === 0) {
      return {
        status: 'na',
        messageKey: 'security.spf_record.not_applicable',
      };
    }

    const spfRecord = dns.txt.find((record) => SPF_RECORD_RE.test(record.trim()));
    if (!spfRecord) {
      return {
        status: 'fail',
        messageKey: 'security.spf_record.missing',
        remediationKey: 'security.spf_record.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.spf_record.ok',
      evidence: spfRecord,
    };
  },
};

export default rule;
