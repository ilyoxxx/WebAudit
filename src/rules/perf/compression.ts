import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'perf/compression',
  category: 'perf',
  weight: 4,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Encoding',

  evaluate(ctx: ScanContext): RuleResult {
    const encoding = ctx.http.headers['content-encoding'];

    if (!encoding) {
      return {
        status: 'warn',
        messageKey: 'perf.compression.missing',
        remediationKey: 'perf.compression.remediation',
      };
    }

    if (!['gzip', 'br', 'deflate'].includes(encoding.toLowerCase())) {
      return {
        status: 'warn',
        messageKey: 'perf.compression.unrecognized',
        evidence: encoding,
      };
    }

    return {
      status: 'pass',
      messageKey: 'perf.compression.ok',
      evidence: encoding,
    };
  },
};

export default rule;
