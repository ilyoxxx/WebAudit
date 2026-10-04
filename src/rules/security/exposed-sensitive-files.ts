import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/exposed-sensitive-files',
  category: 'security',
  weight: 10,
  docs: 'https://owasp.org/www-project-top-ten/',

  evaluate(ctx: ScanContext): RuleResult {
    if (!ctx.exposedFiles || ctx.exposedFiles.length === 0) {
      return {
        status: 'pass',
        messageKey: 'security.exposed_files.ok',
      };
    }

    return {
      status: 'fail',
      messageKey: 'security.exposed_files.found',
      evidence: ctx.exposedFiles.map((f) => f.path).join(', '),
      remediationKey: 'security.exposed_files.remediation',
    };
  },
};

export default rule;
