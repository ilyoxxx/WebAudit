import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'seo/robots-txt-present',
  category: 'seo',
  weight: 2,
  docs: 'https://developers.google.com/search/docs/crawling-indexing/robots/intro',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.robotsTxt === null) {
      return {
        status: 'warn',
        messageKey: 'seo.robots_txt_present.missing',
        remediationKey: 'seo.robots_txt_present.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'seo.robots_txt_present.ok',
      evidence: ctx.robotsTxt,
    };
  },
};

export default rule;
