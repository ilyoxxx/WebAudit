import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/mentions-legales',
  category: 'rgpd',
  weight: 6,
  docs: 'https://www.cnil.fr/fr/les-obligations-des-editeurs-de-site-internet',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.mentionsLegalesDetected) {
      return {
        status: 'pass',
        messageKey: 'rgpd.mentions_legales.found',
      };
    }

    return {
      status: 'fail',
      messageKey: 'rgpd.mentions_legales.missing',
      remediationKey: 'rgpd.mentions_legales.remediation',
    };
  },
};

export default rule;
