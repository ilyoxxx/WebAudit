/**
 * Le contrat de règle. Toute contribution passe par ce fichier.
 * Ne pas y toucher sans discussion : c'est l'interface stable pour les contributeurs externes.
 */

export type RuleCategory = 'security' | 'rgpd' | 'perf' | 'seo';
export type RuleStatus = 'pass' | 'fail' | 'warn' | 'na';

export interface RuleResult {
  status: RuleStatus;
  messageKey: string;
  evidence?: string;
  remediationKey?: string;
}

export interface Rule {
  id: string;
  category: RuleCategory;
  weight: number;
  docs: string;
  evaluate(ctx: ScanContext): RuleResult;
}

export interface ScanContext {
  url: string;
  finalUrl: string;
  http: {
    status: number;
    headers: Record<string, string>;
    bodyHtml: string;
    redirected: boolean;
    timingMs: number;
  };
  tls: {
    valid: boolean;
    protocol?: string;
    issuer?: string;
    daysUntilExpiry?: number;
    error?: string;
  } | null;
  dns: {
    a: string[];
    aaaa: string[];
    mx: string[];
    txt: string[];
  };
  cookies: {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: string;
  }[];
  robotsTxt: string | null;
  mentionsLegalesDetected: boolean;
  exposedFiles: {
    path: string;
    status: number;
  }[];
}

export interface RuleReport extends RuleResult {
  id: string;
  category: RuleCategory;
  weight: number;
  docs: string;
}

export interface ScanReport {
  url: string;
  scannedAt: string;
  grade: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
  score: number;
  results: RuleReport[];
}
