/**
 * Le contrat de règle. Toute contribution passe par ce fichier.
 * Ne pas y toucher sans discussion : c'est l'interface stable pour les contributeurs externes.
 */

export type RuleCategory = 'security' | 'rgpd' | 'perf' | 'seo';
export type RuleStatus = 'pass' | 'fail' | 'warn' | 'na';

export interface RuleResult {
  status: RuleStatus;
  /** Clé i18n définie dans /locales/*.json — jamais de texte en dur ici. */
  messageKey: string;
  /** Donnée brute observée (ex: valeur du header manquant/erroné). */
  evidence?: string;
  /** Clé i18n pointant vers la remédiation suggérée. */
  remediationKey?: string;
}

export interface Rule {
  id: string;
  category: RuleCategory;
  /** Poids de la règle dans le score global, de 1 (mineur) à 10 (critique). */
  weight: number;
  /** Lien de référence : MDN, CNIL, RFC... */
  docs: string;
  evaluate(ctx: ScanContext): RuleResult;
}

/**
 * Contexte passé à chaque règle. Rempli par les collectors avant l'exécution
 * du moteur. Les collectors sont responsables de la robustesse réseau
 * (timeouts, erreurs) ; une règle ne doit jamais throw.
 */
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
