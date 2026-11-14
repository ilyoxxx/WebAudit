import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Rule, RuleReport, ScanContext, ScanReport } from '../types';

const RULES_DIR = path.join(__dirname, '..', 'rules');

/**
 * Charge dynamiquement tous les fichiers .ts/.js sous /src/rules/**
 * (hors fichiers de test). Chaque fichier doit faire `export default` une Rule.
 * C'est ce mécanisme qui permet à un contributeur d'ajouter une règle sans
 * toucher à aucun autre fichier : il suffit de déposer le fichier au bon endroit.
 */
export function loadRules(): Rule[] {
  const rules: Rule[] = [];

  function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (!/\.(ts|js)$/.test(entry.name)) continue;
      if (/\.(test|spec)\.(ts|js)$/.test(entry.name)) continue;
      if (fullPath.includes(`${path.sep}__tests__${path.sep}`)) continue;

      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require(fullPath);
      const rule: Rule | undefined = mod.default ?? mod.rule;
      if (!rule || !rule.id || typeof rule.evaluate !== 'function') {
        console.warn(`[engine] fichier ignoré, pas de règle valide: ${fullPath}`);
        continue;
      }
      rules.push(rule);
    }
  }

  walk(RULES_DIR);
  return rules;
}

export function runRules(rules: Rule[], ctx: ScanContext): RuleReport[] {
  return rules.map((rule) => {
    try {
      const result = rule.evaluate(ctx);
      return { id: rule.id, category: rule.category, weight: rule.weight, docs: rule.docs, ...result };
    } catch (err) {
      // Une règle qui plante ne doit jamais faire tomber le scan entier.
      return {
        id: rule.id,
        category: rule.category,
        weight: rule.weight,
        docs: rule.docs,
        status: 'na' as const,
        messageKey: 'engine.rule_crashed',
        evidence: err instanceof Error ? err.message : String(err),
      };
    }
  });
}

/**
 * Score pondéré : chaque règle 'pass' rapporte son poids plein, 'warn' la moitié,
 * 'fail' zéro, 'na' est exclue du calcul (ni pénalité ni bonus).
 */
export function computeGrade(results: RuleReport[]): { score: number; grade: ScanReport['grade'] } {
  const applicable = results.filter((r) => r.status !== 'na');
  const totalWeight = applicable.reduce((sum, r) => sum + r.weight, 0);

  if (totalWeight === 0) {
    return { score: 0, grade: 'F' };
  }

  const earned = applicable.reduce((sum, r) => {
    if (r.status === 'pass') return sum + r.weight;
    if (r.status === 'warn') return sum + r.weight * 0.5;
    return sum;
  }, 0);

  const score = Math.round((earned / totalWeight) * 100);

  let grade: ScanReport['grade'];
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else if (score >= 20) grade = 'E';
  else grade = 'F';

  return { score, grade };
}

export function buildReport(url: string, ctx: ScanContext, rules: Rule[]): ScanReport {
  const results = runRules(rules, ctx);
  const { score, grade } = computeGrade(results);

  return {
    url,
    scannedAt: new Date().toISOString(),
    grade,
    score,
    results,
  };
}
