#!/usr/bin/env node
/**
 * npm run new:rule
 * Génère un squelette de règle dans src/rules/<category>/<id>.ts
 * et le fichier de test associé.
 */
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const CATEGORIES = ['security', 'rgpd', 'perf', 'seo'];

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

function toPascalCase(str) {
  return str
    .split(/[-_\s]+/)
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join('');
}

async function main() {
  console.log('=== Créer une nouvelle règle webaudit ===\n');

  const id = (await ask('Identifiant de la règle (kebab-case, ex: permissions-policy): ')).trim();
  if (!id || !/^[a-z0-9-]+$/.test(id)) {
    console.error('Identifiant invalide. Utilise uniquement des minuscules, chiffres et tirets.');
    process.exit(1);
  }

  let category = (await ask(`Catégorie (${CATEGORIES.join('/')}): `)).trim();
  if (!CATEGORIES.includes(category)) {
    console.error(`Catégorie invalide. Doit être l'une de: ${CATEGORIES.join(', ')}`);
    process.exit(1);
  }

  const docs = (await ask('Lien de doc (MDN/CNIL/RFC): ')).trim();
  const weight = (await ask('Poids (1-10, défaut 5): ')).trim() || '5';

  rl.close();

  const dir = path.join(__dirname, '..', 'src', 'rules', category);
  const filePath = path.join(dir, `${id}.ts`);

  if (fs.existsSync(filePath)) {
    console.error(`Le fichier existe déjà: ${filePath}`);
    process.exit(1);
  }

  const messageKeyBase = `${category}.${id.replace(/-/g, '_')}`;

  const template = `import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: '${category}/${id}',
  category: '${category}',
  weight: ${weight},
  docs: '${docs || 'https://developer.mozilla.org/'}',

  evaluate(ctx: ScanContext): RuleResult {
    // TODO: implémente la logique en te basant sur ctx.http, ctx.tls,
    // ctx.dns, ctx.cookies, ctx.robotsTxt, ctx.mentionsLegalesDetected.
    //
    // Exemple :
    // const header = ctx.http.headers['nom-du-header'];
    // if (!header) {
    //   return { status: 'fail', messageKey: '${messageKeyBase}.missing', remediationKey: '${messageKeyBase}.remediation' };
    // }

    return {
      status: 'na',
      messageKey: '${messageKeyBase}.not_implemented',
    };
  },
};

export default rule;
`;

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, template);

  console.log(`\n✔ Règle créée : ${path.relative(process.cwd(), filePath)}`);
  console.log(`\nN'oublie pas d'ajouter les clés suivantes dans locales/fr.json et locales/en.json :`);
  console.log(`  - ${messageKeyBase}.missing`);
  console.log(`  - ${messageKeyBase}.ok`);
  console.log(`  - ${messageKeyBase}.remediation`);
}

main();
