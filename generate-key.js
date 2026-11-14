#!/usr/bin/env node
const { execSync } = require('child_process');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

async function main() {
  const owner = (await ask('Nom/email du client : ')).trim();
  const note = (await ask('Note (optionnel, ex: "payé 29€ le 04/10") : ')).trim();
  rl.close();

  const { generateKey } = require('../dist/server/apiKeys');
  const key = generateKey(owner, note || undefined);

  console.log('\n✔ Clé générée :');
  console.log(key);
  console.log('\nEnvoie-la au client. Elle est stockée dans data/api-keys.json (jamais commité).');
}

main();
