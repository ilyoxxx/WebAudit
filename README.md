# webaudit

> Scanner d'audit web sécurité &amp; RGPD, à règles modulaires. Une URL entre, un rapport A→F avec explications et remédiations sort.

<!-- TODO avant publication : remplacer par un GIF réel du scan (asciinema→gif ou screen record, 10-15s, montre l'URL tapée + le rapport qui s'affiche) -->
![démo webaudit](docs/demo.gif)
[Contribuer](CONTRIBUTING.md) · [Ouvrir une issue "good first issue"](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

---

## Pourquoi

La plupart des scanners de sécurité web sont soit des services SaaS fermés, soit des projets monolithiques impossibles à étendre sans lire tout le code. `webaudit` fait un pari différent : **chaque règle est un fichier isolé de ~30 lignes**. Copier `rules/hsts.ts`, écrire sa propre règle, ouvrir une PR — sans jamais toucher au serveur, au moteur ou au front.

## Démarrage rapide

```bash
git clone https://github.com/yourname/webaudit.git
cd webaudit
npm install
npm run dev
```

Ouvre `http://localhost:3000`, tape une URL, regarde le rapport.

## Architecture

```
/src
  /server        server.ts (Express + TS), route /api/scan
  /collectors    http.ts, tls.ts, dns.ts, cookies.ts
  /rules         un fichier = une règle
    /security    hsts.ts, x-frame-options.ts...
    /rgpd        cookie-consent.ts, mentions-legales.ts...
    /perf        compression.ts...
  /engine        runner.ts (charge et exécute les règles, calcule le score)
/public          index.html, style.css, app.js — vanilla, zéro build
/locales         fr.json, en.json
```

Le flux : une URL entre → les collectors font les requêtes réseau une seule fois (headers HTTP, TLS, DNS, cookies, robots.txt) → le résultat est empaqueté dans un `ScanContext` → chaque règle du moteur l'évalue indépendamment → le moteur agrège en un score pondéré 0-100 puis une note A→F.

## Le contrat de règle

```ts
export interface Rule {
  id: string;
  category: 'security' | 'rgpd' | 'perf' | 'seo';
  weight: number;                    // 1-10
  docs: string;                      // lien MDN/CNIL
  evaluate(ctx: ScanContext): RuleResult;
}

export interface RuleResult {
  status: 'pass' | 'fail' | 'warn' | 'na';
  messageKey: string;                // clé i18n, jamais de texte en dur
  evidence?: string;
  remediationKey?: string;
}
```

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour un exemple complet et la commande `npm run new:rule` qui génère le squelette pour toi.

## Ce que le projet ne fait pas (volontairement)

Pas de Puppeteer / Chrome headless. Ça alourdit l'installation, casse la CI sur certains environnements, et fait fuir les contributeurs qui veulent juste `npm install && npm run dev`. On reste sur `fetch` (via `undici`) + parsing HTML (`cheerio`) pendant les premiers mois. Une détection plus fine (JS-rendered content, vrai parcours de consentement) est un sujet pour plus tard, pas pour le MVP.

## Statut du projet

Scan HTTP/TLS/DNS/cookies/robots.txt opérationnel. 5 règles de démonstration livrées (`security/hsts`, `security/x-frame-options`, `rgpd/cookie-consent`, `rgpd/mentions-legales`, `perf/compression`). 25 règles supplémentaires listées comme [`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) — voir `.github/ISSUES_SEED.md`.

## Licence

MIT
