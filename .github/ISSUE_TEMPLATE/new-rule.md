---
name: Nouvelle règle
about: Proposer ou implémenter une nouvelle règle d'audit
title: "[rule] <catégorie>/<id>"
labels: good first issue
---

## Règle à implémenter

**ID proposé :** `<catégorie>/<id>` (ex: `security/permissions-policy`)

**Catégorie :** security / rgpd / perf / seo

**Doc de référence :** <lien MDN, CNIL, RFC...>

## Comportement attendu

<!-- Décris précisément ce que la règle doit vérifier -->

- `fail` quand : ...
- `warn` quand : ...
- `pass` quand : ...

## Poids suggéré

`1` (mineur) à `10` (critique) — proposition : `?`

## Pour contribuer

1. `npm run new:rule` pour générer le squelette dans `src/rules/<catégorie>/`
2. Implémente `evaluate()` en te basant sur `src/rules/security/hsts.ts` comme modèle
3. Ajoute les clés de message dans `locales/fr.json`
4. Ouvre ta PR en référençant cette issue (`Closes #`)

Voir [CONTRIBUTING.md](../../CONTRIBUTING.md) pour le détail complet.
