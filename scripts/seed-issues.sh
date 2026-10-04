#!/usr/bin/env bash
# Crée les 25 issues "good first issue" depuis .github/ISSUES_SEED.md via GitHub CLI.
# Prérequis : `gh auth login` fait, exécuté depuis la racine du repo cloné.
set -euo pipefail

SEED_FILE="$(dirname "$0")/../.github/ISSUES_SEED.md"

if ! command -v gh &> /dev/null; then
  echo "GitHub CLI (gh) n'est pas installé. https://cli.github.com/"
  exit 1
fi

# Trim pur bash (sans xargs) : les apostrophes françaises dans le texte
# (ex: "s'il", "n'a") font planter xargs, donc on évite complètement.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

count=0
while IFS='|' read -r id category weight doc behavior; do
  # ignore lignes vides, commentaires, headers markdown
  [[ -z "$id" || "$id" =~ ^# || "$id" =~ ^Format ]] && continue

  id=$(trim "$id")
  category=$(trim "$category")
  weight=$(trim "$weight")
  doc=$(trim "$doc")
  behavior=$(trim "$behavior")

  title="[rule] ${id}"
  body=$(cat <<EOF
## Règle à implémenter

**ID proposé :** \`${id}\`
**Catégorie :** ${category}
**Poids suggéré :** ${weight}
**Doc de référence :** ${doc}

## Comportement attendu

${behavior}

## Pour contribuer

1. \`npm run new:rule\` pour générer le squelette
2. Implémente \`evaluate()\` (voir \`src/rules/security/hsts.ts\` comme modèle)
3. Ajoute les clés de message dans \`locales/fr.json\`
4. Ouvre ta PR en référençant cette issue

Voir [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md).
EOF
)

  gh issue create --title "$title" --body "$body" --label "good first issue"
  count=$((count + 1))
done < <(tail -n +6 "$SEED_FILE")

echo "✔ ${count} issues créées."