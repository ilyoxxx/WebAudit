# Contribuer à webaudit

Merci de t'intéresser au projet. La bonne nouvelle : **tu n'as besoin de lire qu'un seul fichier** pour contribuer une règle. Pas besoin de comprendre le serveur, le moteur, ou le front.

## Le principe en 30 secondes

Une règle = un fichier TypeScript de ~30 lignes dans `src/rules/<catégorie>/`. Elle reçoit un `ScanContext` (headers HTTP, TLS, DNS, cookies, HTML...) déjà collecté, et renvoie un verdict `pass | warn | fail | na`.

Tu n'écris jamais de requête réseau, jamais de texte affiché à l'utilisateur (tout passe par des clés i18n dans `/locales`).

## Ajouter une règle en 3 étapes

### 1. Génère le squelette

```bash
npm run new:rule
```

Le script te demande l'identifiant, la catégorie, un lien de doc et un poids, et crée le fichier pour toi.

### 2. Implémente `evaluate()`

Exemple complet — la règle HSTS, à copier/adapter (`src/rules/security/hsts.ts`) :

```ts
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/hsts',
  category: 'security',
  weight: 8,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['strict-transport-security'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.hsts.missing',
        remediationKey: 'security.hsts.remediation',
      };
    }

    return { status: 'pass', messageKey: 'security.hsts.ok', evidence: header };
  },
};

export default rule;
```

Ce que tu as à disposition dans `ctx` (voir `src/types.ts` pour le détail complet) :

| Champ | Contenu |
|---|---|
| `ctx.http.headers` | Tous les headers HTTP de la réponse, en minuscules |
| `ctx.http.bodyHtml` | Le HTML brut de la page |
| `ctx.tls` | Infos certificat (validité, expiration, protocole) |
| `ctx.dns` | Enregistrements A/AAAA/MX/TXT |
| `ctx.cookies` | Cookies posés (nom, Secure, HttpOnly, SameSite) |
| `ctx.robotsTxt` | Contenu de robots.txt s'il existe |
| `ctx.mentionsLegalesDetected` | Booléen, détection heuristique d'une page mentions légales |

**Règles à respecter :**
- Jamais de texte en dur → toujours une `messageKey`.
- Jamais d'appel réseau dans `evaluate()` — c'est une fonction pure.
- La règle ne doit jamais `throw` volontairement (le moteur intercepte déjà les crashs, mais un `status: 'na'` explicite est plus propre si le contexte manque de données).

### 3. Ajoute les clés de traduction

Dans `locales/fr.json` **et** `locales/en.json`, ajoute au minimum :

```json
{
  "security.hsts.missing": "Le site n'envoie pas d'en-tête HSTS.",
  "security.hsts.ok": "HSTS est correctement configuré.",
  "security.hsts.remediation": "Ajoutez 'Strict-Transport-Security: max-age=31536000'."
}
```

Tu n'es **pas obligé** de traduire en anglais si tu ne le maîtrises pas — une PR avec seulement le FR est acceptée, quelqu'un complétera l'EN.

## Ouvrir la PR

- Une PR = une règle (ou une correction de traduction). Pas de PR fourre-tout.
- Titre : `feat(rules): security/permissions-policy`
- Si un test existe pour ta règle, lance `npm test`. Sinon ce n'est pas bloquant à ce stade du projet.
- Référence l'issue `good first issue` correspondante si elle existe (`Closes #12`).

## Contribuer autrement

- **Traductions** (`/locales`) : ajouter une langue, ou compléter les clés manquantes en EN.
- **Collectors** (`src/collectors/`) : plus technique, discute d'abord en issue avant d'ouvrir une PR (ça touche à plusieurs règles).
- **Documentation** : corriger le README, ajouter des exemples.

## Ce qu'on n'accepte pas (pour l'instant)

- Puppeteer / Chrome headless — voir le README pour la raison. On reste sur `fetch` + parsing HTML pendant les premiers mois.
- Des règles qui dépendent d'API tierces payantes.
- Du texte affiché en dur hors du système i18n.

Des questions ? Ouvre une issue avec le label `question`.
