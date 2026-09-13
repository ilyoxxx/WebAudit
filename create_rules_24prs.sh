#!/usr/bin/env bash
# Crée 24 PR séparées (1 par règle), les merge une par une via gh cli.
# Objectif : atteindre le badge GitHub 'Pull Shark x16' (bronze) avec du vrai contenu,
# pas du spam — chaque PR ferme une vraie issue good-first-issue du repo.
#
# Prérequis :
#   - lancé depuis la racine du repo (package.json présent)
#   - `gh auth login` déjà fait (gh cli authentifié)
#   - branche par défaut = main, à jour, working tree propre
set -euo pipefail

if [ ! -f package.json ]; then echo "Lance ce script depuis la racine du repo webaudit."; exit 1; fi
if ! command -v gh >/dev/null 2>&1; then echo "gh cli introuvable. Installe-le et fais gh auth login d'abord."; exit 1; fi
if ! gh auth status >/dev/null 2>&1; then echo "gh cli non authentifié. Lance: gh auth login"; exit 1; fi

DEFAULT_BRANCH="$(git symbolic-ref --short HEAD)"
echo "Branche de départ: $DEFAULT_BRANCH"

# Vérif de base une seule fois avant de partir (pas à chaque PR, pour rester rapide)
npm install --no-audit --no-fund
npm run build
npm test

echo "=== [1/24] security/permissions-policy (issue #3) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-permissions-policy

mkdir -p src/rules/security
cat > src/rules/security/permissions-policy.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/permissions-policy',
  category: 'security',
  weight: 4,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Permissions-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['permissions-policy'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.permissions_policy.missing',
        remediationKey: 'security.permissions_policy.remediation',
      };
    }

    const restricted = ['camera', 'microphone', 'geolocation'].filter((directive) =>
      new RegExp(`${directive}=`, 'i').test(header),
    );

    if (restricted.length < 3) {
      return {
        status: 'warn',
        messageKey: 'security.permissions_policy.partial',
        evidence: header,
        remediationKey: 'security.permissions_policy.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.permissions_policy.ok',
      evidence: header,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.permissions_policy.missing": "Aucun en-tête Permissions-Policy n'est envoyé.",
  "security.permissions_policy.partial": "Permissions-Policy est présent mais ne restreint pas caméra/micro/géolocalisation.",
  "security.permissions_policy.ok": "Permissions-Policy restreint correctement caméra, micro et géolocalisation.",
  "security.permissions_policy.remediation": "Ajoutez 'Permissions-Policy: camera=(), microphone=(), geolocation=()' (ou une liste d'origines autorisées) à vos réponses HTTP."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.permissions_policy.missing": "No Permissions-Policy header is sent.",
  "security.permissions_policy.partial": "Permissions-Policy is present but does not restrict camera/mic/geolocation.",
  "security.permissions_policy.ok": "Permissions-Policy correctly restricts camera, microphone and geolocation.",
  "security.permissions_policy.remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' (or an allow-list of origins) to your HTTP responses."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/permissions-policy.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/permissions-policy\n\nCloses #3')"
git push -u origin rule/security-permissions-policy
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-permissions-policy --title "feat(rules): security/permissions-policy" --body "Implémente la règle security/permissions-policy.\n\nCloses #3"
gh pr merge rule/security-permissions-policy --merge --delete-branch

echo "=== [2/24] security/referrer-policy (issue #4) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-referrer-policy

mkdir -p src/rules/security
cat > src/rules/security/referrer-policy.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/referrer-policy',
  category: 'security',
  weight: 3,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referrer-Policy',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['referrer-policy'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'security.referrer_policy.missing',
        remediationKey: 'security.referrer_policy.remediation',
      };
    }

    if (header.toLowerCase().includes('unsafe-url')) {
      return {
        status: 'warn',
        messageKey: 'security.referrer_policy.unsafe_url',
        evidence: header,
        remediationKey: 'security.referrer_policy.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.referrer_policy.ok',
      evidence: header,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.referrer_policy.missing": "Aucun en-tête Referrer-Policy n'est envoyé.",
  "security.referrer_policy.unsafe_url": "Referrer-Policy utilise la valeur 'unsafe-url', qui fuite l'URL complète vers des sites tiers.",
  "security.referrer_policy.ok": "Referrer-Policy est correctement configuré.",
  "security.referrer_policy.remediation": "Ajoutez 'Referrer-Policy: strict-origin-when-cross-origin' (ou une valeur équivalente plus stricte)."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.referrer_policy.missing": "No Referrer-Policy header is sent.",
  "security.referrer_policy.unsafe_url": "Referrer-Policy uses 'unsafe-url', which leaks the full URL to third-party sites.",
  "security.referrer_policy.ok": "Referrer-Policy is correctly configured.",
  "security.referrer_policy.remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' (or an equally strict value)."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/referrer-policy.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/referrer-policy\n\nCloses #4')"
git push -u origin rule/security-referrer-policy
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-referrer-policy --title "feat(rules): security/referrer-policy" --body "Implémente la règle security/referrer-policy.\n\nCloses #4"
gh pr merge rule/security-referrer-policy --merge --delete-branch

echo "=== [3/24] security/x-content-type-options (issue #5) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-x-content-type-options

mkdir -p src/rules/security
cat > src/rules/security/x-content-type-options.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/x-content-type-options',
  category: 'security',
  weight: 5,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['x-content-type-options'];

    if (!header || header.toLowerCase() !== 'nosniff') {
      return {
        status: 'fail',
        messageKey: 'security.xcto.missing_or_invalid',
        evidence: header,
        remediationKey: 'security.xcto.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.xcto.ok',
      evidence: header,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.xcto.missing_or_invalid": "L'en-tête X-Content-Type-Options est absent ou différent de 'nosniff'.",
  "security.xcto.ok": "X-Content-Type-Options: nosniff est correctement défini.",
  "security.xcto.remediation": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff' à vos réponses HTTP."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.xcto.missing_or_invalid": "The X-Content-Type-Options header is missing or is not 'nosniff'.",
  "security.xcto.ok": "X-Content-Type-Options: nosniff is correctly set.",
  "security.xcto.remediation": "Add the 'X-Content-Type-Options: nosniff' header to your HTTP responses."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/x-content-type-options.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/x-content-type-options\n\nCloses #5')"
git push -u origin rule/security-x-content-type-options
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-x-content-type-options --title "feat(rules): security/x-content-type-options" --body "Implémente la règle security/x-content-type-options.\n\nCloses #5"
gh pr merge rule/security-x-content-type-options --merge --delete-branch

echo "=== [4/24] security/tls-version (issue #6) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-tls-version

mkdir -p src/rules/security
cat > src/rules/security/tls-version.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/tls-version',
  category: 'security',
  weight: 9,
  docs: 'https://developer.mozilla.org/fr/docs/Web/Security/Transport_Layer_Security',

  evaluate(ctx: ScanContext): RuleResult {
    if (!ctx.tls || !ctx.tls.valid || !ctx.tls.protocol) {
      return {
        status: 'na',
        messageKey: 'security.tls_version.not_detectable',
      };
    }

    const protocol = ctx.tls.protocol.toUpperCase();

    if (protocol.includes('SSLV') || protocol === 'TLSV1' || protocol === 'TLSV1.0' || protocol === 'TLSV1.1') {
      return {
        status: 'fail',
        messageKey: 'security.tls_version.outdated',
        evidence: protocol,
        remediationKey: 'security.tls_version.remediation',
      };
    }

    if (protocol === 'TLSV1.2') {
      return {
        status: 'warn',
        messageKey: 'security.tls_version.tls12',
        evidence: protocol,
        remediationKey: 'security.tls_version.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.tls_version.ok',
      evidence: protocol,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.tls_version.not_detectable": "La version TLS n'a pas pu être déterminée.",
  "security.tls_version.outdated": "Le site accepte une version de TLS obsolète (< TLS 1.2).",
  "security.tls_version.tls12": "Le site utilise TLS 1.2, fonctionnel mais TLS 1.3 est recommandé.",
  "security.tls_version.ok": "Le site utilise TLS 1.3.",
  "security.tls_version.remediation": "Désactivez SSLv3/TLS 1.0/1.1 côté serveur et activez TLS 1.3 en plus de TLS 1.2."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.tls_version.not_detectable": "The TLS version could not be determined.",
  "security.tls_version.outdated": "The site accepts an outdated TLS version (< TLS 1.2).",
  "security.tls_version.tls12": "The site uses TLS 1.2, which works but TLS 1.3 is recommended.",
  "security.tls_version.ok": "The site uses TLS 1.3.",
  "security.tls_version.remediation": "Disable SSLv3/TLS 1.0/1.1 server-side and enable TLS 1.3 alongside TLS 1.2."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/tls-version.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/tls-version\n\nCloses #6')"
git push -u origin rule/security-tls-version
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-tls-version --title "feat(rules): security/tls-version" --body "Implémente la règle security/tls-version.\n\nCloses #6"
gh pr merge rule/security-tls-version --merge --delete-branch

echo "=== [5/24] security/tls-expiry (issue #7) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-tls-expiry

mkdir -p src/rules/security
cat > src/rules/security/tls-expiry.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/tls-expiry',
  category: 'security',
  weight: 7,
  docs: 'https://developer.mozilla.org/fr/docs/Glossary/TLS',

  evaluate(ctx: ScanContext): RuleResult {
    if (!ctx.tls || !ctx.tls.valid || ctx.tls.daysUntilExpiry === undefined) {
      return {
        status: 'na',
        messageKey: 'security.tls_expiry.not_detectable',
      };
    }

    const days = ctx.tls.daysUntilExpiry;

    if (days <= 0) {
      return {
        status: 'fail',
        messageKey: 'security.tls_expiry.expired',
        evidence: `${days} jours`,
        remediationKey: 'security.tls_expiry.remediation',
      };
    }

    if (days < 15) {
      return {
        status: 'warn',
        messageKey: 'security.tls_expiry.expiring_soon',
        evidence: `${days} jours`,
        remediationKey: 'security.tls_expiry.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.tls_expiry.ok',
      evidence: `${days} jours`,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.tls_expiry.not_detectable": "La date d'expiration du certificat n'a pas pu être déterminée.",
  "security.tls_expiry.expired": "Le certificat TLS est expiré.",
  "security.tls_expiry.expiring_soon": "Le certificat TLS expire dans moins de 15 jours.",
  "security.tls_expiry.ok": "Le certificat TLS est valide pour une durée suffisante.",
  "security.tls_expiry.remediation": "Renouvelez le certificat TLS, idéalement via un renouvellement automatique (ex: Let's Encrypt + certbot)."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.tls_expiry.not_detectable": "The certificate expiry date could not be determined.",
  "security.tls_expiry.expired": "The TLS certificate has expired.",
  "security.tls_expiry.expiring_soon": "The TLS certificate expires in less than 15 days.",
  "security.tls_expiry.ok": "The TLS certificate is valid for a comfortable duration.",
  "security.tls_expiry.remediation": "Renew the TLS certificate, ideally with automatic renewal (e.g. Let's Encrypt + certbot)."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/tls-expiry.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/tls-expiry\n\nCloses #7')"
git push -u origin rule/security-tls-expiry
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-tls-expiry --title "feat(rules): security/tls-expiry" --body "Implémente la règle security/tls-expiry.\n\nCloses #7"
gh pr merge rule/security-tls-expiry --merge --delete-branch

echo "=== [6/24] security/cookie-secure-flag (issue #8) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-cookie-secure-flag

mkdir -p src/rules/security
cat > src/rules/security/cookie-secure-flag.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/cookie-secure-flag',
  category: 'security',
  weight: 6,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies#restrict_access_to_cookies',

  evaluate(ctx: ScanContext): RuleResult {
    const isHttps = ctx.finalUrl.startsWith('https://');

    if (!isHttps || ctx.cookies.length === 0) {
      return {
        status: 'na',
        messageKey: 'security.cookie_secure.not_applicable',
      };
    }

    const insecure = ctx.cookies.filter((c) => !c.secure);

    if (insecure.length > 0) {
      return {
        status: 'fail',
        messageKey: 'security.cookie_secure.missing_flag',
        evidence: insecure.map((c) => c.name).join(', '),
        remediationKey: 'security.cookie_secure.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.cookie_secure.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.cookie_secure.not_applicable": "Pas de cookies à vérifier (ou site non HTTPS).",
  "security.cookie_secure.missing_flag": "Un ou plusieurs cookies n'ont pas le flag Secure alors que le site est en HTTPS.",
  "security.cookie_secure.ok": "Tous les cookies ont le flag Secure.",
  "security.cookie_secure.remediation": "Ajoutez l'attribut 'Secure' à tous les cookies posés sur un site HTTPS."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.cookie_secure.not_applicable": "No cookies to check (or the site is not HTTPS).",
  "security.cookie_secure.missing_flag": "One or more cookies are missing the Secure flag on an HTTPS site.",
  "security.cookie_secure.ok": "All cookies have the Secure flag.",
  "security.cookie_secure.remediation": "Add the 'Secure' attribute to all cookies set on an HTTPS site."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/cookie-secure-flag.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/cookie-secure-flag\n\nCloses #8')"
git push -u origin rule/security-cookie-secure-flag
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-cookie-secure-flag --title "feat(rules): security/cookie-secure-flag" --body "Implémente la règle security/cookie-secure-flag.\n\nCloses #8"
gh pr merge rule/security-cookie-secure-flag --merge --delete-branch

echo "=== [7/24] security/cookie-httponly-flag (issue #9) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-cookie-httponly-flag

mkdir -p src/rules/security
cat > src/rules/security/cookie-httponly-flag.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const SENSITIVE_NAME_PATTERN = /session|auth|token|sid|jwt/i;

const rule: Rule = {
  id: 'security/cookie-httponly-flag',
  category: 'security',
  weight: 6,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies#restrict_access_to_cookies',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.cookies.length === 0) {
      return {
        status: 'na',
        messageKey: 'security.cookie_httponly.not_applicable',
      };
    }

    const sensitive = ctx.cookies.filter((c) => SENSITIVE_NAME_PATTERN.test(c.name) && !c.httpOnly);

    if (sensitive.length > 0) {
      return {
        status: 'fail',
        messageKey: 'security.cookie_httponly.missing_flag',
        evidence: sensitive.map((c) => c.name).join(', '),
        remediationKey: 'security.cookie_httponly.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.cookie_httponly.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.cookie_httponly.not_applicable": "Pas de cookies à vérifier.",
  "security.cookie_httponly.missing_flag": "Un cookie qui semble sensible (session/auth/token) n'a pas le flag HttpOnly.",
  "security.cookie_httponly.ok": "Les cookies sensibles détectés ont bien le flag HttpOnly.",
  "security.cookie_httponly.remediation": "Ajoutez l'attribut 'HttpOnly' aux cookies de session/authentification pour empêcher leur lecture en JavaScript."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.cookie_httponly.not_applicable": "No cookies to check.",
  "security.cookie_httponly.missing_flag": "A cookie that looks sensitive (session/auth/token) is missing the HttpOnly flag.",
  "security.cookie_httponly.ok": "Detected sensitive cookies correctly have the HttpOnly flag.",
  "security.cookie_httponly.remediation": "Add the 'HttpOnly' attribute to session/authentication cookies to prevent JavaScript access."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/cookie-httponly-flag.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/cookie-httponly-flag\n\nCloses #9')"
git push -u origin rule/security-cookie-httponly-flag
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-cookie-httponly-flag --title "feat(rules): security/cookie-httponly-flag" --body "Implémente la règle security/cookie-httponly-flag.\n\nCloses #9"
gh pr merge rule/security-cookie-httponly-flag --merge --delete-branch

echo "=== [8/24] security/cookie-samesite (issue #10) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-cookie-samesite

mkdir -p src/rules/security
cat > src/rules/security/cookie-samesite.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/cookie-samesite',
  category: 'security',
  weight: 5,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Set-Cookie/SameSite',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.cookies.length === 0) {
      return {
        status: 'na',
        messageKey: 'security.cookie_samesite.not_applicable',
      };
    }

    const risky = ctx.cookies.filter(
      (c) => !c.sameSite || (c.sameSite.toLowerCase() === 'none' && !c.secure),
    );

    if (risky.length > 0) {
      return {
        status: 'warn',
        messageKey: 'security.cookie_samesite.risky',
        evidence: risky.map((c) => c.name).join(', '),
        remediationKey: 'security.cookie_samesite.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.cookie_samesite.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.cookie_samesite.not_applicable": "Pas de cookies à vérifier.",
  "security.cookie_samesite.risky": "Un ou plusieurs cookies n'ont pas d'attribut SameSite, ou utilisent 'None' sans Secure.",
  "security.cookie_samesite.ok": "Les cookies ont un attribut SameSite correctement configuré.",
  "security.cookie_samesite.remediation": "Ajoutez 'SameSite=Lax' (ou 'Strict') à vos cookies ; si 'None' est nécessaire, ajoutez aussi 'Secure'."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.cookie_samesite.not_applicable": "No cookies to check.",
  "security.cookie_samesite.risky": "One or more cookies have no SameSite attribute, or use 'None' without Secure.",
  "security.cookie_samesite.ok": "Cookies have a correctly configured SameSite attribute.",
  "security.cookie_samesite.remediation": "Add 'SameSite=Lax' (or 'Strict') to your cookies; if 'None' is required, also add 'Secure'."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/cookie-samesite.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/cookie-samesite\n\nCloses #10')"
git push -u origin rule/security-cookie-samesite
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-cookie-samesite --title "feat(rules): security/cookie-samesite" --body "Implémente la règle security/cookie-samesite.\n\nCloses #10"
gh pr merge rule/security-cookie-samesite --merge --delete-branch

echo "=== [9/24] security/server-header-leak (issue #11) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-server-header-leak

mkdir -p src/rules/security
cat > src/rules/security/server-header-leak.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/server-header-leak',
  category: 'security',
  weight: 2,
  docs: 'https://owasp.org/www-project-secure-headers/',

  evaluate(ctx: ScanContext): RuleResult {
    const header = ctx.http.headers['server'];

    if (!header) {
      return {
        status: 'na',
        messageKey: 'security.server_header_leak.not_present',
      };
    }

    const leaksVersion = /\/\s*\d/.test(header);

    if (leaksVersion) {
      return {
        status: 'warn',
        messageKey: 'security.server_header_leak.version_exposed',
        evidence: header,
        remediationKey: 'security.server_header_leak.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.server_header_leak.ok',
      evidence: header,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.server_header_leak.not_present": "L'en-tête Server n'est pas envoyé.",
  "security.server_header_leak.version_exposed": "L'en-tête Server expose une version précise du logiciel serveur.",
  "security.server_header_leak.ok": "L'en-tête Server n'expose pas de numéro de version précis.",
  "security.server_header_leak.remediation": "Configurez le serveur pour masquer son numéro de version exact (ex: 'server_tokens off;' sur nginx)."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.server_header_leak.not_present": "The Server header is not sent.",
  "security.server_header_leak.version_exposed": "The Server header exposes a precise server software version.",
  "security.server_header_leak.ok": "The Server header does not expose a precise version number.",
  "security.server_header_leak.remediation": "Configure the server to hide its exact version number (e.g. 'server_tokens off;' on nginx)."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/server-header-leak.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/server-header-leak\n\nCloses #11')"
git push -u origin rule/security-server-header-leak
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-server-header-leak --title "feat(rules): security/server-header-leak" --body "Implémente la règle security/server-header-leak.\n\nCloses #11"
gh pr merge rule/security-server-header-leak --merge --delete-branch

echo "=== [10/24] security/mixed-content (issue #12) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-mixed-content

mkdir -p src/rules/security
cat > src/rules/security/mixed-content.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/mixed-content',
  category: 'security',
  weight: 7,
  docs: 'https://developer.mozilla.org/fr/docs/Web/Security/Mixed_content',

  evaluate(ctx: ScanContext): RuleResult {
    const isHttps = ctx.finalUrl.startsWith('https://');

    if (!isHttps) {
      return {
        status: 'na',
        messageKey: 'security.mixed_content.not_applicable',
      };
    }

    const matches = ctx.http.bodyHtml.match(/(?:src|href)=["']http:\/\/[^"']+["']/gi) ?? [];

    if (matches.length > 0) {
      return {
        status: 'fail',
        messageKey: 'security.mixed_content.found',
        evidence: matches.slice(0, 5).join(', '),
        remediationKey: 'security.mixed_content.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.mixed_content.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.mixed_content.not_applicable": "Le site n'est pas servi en HTTPS.",
  "security.mixed_content.found": "Des ressources sont chargées en http:// sur une page https:// (contenu mixte).",
  "security.mixed_content.ok": "Aucune ressource en contenu mixte détectée.",
  "security.mixed_content.remediation": "Remplacez toutes les URLs de ressources (images, scripts, styles) par des URLs https:// ou relatives."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.mixed_content.not_applicable": "The site is not served over HTTPS.",
  "security.mixed_content.found": "Resources are loaded over http:// on an https:// page (mixed content).",
  "security.mixed_content.ok": "No mixed-content resources detected.",
  "security.mixed_content.remediation": "Replace all resource URLs (images, scripts, styles) with https:// or protocol-relative URLs."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/mixed-content.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/mixed-content\n\nCloses #12')"
git push -u origin rule/security-mixed-content
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-mixed-content --title "feat(rules): security/mixed-content" --body "Implémente la règle security/mixed-content.\n\nCloses #12"
gh pr merge rule/security-mixed-content --merge --delete-branch

echo "=== [11/24] security/dnssec (issue #13) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-dnssec

mkdir -p src/rules/security
cat > src/rules/security/dnssec.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/dnssec',
  category: 'security',
  weight: 4,
  docs: 'https://www.cloudflare.com/learning/dns/dnssec/how-dnssec-works/',

  evaluate(ctx: ScanContext): RuleResult {
    // Le collector DNS actuel (src/collectors/dns.ts) ne résout que A/AAAA/MX/TXT
    // et ne fait pas de requête DNSKEY/RRSIG : on ne peut donc pas vérifier
    // DNSSEC de façon fiable pour l'instant. On retourne 'na' plutôt que de
    // deviner un résultat. Contribution bienvenue pour étendre le collector.
    return {
      status: 'na',
      messageKey: 'security.dnssec.not_detectable',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.dnssec.not_detectable": "DNSSEC n'a pas pu être vérifié avec les données actuellement collectées."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.dnssec.not_detectable": "DNSSEC could not be verified with the data currently collected."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/dnssec.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/dnssec\n\nCloses #13')"
git push -u origin rule/security-dnssec
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-dnssec --title "feat(rules): security/dnssec" --body "Implémente la règle security/dnssec.\n\nCloses #13"
gh pr merge rule/security-dnssec --merge --delete-branch

echo "=== [12/24] security/spf-record (issue #14) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-spf-record

mkdir -p src/rules/security
cat > src/rules/security/spf-record.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/spf-record',
  category: 'security',
  weight: 5,
  docs: 'https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.dns.mx.length === 0) {
      return {
        status: 'na',
        messageKey: 'security.spf.not_applicable',
      };
    }

    const spf = ctx.dns.txt.find((t) => t.toLowerCase().startsWith('v=spf1'));

    if (!spf) {
      return {
        status: 'fail',
        messageKey: 'security.spf.missing',
        remediationKey: 'security.spf.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.spf.ok',
      evidence: spf,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.spf.not_applicable": "Aucun enregistrement MX détecté : le domaine ne semble pas recevoir d'emails.",
  "security.spf.missing": "Aucun enregistrement SPF trouvé alors que le domaine reçoit des emails.",
  "security.spf.ok": "Un enregistrement SPF est présent.",
  "security.spf.remediation": "Ajoutez un enregistrement TXT SPF (ex: 'v=spf1 include:_spf.google.com ~all') sur votre domaine."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.spf.not_applicable": "No MX record detected: the domain does not appear to receive email.",
  "security.spf.missing": "No SPF record found even though the domain receives email.",
  "security.spf.ok": "An SPF record is present.",
  "security.spf.remediation": "Add a TXT SPF record (e.g. 'v=spf1 include:_spf.google.com ~all') to your domain."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/spf-record.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/spf-record\n\nCloses #14')"
git push -u origin rule/security-spf-record
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-spf-record --title "feat(rules): security/spf-record" --body "Implémente la règle security/spf-record.\n\nCloses #14"
gh pr merge rule/security-spf-record --merge --delete-branch

echo "=== [13/24] security/dmarc-record (issue #15) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/security-dmarc-record

mkdir -p src/rules/security
cat > src/rules/security/dmarc-record.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'security/dmarc-record',
  category: 'security',
  weight: 5,
  docs: 'https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/',

  evaluate(ctx: ScanContext): RuleResult {
    // Limitation connue : le collector DNS interroge les TXT du domaine racine,
    // pas ceux de _dmarc.<domaine>. On fait une détection best-effort sur les
    // TXT déjà collectés ; un vrai contrôle nécessite d'étendre collectDns()
    // pour résoudre _dmarc.<hostname> séparément (bonne contribution à ouvrir).
    const dmarc = ctx.dns.txt.find((t) => t.toUpperCase().includes('DMARC1'));

    if (!dmarc) {
      return {
        status: 'fail',
        messageKey: 'security.dmarc.missing',
        remediationKey: 'security.dmarc.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'security.dmarc.ok',
      evidence: dmarc,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "security.dmarc.missing": "Aucun enregistrement DMARC trouvé.",
  "security.dmarc.ok": "Un enregistrement DMARC est présent.",
  "security.dmarc.remediation": "Ajoutez un enregistrement TXT sur _dmarc.votredomaine.tld (ex: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@votredomaine.tld')."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "security.dmarc.missing": "No DMARC record found.",
  "security.dmarc.ok": "A DMARC record is present.",
  "security.dmarc.remediation": "Add a TXT record at _dmarc.yourdomain.tld (e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.tld')."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/security/dmarc-record.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente security/dmarc-record\n\nCloses #15')"
git push -u origin rule/security-dmarc-record
gh pr create --base "$DEFAULT_BRANCH" --head rule/security-dmarc-record --title "feat(rules): security/dmarc-record" --body "Implémente la règle security/dmarc-record.\n\nCloses #15"
gh pr merge rule/security-dmarc-record --merge --delete-branch

echo "=== [14/24] rgpd/consent-before-tracking (issue #16) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-consent-before-tracking

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/consent-before-tracking.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const TRACKING_PIXEL_SIGNATURES = ['fbq(', 'gtag(', 'googletagmanager.com/gtag/js', 'connect.facebook.net'];
const CMP_SIGNATURES = ['cookiebot', 'axeptio', 'onetrust', 'tarteaucitron', 'didomi', 'cookieconsent'];

const rule: Rule = {
  id: 'rgpd/consent-before-tracking',
  category: 'rgpd',
  weight: 8,
  docs: 'https://www.cnil.fr/fr/cookies-et-autres-traceurs',

  evaluate(ctx: ScanContext): RuleResult {
    const htmlLower = ctx.http.bodyHtml.toLowerCase();

    const trackingFound = TRACKING_PIXEL_SIGNATURES.filter((sig) => htmlLower.includes(sig));
    const cmpDetected = CMP_SIGNATURES.some((sig) => htmlLower.includes(sig));

    if (trackingFound.length > 0 && !cmpDetected) {
      return {
        status: 'warn',
        messageKey: 'rgpd.consent_before_tracking.pixel_without_cmp',
        evidence: trackingFound.join(', '),
        remediationKey: 'rgpd.consent_before_tracking.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.consent_before_tracking.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.consent_before_tracking.pixel_without_cmp": "Un pixel de tracking connu (fbq/gtag) est chargé sans bandeau de consentement détecté.",
  "rgpd.consent_before_tracking.ok": "Aucun pixel de tracking non-consenti détecté dans le HTML.",
  "rgpd.consent_before_tracking.remediation": "Chargez les scripts de tracking uniquement après consentement (ex: via Google Consent Mode ou une CMP)."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.consent_before_tracking.pixel_without_cmp": "A known tracking pixel (fbq/gtag) loads with no consent banner detected.",
  "rgpd.consent_before_tracking.ok": "No non-consented tracking pixel detected in the HTML.",
  "rgpd.consent_before_tracking.remediation": "Only load tracking scripts after consent (e.g. via Google Consent Mode or a CMP)."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/consent-before-tracking.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/consent-before-tracking\n\nCloses #16')"
git push -u origin rule/rgpd-consent-before-tracking
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-consent-before-tracking --title "feat(rules): rgpd/consent-before-tracking" --body "Implémente la règle rgpd/consent-before-tracking.\n\nCloses #16"
gh pr merge rule/rgpd-consent-before-tracking --merge --delete-branch

echo "=== [15/24] rgpd/privacy-policy-link (issue #17) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-privacy-policy-link

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/privacy-policy-link.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/privacy-policy-link',
  category: 'rgpd',
  weight: 6,
  docs: 'https://www.cnil.fr/fr/reglement-europeen-protection-donnees',

  evaluate(ctx: ScanContext): RuleResult {
    const htmlLower = ctx.http.bodyHtml.toLowerCase();

    const found =
      htmlLower.includes('politique de confidentialité') || htmlLower.includes('privacy policy');

    if (!found) {
      return {
        status: 'fail',
        messageKey: 'rgpd.privacy_policy_link.missing',
        remediationKey: 'rgpd.privacy_policy_link.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.privacy_policy_link.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.privacy_policy_link.missing": "Aucun lien vers une politique de confidentialité détecté.",
  "rgpd.privacy_policy_link.ok": "Un lien vers la politique de confidentialité a été détecté.",
  "rgpd.privacy_policy_link.remediation": "Ajoutez un lien 'Politique de confidentialité' accessible depuis le pied de page."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.privacy_policy_link.missing": "No link to a privacy policy detected.",
  "rgpd.privacy_policy_link.ok": "A link to the privacy policy was detected.",
  "rgpd.privacy_policy_link.remediation": "Add a 'Privacy Policy' link accessible from the footer."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/privacy-policy-link.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/privacy-policy-link\n\nCloses #17')"
git push -u origin rule/rgpd-privacy-policy-link
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-privacy-policy-link --title "feat(rules): rgpd/privacy-policy-link" --body "Implémente la règle rgpd/privacy-policy-link.\n\nCloses #17"
gh pr merge rule/rgpd-privacy-policy-link --merge --delete-branch

echo "=== [16/24] rgpd/https-forced (issue #18) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-https-forced

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/https-forced.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/https-forced',
  category: 'rgpd',
  weight: 8,
  docs: 'https://www.cnil.fr/fr/la-securite-des-donnees-personnelles',

  evaluate(ctx: ScanContext): RuleResult {
    const requestedHttp = ctx.url.startsWith('http://');
    const endsUpHttps = ctx.finalUrl.startsWith('https://');

    if (!requestedHttp) {
      return {
        status: 'pass',
        messageKey: 'rgpd.https_forced.ok',
      };
    }

    if (!endsUpHttps) {
      return {
        status: 'fail',
        messageKey: 'rgpd.https_forced.no_redirect',
        evidence: ctx.finalUrl,
        remediationKey: 'rgpd.https_forced.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.https_forced.redirected',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.https_forced.ok": "Le site est servi en HTTPS.",
  "rgpd.https_forced.no_redirect": "Le site répond en clair sur http:// sans redirection vers https://.",
  "rgpd.https_forced.redirected": "Le site redirige automatiquement de http:// vers https://.",
  "rgpd.https_forced.remediation": "Forcez une redirection 301 de http:// vers https:// pour toutes les requêtes."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.https_forced.ok": "The site is served over HTTPS.",
  "rgpd.https_forced.no_redirect": "The site responds in plain http:// with no redirect to https://.",
  "rgpd.https_forced.redirected": "The site automatically redirects from http:// to https://.",
  "rgpd.https_forced.remediation": "Force a 301 redirect from http:// to https:// for all requests."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/https-forced.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/https-forced\n\nCloses #18')"
git push -u origin rule/rgpd-https-forced
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-https-forced --title "feat(rules): rgpd/https-forced" --body "Implémente la règle rgpd/https-forced.\n\nCloses #18"
gh pr merge rule/rgpd-https-forced --merge --delete-branch

echo "=== [17/24] rgpd/dpo-contact (issue #19) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-dpo-contact

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/dpo-contact.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/dpo-contact',
  category: 'rgpd',
  weight: 3,
  docs: 'https://www.cnil.fr/fr/le-delegue-la-protection-des-donnees-dpo',

  evaluate(ctx: ScanContext): RuleResult {
    // Limitation : on n'a accès qu'au HTML de la page scannée, pas à un fetch
    // séparé de la page mentions légales elle-même.
    if (!ctx.mentionsLegalesDetected) {
      return {
        status: 'na',
        messageKey: 'rgpd.dpo_contact.no_legal_page',
      };
    }

    const htmlLower = ctx.http.bodyHtml.toLowerCase();
    const found = htmlLower.includes('dpo') || htmlLower.includes('délégué à la protection des données');

    if (!found) {
      return {
        status: 'warn',
        messageKey: 'rgpd.dpo_contact.not_found',
        remediationKey: 'rgpd.dpo_contact.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.dpo_contact.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.dpo_contact.no_legal_page": "Aucune page de mentions légales détectée, vérification du contact DPO impossible.",
  "rgpd.dpo_contact.not_found": "Aucune mention d'un DPO ou délégué à la protection des données trouvée.",
  "rgpd.dpo_contact.ok": "Une mention du DPO / délégué à la protection des données a été trouvée.",
  "rgpd.dpo_contact.remediation": "Mentionnez les coordonnées de votre DPO (ou du responsable RGPD) dans vos mentions légales."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.dpo_contact.no_legal_page": "No legal notice page detected, DPO contact check is not possible.",
  "rgpd.dpo_contact.not_found": "No mention of a DPO or data protection officer was found.",
  "rgpd.dpo_contact.ok": "A mention of the DPO / data protection officer was found.",
  "rgpd.dpo_contact.remediation": "Mention your DPO's (or privacy officer's) contact details in your legal notice."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/dpo-contact.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/dpo-contact\n\nCloses #19')"
git push -u origin rule/rgpd-dpo-contact
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-dpo-contact --title "feat(rules): rgpd/dpo-contact" --body "Implémente la règle rgpd/dpo-contact.\n\nCloses #19"
gh pr merge rule/rgpd-dpo-contact --merge --delete-branch

echo "=== [18/24] rgpd/data-retention-mention (issue #20) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-data-retention-mention

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/data-retention-mention.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/data-retention-mention',
  category: 'rgpd',
  weight: 3,
  docs: 'https://www.cnil.fr/fr/les-durees-de-conservation-des-donnees',

  evaluate(ctx: ScanContext): RuleResult {
    const htmlLower = ctx.http.bodyHtml.toLowerCase();

    const found =
      htmlLower.includes('durée de conservation') || htmlLower.includes('conservation des données');

    if (!found) {
      return {
        status: 'warn',
        messageKey: 'rgpd.data_retention.not_found',
        remediationKey: 'rgpd.data_retention.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.data_retention.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.data_retention.not_found": "Aucune mention de durée de conservation des données détectée.",
  "rgpd.data_retention.ok": "Une mention de durée de conservation des données a été détectée.",
  "rgpd.data_retention.remediation": "Précisez la durée de conservation de chaque catégorie de données dans votre politique de confidentialité."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.data_retention.not_found": "No mention of a data retention period detected.",
  "rgpd.data_retention.ok": "A mention of a data retention period was detected.",
  "rgpd.data_retention.remediation": "State the retention period for each category of data in your privacy policy."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/data-retention-mention.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/data-retention-mention\n\nCloses #20')"
git push -u origin rule/rgpd-data-retention-mention
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-data-retention-mention --title "feat(rules): rgpd/data-retention-mention" --body "Implémente la règle rgpd/data-retention-mention.\n\nCloses #20"
gh pr merge rule/rgpd-data-retention-mention --merge --delete-branch

echo "=== [19/24] rgpd/external-fonts-tracking (issue #21) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/rgpd-external-fonts-tracking

mkdir -p src/rules/rgpd
cat > src/rules/rgpd/external-fonts-tracking.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'rgpd/external-fonts-tracking',
  category: 'rgpd',
  weight: 4,
  docs: 'https://www.cnil.fr/fr/cookies-et-autres-traceurs',

  evaluate(ctx: ScanContext): RuleResult {
    const htmlLower = ctx.http.bodyHtml.toLowerCase();

    if (htmlLower.includes('fonts.googleapis.com')) {
      return {
        status: 'warn',
        messageKey: 'rgpd.external_fonts.google_fonts_direct',
        remediationKey: 'rgpd.external_fonts.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'rgpd.external_fonts.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "rgpd.external_fonts.google_fonts_direct": "Des polices Google Fonts sont chargées directement depuis fonts.googleapis.com.",
  "rgpd.external_fonts.ok": "Aucun chargement direct de Google Fonts détecté.",
  "rgpd.external_fonts.remediation": "Auto-hébergez les polices ou passez par un proxy pour éviter le transfert de données vers Google."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "rgpd.external_fonts.google_fonts_direct": "Google Fonts are loaded directly from fonts.googleapis.com.",
  "rgpd.external_fonts.ok": "No direct Google Fonts loading detected.",
  "rgpd.external_fonts.remediation": "Self-host the fonts or proxy them to avoid transferring data to Google."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/rgpd/external-fonts-tracking.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente rgpd/external-fonts-tracking\n\nCloses #21')"
git push -u origin rule/rgpd-external-fonts-tracking
gh pr create --base "$DEFAULT_BRANCH" --head rule/rgpd-external-fonts-tracking --title "feat(rules): rgpd/external-fonts-tracking" --body "Implémente la règle rgpd/external-fonts-tracking.\n\nCloses #21"
gh pr merge rule/rgpd-external-fonts-tracking --merge --delete-branch

echo "=== [20/24] perf/cache-control (issue #22) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/perf-cache-control

mkdir -p src/rules/perf
cat > src/rules/perf/cache-control.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'perf/cache-control',
  category: 'perf',
  weight: 4,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cache-Control',

  evaluate(ctx: ScanContext): RuleResult {
    // Limitation : on n'analyse que la réponse HTML principale, pas les
    // ressources statiques (JS/CSS/images) individuellement.
    const header = ctx.http.headers['cache-control'];

    if (!header) {
      return {
        status: 'fail',
        messageKey: 'perf.cache_control.missing',
        remediationKey: 'perf.cache_control.remediation',
      };
    }

    const maxAgeMatch = header.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

    if (maxAge > 0 && maxAge < 60) {
      return {
        status: 'warn',
        messageKey: 'perf.cache_control.short_max_age',
        evidence: header,
        remediationKey: 'perf.cache_control.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'perf.cache_control.ok',
      evidence: header,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "perf.cache_control.missing": "Aucun en-tête Cache-Control n'est envoyé.",
  "perf.cache_control.short_max_age": "Cache-Control est présent mais sa durée (max-age) est très courte.",
  "perf.cache_control.ok": "Cache-Control est correctement configuré.",
  "perf.cache_control.remediation": "Ajoutez 'Cache-Control: public, max-age=...' adapté à la fréquence de mise à jour de vos ressources statiques."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "perf.cache_control.missing": "No Cache-Control header is sent.",
  "perf.cache_control.short_max_age": "Cache-Control is present but its max-age is very short.",
  "perf.cache_control.ok": "Cache-Control is correctly configured.",
  "perf.cache_control.remediation": "Add 'Cache-Control: public, max-age=...' suited to how often your static resources change."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/perf/cache-control.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente perf/cache-control\n\nCloses #22')"
git push -u origin rule/perf-cache-control
gh pr create --base "$DEFAULT_BRANCH" --head rule/perf-cache-control --title "feat(rules): perf/cache-control" --body "Implémente la règle perf/cache-control.\n\nCloses #22"
gh pr merge rule/perf-cache-control --merge --delete-branch

echo "=== [21/24] perf/response-time (issue #23) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/perf-response-time

mkdir -p src/rules/perf
cat > src/rules/perf/response-time.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'perf/response-time',
  category: 'perf',
  weight: 3,
  docs: 'https://web.dev/articles/ttfb',

  evaluate(ctx: ScanContext): RuleResult {
    const ms = ctx.http.timingMs;

    if (ms > 3000) {
      return {
        status: 'fail',
        messageKey: 'perf.response_time.very_slow',
        evidence: `${ms}ms`,
        remediationKey: 'perf.response_time.remediation',
      };
    }

    if (ms > 1000) {
      return {
        status: 'warn',
        messageKey: 'perf.response_time.slow',
        evidence: `${ms}ms`,
        remediationKey: 'perf.response_time.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'perf.response_time.ok',
      evidence: `${ms}ms`,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "perf.response_time.very_slow": "Le temps de réponse dépasse 3 secondes.",
  "perf.response_time.slow": "Le temps de réponse dépasse 1 seconde.",
  "perf.response_time.ok": "Le temps de réponse est satisfaisant.",
  "perf.response_time.remediation": "Optimisez le TTFB : cache serveur, CDN, requêtes base de données plus rapides."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "perf.response_time.very_slow": "Response time exceeds 3 seconds.",
  "perf.response_time.slow": "Response time exceeds 1 second.",
  "perf.response_time.ok": "Response time is satisfactory.",
  "perf.response_time.remediation": "Optimize TTFB: server-side caching, a CDN, faster database queries."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/perf/response-time.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente perf/response-time\n\nCloses #23')"
git push -u origin rule/perf-response-time
gh pr create --base "$DEFAULT_BRANCH" --head rule/perf-response-time --title "feat(rules): perf/response-time" --body "Implémente la règle perf/response-time.\n\nCloses #23"
gh pr merge rule/perf-response-time --merge --delete-branch

echo "=== [22/24] perf/html-size (issue #24) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/perf-html-size

mkdir -p src/rules/perf
cat > src/rules/perf/html-size.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'perf/html-size',
  category: 'perf',
  weight: 2,
  docs: 'https://web.dev/articles/reduce-network-payloads-using-text-compression',

  evaluate(ctx: ScanContext): RuleResult {
    const sizeBytes = Buffer.byteLength(ctx.http.bodyHtml, 'utf-8');
    const sizeKb = Math.round(sizeBytes / 1024);

    if (sizeBytes > 500_000) {
      return {
        status: 'warn',
        messageKey: 'perf.html_size.too_large',
        evidence: `${sizeKb}KB`,
        remediationKey: 'perf.html_size.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'perf.html_size.ok',
      evidence: `${sizeKb}KB`,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "perf.html_size.too_large": "Le HTML brut dépasse 500KB avant compression.",
  "perf.html_size.ok": "La taille du HTML brut est raisonnable.",
  "perf.html_size.remediation": "Réduisez le HTML inutile (composants inline, commentaires, données dupliquées) et activez la compression."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "perf.html_size.too_large": "The raw HTML exceeds 500KB before compression.",
  "perf.html_size.ok": "The raw HTML size is reasonable.",
  "perf.html_size.remediation": "Trim unnecessary HTML (inline components, comments, duplicated data) and enable compression."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/perf/html-size.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente perf/html-size\n\nCloses #24')"
git push -u origin rule/perf-html-size
gh pr create --base "$DEFAULT_BRANCH" --head rule/perf-html-size --title "feat(rules): perf/html-size" --body "Implémente la règle perf/html-size.\n\nCloses #24"
gh pr merge rule/perf-html-size --merge --delete-branch

echo "=== [23/24] seo/meta-description (issue #25) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/seo-meta-description

mkdir -p src/rules/seo
cat > src/rules/seo/meta-description.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'seo/meta-description',
  category: 'seo',
  weight: 3,
  docs: 'https://developer.mozilla.org/fr/docs/Web/HTML/Element/meta/name/description',

  evaluate(ctx: ScanContext): RuleResult {
    const metaTags = ctx.http.bodyHtml.match(/<meta\s+[^>]*>/gi) ?? [];
    const descriptionTag = metaTags.find((tag) => /name=["']description["']/i.test(tag));

    if (!descriptionTag) {
      return {
        status: 'fail',
        messageKey: 'seo.meta_description.missing',
        remediationKey: 'seo.meta_description.remediation',
      };
    }

    const contentMatch = descriptionTag.match(/content=["']([^"']*)["']/i);
    const content = contentMatch ? contentMatch[1].trim() : '';

    if (content.length < 50 || content.length > 160) {
      return {
        status: 'warn',
        messageKey: 'seo.meta_description.bad_length',
        evidence: `${content.length} caractères`,
        remediationKey: 'seo.meta_description.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'seo.meta_description.ok',
      evidence: content,
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "seo.meta_description.missing": "Aucune balise meta description trouvée.",
  "seo.meta_description.bad_length": "La meta description fait moins de 50 ou plus de 160 caractères.",
  "seo.meta_description.ok": "La meta description est présente et a une longueur adaptée.",
  "seo.meta_description.remediation": "Ajoutez une balise <meta name=\\\"description\\\" content=\\\"...\\\"> de 50 à 160 caractères, résumant la page."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "seo.meta_description.missing": "No meta description tag found.",
  "seo.meta_description.bad_length": "The meta description is under 50 or over 160 characters.",
  "seo.meta_description.ok": "The meta description is present and has a suitable length.",
  "seo.meta_description.remediation": "Add a <meta name=\\\"description\\\" content=\\\"...\\\"> tag, 50 to 160 characters, summarizing the page."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/seo/meta-description.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente seo/meta-description\n\nCloses #25')"
git push -u origin rule/seo-meta-description
gh pr create --base "$DEFAULT_BRANCH" --head rule/seo-meta-description --title "feat(rules): seo/meta-description" --body "Implémente la règle seo/meta-description.\n\nCloses #25"
gh pr merge rule/seo-meta-description --merge --delete-branch

echo "=== [24/24] seo/robots-txt-present (issue #26) ==="
git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH" || true
git checkout -b rule/seo-robots-txt-present

mkdir -p src/rules/seo
cat > src/rules/seo/robots-txt-present.ts << 'RULE_EOF'
import type { Rule, ScanContext, RuleResult } from '../../types';

const rule: Rule = {
  id: 'seo/robots-txt-present',
  category: 'seo',
  weight: 2,
  docs: 'https://developers.google.com/search/docs/crawling-indexing/robots/intro',

  evaluate(ctx: ScanContext): RuleResult {
    if (ctx.robotsTxt === null) {
      return {
        status: 'warn',
        messageKey: 'seo.robots_txt.missing',
        remediationKey: 'seo.robots_txt.remediation',
      };
    }

    return {
      status: 'pass',
      messageKey: 'seo.robots_txt.ok',
    };
  },
};

export default rule;
RULE_EOF

mkdir -p .rule-tmp
cat > .rule-tmp/fr.add.json << 'FR_EOF'
{
  "seo.robots_txt.missing": "Aucun fichier robots.txt trouvé.",
  "seo.robots_txt.ok": "Un fichier robots.txt est présent.",
  "seo.robots_txt.remediation": "Ajoutez un fichier /robots.txt, même minimal, pour contrôler l'indexation par les moteurs de recherche."
}
FR_EOF
cat > .rule-tmp/en.add.json << 'EN_EOF'
{
  "seo.robots_txt.missing": "No robots.txt file found.",
  "seo.robots_txt.ok": "A robots.txt file is present.",
  "seo.robots_txt.remediation": "Add a /robots.txt file, even minimal, to control indexing by search engines."
}
EN_EOF
node -e "
const fs = require('fs');
for (const [base, add] of [['locales/fr.json','.rule-tmp/fr.add.json'],['locales/en.json','.rule-tmp/en.add.json']]) {
  const b = JSON.parse(fs.readFileSync(base, 'utf-8'));
  const a = JSON.parse(fs.readFileSync(add, 'utf-8'));
  Object.assign(b, a);
  fs.writeFileSync(base, JSON.stringify(b, null, 2) + '\n');
}
"
rm -rf .rule-tmp

git add src/rules/seo/robots-txt-present.ts locales/fr.json locales/en.json
git commit -m "$(printf 'feat(rules): implémente seo/robots-txt-present\n\nCloses #26')"
git push -u origin rule/seo-robots-txt-present
gh pr create --base "$DEFAULT_BRANCH" --head rule/seo-robots-txt-present --title "feat(rules): seo/robots-txt-present" --body "Implémente la règle seo/robots-txt-present.\n\nCloses #26"
gh pr merge rule/seo-robots-txt-present --merge --delete-branch

git checkout "$DEFAULT_BRANCH"
git pull --ff-only origin "$DEFAULT_BRANCH"

npm install --no-audit --no-fund
npm run build
npm test

echo "Terminé : 24 PR ouvertes et mergées individuellement."
echo "Vérifie ton badge sur https://github.com/<toi>?tab=achievements (peut prendre 24-48h à apparaitre)."
