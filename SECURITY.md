# Sécurité de WebAudit

## Variables d'environnement

| Variable | Rôle | Défaut |
|---|---|---|
| `SESSION_SECRET` | Secret de signature (**32 caractères minimum**, ex. `openssl rand -base64 48`) | — (connexion désactivée) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | OAuth GitHub | — |
| `BASE_URL` | URL publique **en https://** (active cookies `__Host-`, `Secure`, HSTS) | — |
| `DATA_DIR` | Dossier persistant (clés, sessions, quota) — monter un volume dessus | `./data` |
| `TRUST_PROXY` | Nombre de proxys devant l'appli (Railway seul = `1`, Cloudflare + Railway = `2`) | `1` |
| `FREE_SCANS_PER_DAY` | Scans gratuits / jour / réseau | `3` |
| `FREE_GLOBAL_PER_DAY` | Plafond global du gratuit / jour | `500` |
| `KEY_SCANS_PER_HOUR` | Plafond horaire par clé API | `120` |
| `TARGET_SCANS_PER_HOUR` | Scans / heure pour un même site cible | `10` |
| `MAX_CONCURRENT_SCANS` | Scans simultanés (global) | `8` |
| `ALLOW_SELF_SCAN` | `1` pour autoriser WebAudit à scanner son propre domaine | désactivé |

> Si `TRUST_PROXY` est faux, soit tous les visiteurs partagent un quota, soit le quota est contournable. À vérifier après déploiement.

## Ce qui est protégé

- **SSRF** (`src/security/ssrf.ts`) : refus des IP littérales (127.x, 10.x, 169.254.x, IPv6, formes décimale/hexa/octale), des noms internes (`localhost`, `*.internal`, `*.local`, noms sans point), des ports hors 80/443, des identifiants dans l'URL. La résolution DNS est vérifiée avant le scan **et** au moment de la connexion (anti DNS-rebinding). Les redirections sont suivies à la main et revalidées à chaque saut. Les messages d'erreur réseau ne sont plus renvoyés au client.
- **Quota** : basé sur l'IP vue par le proxy (pas sur un en-tête falsifiable), IPv6 regroupé par /64, persistant sur disque, plafond global, plafond par rafale, par cible, par clé, concurrence limitée, anti brute-force des clés.
- **Cookies / sessions** : sessions côté serveur (déconnexion = révocation réelle), cookie opaque `HttpOnly`, `Secure`, `SameSite=Strict`, préfixe `__Host-`, durée 24 h, OAuth avec `state` à usage unique + PKCE, protection CSRF (en-tête, `Origin`, `Sec-Fetch-Site`). Un cookie malformé ne peut plus faire planter le serveur.
- **API** : JSON limité à 4 Ko, erreurs sans stack trace, CSP stricte, HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `COOP/CORP`.
- **Clés API** : stockées sous forme d'empreinte SHA-256 (les anciennes clés en clair sont migrées automatiquement), fichiers de données en mode `0600`.

## Usurpation de l'adresse e-mail (spoofing) — à faire chez ton registrar / hébergeur DNS

WebAudit n'envoie aucun e-mail : l'usurpation de `contact@ilyox.fr` se règle **uniquement dans la zone DNS du domaine**. Trois enregistrements :

1. **SPF** (TXT sur `ilyox.fr`) : liste qui a le droit d'envoyer, et refuse le reste.
   - Le domaine n'envoie aucun mail : `v=spf1 -all`
   - Il envoie via un fournisseur : `v=spf1 include:<spf-du-fournisseur> -all` (ex. Google : `include:_spf.google.com`, OVH : `include:mx.ovh.com`, Cloudflare Email Routing : `include:_spf.mx.cloudflare.net`)
2. **DKIM** : signature des mails, à activer chez le fournisseur qui envoie (il te donne un TXT `selecteur._domainkey` à publier).
3. **DMARC** (TXT sur `_dmarc.ilyox.fr`) : dit aux destinataires de **rejeter** les faux.
   - Phase de test (1 à 2 semaines) : `v=DMARC1; p=none; rua=mailto:contact@ilyox.fr`
   - Ensuite : `v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:contact@ilyox.fr`
   - Domaine qui n'envoie rien : `v=DMARC1; p=reject; adkim=s; aspf=s` **et** SPF `v=spf1 -all`

Compléments recommandés : enregistrement `CAA` (`0 issue "letsencrypt.org"`), DNSSEC activé chez le registrar, 2FA sur le compte registrar/DNS/GitHub/Railway.

WebAudit vérifie maintenant ces enregistrements lui-même (règles `security/spf-record` et `security/dmarc-record`) : scanne `ilyox.fr` pour contrôler.

## Signaler une vulnérabilité

Écrire à contact@ilyox.fr (ne pas ouvrir d'issue publique).
