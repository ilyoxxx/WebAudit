# 25 issues "good first issue" à ouvrir au lancement

Chaque ligne = une règle non encore implémentée. Utilise `scripts/seed-issues.sh`
pour les créer automatiquement via `gh cli`, ou copie-colle manuellement dans
le template `new-rule.md`.

Format : `id | catégorie | poids | doc | comportement attendu`

security/csp | security | 9 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy | fail si absent, warn si 'unsafe-inline' présent, pass sinon
security/permissions-policy | security | 4 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Permissions-Policy | fail si header absent, pass s'il restreint au moins camera/microphone/geolocation
security/referrer-policy | security | 3 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referrer-Policy | fail si absent, warn si 'unsafe-url', pass sinon
security/x-content-type-options | security | 5 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options | fail si absent ou différent de 'nosniff'
security/tls-version | security | 9 | https://developer.mozilla.org/fr/docs/Web/Security/Transport_Layer_Security | fail si ctx.tls.protocol < TLSv1.2, warn si TLSv1.2, pass si TLSv1.3
security/tls-expiry | security | 7 | https://developer.mozilla.org/fr/docs/Glossary/TLS | fail si expiré, warn si < 15 jours, pass sinon (ctx.tls.daysUntilExpiry)
security/cookie-secure-flag | security | 6 | https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies#restrict_access_to_cookies | fail si un cookie n'a pas le flag Secure sur un site HTTPS
security/cookie-httponly-flag | security | 6 | https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies#restrict_access_to_cookies | fail si un cookie sensible (session, auth) n'a pas HttpOnly
security/cookie-samesite | security | 5 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Set-Cookie/SameSite | warn si SameSite absent ou 'None' sans Secure
security/server-header-leak | security | 2 | https://owasp.org/www-project-secure-headers/ | warn si le header Server expose une version précise (ex: nginx/1.18.0)
security/mixed-content | security | 7 | https://developer.mozilla.org/fr/docs/Web/Security/Mixed_content | fail si des ressources http:// sont chargées sur une page https://
security/dnssec | security | 4 | https://www.cloudflare.com/learning/dns/dnssec/how-dnssec-works/ | warn si absence d'enregistrement DNSSEC (best effort, na si non détectable)
security/spf-record | security | 5 | https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/ | fail si aucun TXT SPF trouvé dans ctx.dns.txt et ctx.dns.mx non vide
security/dmarc-record | security | 5 | https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/ | fail si aucun enregistrement _dmarc trouvé
rgpd/consent-before-tracking | rgpd | 8 | https://www.cnil.fr/fr/cookies-et-autres-traceurs | warn si un pixel de tracking connu (fbq, gtag) est présent dans le HTML sans CMP détecté
rgpd/privacy-policy-link | rgpd | 6 | https://www.cnil.fr/fr/reglement-europeen-protection-donnees | fail si aucun lien contenant 'politique de confidentialité' / 'privacy policy' détecté
rgpd/https-forced | rgpd | 8 | https://www.cnil.fr/fr/la-securite-des-donnees-personnelles | fail si le site répond en clair sur http:// sans redirection vers https://
rgpd/dpo-contact | rgpd | 3 | https://www.cnil.fr/fr/le-delegue-la-protection-des-donnees-dpo | warn si aucune mention 'DPO' ou 'délégué à la protection des données' trouvée sur la page mentions légales
rgpd/data-retention-mention | rgpd | 3 | https://www.cnil.fr/fr/les-durees-de-conservation-des-donnees | warn si aucune mention de durée de conservation détectée dans la politique de confidentialité
rgpd/external-fonts-tracking | rgpd | 4 | https://www.cnil.fr/fr/cookies-et-autres-traceurs | warn si des polices Google Fonts sont chargées directement depuis fonts.googleapis.com (transfert de données hors UE)
perf/cache-control | perf | 4 | https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cache-Control | fail si absent sur les ressources statiques, warn si max-age très court
perf/response-time | perf | 3 | https://web.dev/articles/ttfb | warn si ctx.http.timingMs > 1000ms, fail si > 3000ms
perf/html-size | perf | 2 | https://web.dev/articles/reduce-network-payloads-using-text-compression | warn si le HTML brut dépasse 500KB avant compression
seo/meta-description | seo | 3 | https://developer.mozilla.org/fr/docs/Web/HTML/Element/meta/name/description | fail si absente, warn si < 50 ou > 160 caractères
seo/robots-txt-present | seo | 2 | https://developers.google.com/search/docs/crawling-indexing/robots/intro | warn si robots.txt absent (ctx.robotsTxt null)
