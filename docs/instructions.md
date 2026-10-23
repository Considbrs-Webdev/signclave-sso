# Signclave – Installationsguide

Svensk driftguide. Utveckling, tester och zip-bygge står i [`README.md`](../README.md).

## 1) Grundkrav
- PHP 8.2 med `ext-ldap`, `ext-openssl`, `ext-dom`.
- HTTPS aktivt.
- IdP metadata: Entity ID, SSO URL, X.509-certifikat.
- **IdP måste signera Assertion** (inte bara Response). Pluginets SP-metadata har `WantAssertionsSigned="true"`.
- Pluginet skickar AuthnRequest med **HTTP-POST**. I F5 APM ska SSO-URL vara HTTP-POST-endpointen (`…/profile/post/`), inte Redirect. Se [f5-apm.md](f5-apm.md).

## 2) SAML-konfiguration
1. Aktivera pluginen.
2. Gå till **Inställningar → Signclave SSO**.
3. Fyll i **Identity Provider** (Entity ID, SSO URL, X.509).
4. Lägg gärna ett **Secondary X.509 certificate** inför certifikatrotation (noll downtime).
5. I IdP: konfigurera ACS URL och Entity ID från pluginsidan; slå på assertion-signering.
6. **Allow IdP-initiated SSO** är av som standard. När av krävs `InResponseTo` mot en utgående AuthnRequest.
7. **Clock skew** (standard 60 s, max 300) justeras under Security vid tidsdrift mellan IdP och webbserver.

## 3) LDAP-konfiguration (valfritt)
1. Kryssa i **Enable LDAP fallback authentication** om du vill använda katalog.
2. Sätt katalogtyp (`eDirectory` eller `Active Directory`).
3. Ange host (`ldaps://...:636` rekommenderas). Flera värdar anges kommaseparerat och provas i tur och ordning tills en svarar.
4. Ange Base DN, Bind user och Bind password.
5. Ange `User filter` med `%s` som användarnamns-placeholder.
6. Om bind-lösenordet slutar fungera efter `AUTH_KEY`/`wp_salt`-rotation: spara lösenordet igen under LDAP-inställningarna.

## 4) Grupp till roll
- Lägg en rad per mapping: `source|group|role`
- Exempel: `ldap|cn=wp-admins,ou=groups,o=org|administrator`
- **Role downgrade** är på som standard: roller pluginet satt tas bort när grupperna försvinner.
- **Protected logins**: en login per rad — dessa förlorar inte `administrator` via SSO.
- Sista administratören på sajten kan inte nedgraderas via SSO (`last_admin_protected`).

## 5) Inloggningsbeteende
- Automatisk SSO (standard): `wp-login.php` omdirigeras till IdP. `lostpassword`, `rp`, `resetpass` och `register` omdirigeras inte. Lokala konton använder nöd-URL:en.
- Automatisk SSO av: WordPress-formuläret visas, plus knappen **Logga in med SSO** under formuläret om IdP är konfigurerad.
- LDAP är valfritt (av som standard). Utan katalog räcker SAML; befintliga WP-konton matchas på `user_login` mot SAML-`uid` vid första inloggningen. Därefter är `NameID` identiteten.
- Med LDAP på och fullt konfigurerat krävs katalogträff bara för att **skapa** nya konton. Befintliga WP-konton kan logga in via SAML även om katalogen är nere.
- SAML-identitet binds till IdP:ns `NameID` (`signclave_sso_nameid` i user meta) efter första inloggningen. Namn/e-post uppdaterar profil men avgör inte vem.
- Okänt NameID mot ett konto som redan har ett annat `signclave_sso_nameid` → `nameid_collision`. E-post räcker inte för SAML-bindning.
- Lokal lösenordsinloggning: nöd-URL under Security (`?password=1&signclave_sso_key=...`).
- **Nöd-URL:en är känslig** (access-loggar, Referer). Rotera nyckeln via knappen under Security efter användning/läcka.
- Bypass tillåter bara rena lokala WP-konton (inte `signclave_sso_source` saml/ldap).

## 6) Säkerhetsnoteringar
- Signaturvalidering via xmlseclibs ≥ 3.1.4 (CVE-2025-66475-patchad), prefixad för att undvika krockar.
- SHA-1 avvisas. Endast RSA-SHA256+.
- SAMLResponse max 256 KiB före parse.
- Trust proxy HTTPS headers måste vara på för att X-Forwarded-* ska påverka cookie-secure.
- Pending AuthnRequest-ID:n lagras i WordPress-transients. Bakom lastbalanserare krävs **delad objektcache**.
- Pluginen loggar aldrig lösenord, privata nycklar eller rå assertion.

## 7) Loggar (Nginx)
- Katalog: `uploads/signclave-sso/`
- Filnamn: `sc-<slump>.log` och `sc-audit-<slump>.log` (sparade i options).
- Retention: **Log retention** under Security (standard 90 dagar, 7–730). Cron `signclave_sso_prune_logs` gallrar dagligen. Se [privacy.md](privacy.md).
- Apache: `.htaccess` med `Require all denied` + `index.php`.
- Nginx (lägg i server-block):

```nginx
location ~* /wp-content/uploads/signclave-sso/ {
    deny all;
    return 403;
}
```

## 8) Kodkarta
- `signclave-sso.php` — dual Composer-autoload + `vendor-prefixed/`, `Application::boot()`.
- `vendor-prefixed/` — Strauss-prefixad xmlseclibs (`Signclave\Vendor\…`).
- `src/Saml/SignatureVerifier.php` — XML-DSig via xmlseclibs mot pinnat cert.
- `src/Saml/Handler.php` — ACS, NameID, protokollregler.
- `src/Users/UserManager.php` — NameID-bindning, rollnedgradering.
- `src/Support/Logger.php` — slumpade loggfiler och retention.
- Personuppgifter i loggar: [privacy.md](privacy.md).
- F5 APM och staging-kontroller: [f5-apm.md](f5-apm.md). Hotmodell: [threat-model.md](threat-model.md).

## 9) WP-CLI (när wp-admin är utelåst)

Körs från WordPress-roten, pluginet måste vara aktivt:

```bash
wp signclave sso disable
wp signclave sso enable
wp signclave rotate-key
wp signclave test-ldap
wp signclave test-ldap --user=jdoe --password=secret
wp signclave test-saml --file=/tmp/response.xml
wp signclave doctor
```

`sso disable` stänger av auto-redirect till IdP så nöd-URL eller lokal inloggning fungerar utan SAML-hopp. `rotate-key` skriver den nya nöd-URL:en. `doctor` kollar cert-utgång, LDAP-konfiguration, HTTPS/proxy och loggkatalog (ingen live-bind).
