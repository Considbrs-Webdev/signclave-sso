=== Signclave – SSO for SAML and LDAP ===
Contributors: considboras
Tags: sso, saml, ldap, single sign-on, active directory
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure SAML 2.0 SP with optional LDAP, using pinned IdP certificates and prefixed xmlseclibs.

== Description ==

WordPress SAML Service Provider with optional LDAP fallback.

Source: https://github.com/Considbrs-Webdev/signclave-sso

Features:
- SAML SSO redirect on `wp-login.php`
- Signed assertion validation (XML signature + digest)
- Replay protection, signed RelayState, redirect allowlisting
- Optional LDAP authentication fallback
- Optional group-to-role mapping
- Security audit logging

== Installation ==

1. Upload `signclave-sso` to `/wp-content/plugins/`.
2. Activate the plugin.
3. Configure SAML (and optionally LDAP) under **Settings → Signclave SSO**.
4. Import SP metadata in your IdP (e.g. F5 APM).
5. Copy the **Emergency local login** URL from Security settings.

== Security ==

This plugin follows WordPress and OWASP-oriented practices:

* SAML signatures verified only against the configured IdP X.509 certificate (pinned).
* Strict SAML validation (audience, destination, issuer, InResponseTo) enabled by default.
* Emergency local login requires a secret key (`?password=1&signclave_sso_key=...`), not a public flag.
* Proxy HTTPS headers are ignored unless explicitly enabled.
* Account linking by email is off by default.
* LDAP bind passwords encrypted at rest (AES-256-GCM).
* When LDAP is enabled and fully configured, SAML must verify the directory before provisioning a **new** WordPress user. Existing WordPress accounts can still sign in via SAML if LDAP is down.
* With LDAP disabled or incomplete, SAML runs alone (JIT from IdP attributes; local accounts match by username).
* No raw SQL; admin actions require `manage_options` and nonces.
* Audit log redacts secrets; log directory denied via `.htaccess`.

== Frequently Asked Questions ==

= Where are the settings? =

**Settings → Signclave SSO** (`options-general.php?page=signclave-sso`). There is no top-level admin menu.

= How do local WordPress admins log in when SSO is enabled? =

Use the emergency URL shown under **Security** in plugin settings. It includes a secret key. Existing WordPress accounts can also sign in via SAML when the IdP `uid` matches `user_login`; after the first login identity is the stored NameID.

= Does SAML require LDAP? =

No. Leave **Enable LDAP fallback authentication** unchecked for SAML-only sites. Turn it on only when you want directory verification for new account creation and LDAP password login.

= Does this plugin contact external servers? =

Yes. Browser SSO sends the user to your **Identity Provider** (for example F5 APM). When LDAP is enabled, the WordPress server connects to your **directory** (ldaps:// recommended) for binds and searches. No traffic is sent to the plugin author or to wordpress.org for authentication.

= Behind a reverse proxy / load balancer? =

Enable **Trust proxy HTTPS headers** only if the proxy is trusted and strips client-supplied headers.

= How do I hide the plugin log directory on Nginx? =

Apache gets `.htaccess` automatically. On Nginx, deny `wp-content/uploads/signclave-sso/` in the server block. See `docs/instructions.md` in the plugin folder.

= What if wp-admin is locked out? =

From the WordPress root, with the plugin active: `wp signclave sso disable` turns off auto-redirect to the IdP. `wp signclave rotate-key` prints a new emergency login URL. Full command list is in `docs/instructions.md`.

= Where is the F5 / eDirectory profile documented? =

`docs/f5-apm.md` ships with the plugin, including the staging checks. The IdP SSO URL must be the **HTTP-POST** endpoint; the plugin does not send HTTP-Redirect AuthnRequests.

= Which filters are supported? =

These four filters are the public extension API (signatures will not change in patch releases):

* `signclave_sso_map_attributes` — `( array $mapped, array $rawAttrs )`. `$mapped` keys: `username`, `email`, `first`, `last`, `groups`, `nameId`. Runs after SAML attribute extraction, before LDAP enrich. `nameId` is informational (identity stays the signed assertion NameID).
* `signclave_sso_user_roles` — `( string[] $roles, WP_User $user, string[] $groups, string $source )`. Last word on roles after group mapping.
* `signclave_sso_allow_login` — `( true|WP_Error $allow, WP_User $user, array $context )`. Return a `WP_Error` to reject a valid SAML assertion before the auth cookie is set.
* `signclave_sso_authn_request` — `( string $xml, array $saml )`. Adjust the outbound AuthnRequest XML before it is POSTed to the IdP.

`signclave_sso_trust_proxy_headers` remains available for proxy HTTPS detection.

== Changelog ==

= 1.0.2 =
* Directory banner and icon.

= 1.0.1 =
* Source repository is github.com/Considbrs-Webdev/signclave-sso. The directory contributor is `considboras`.

= 1.0.0 =
* First release on wordpress.org.

= 0.1.21 =
* Plugin Check: print the SAML auto-submit through the script API, list `considboras` as a contributor, and delete only `signclave_sso_` transients on uninstall.

= 0.1.20 =
* Plugin Check: WordPress options, query parameters, AJAX, user meta, cron, and transients use the `signclave_sso_` prefix. Existing `sls_options` are still read until the first save.

= 0.1.19 =
* Plugin Check: global constants use the `SIGNCLAVE_SSO_` prefix.

= 0.1.18 =
* Plugin Check: ignore exception-message escaping. Those strings are logged or thrown, and the browser only sees a fixed escaped message.

= 0.1.17 =
* Rename the plugin to Signclave – SSO for SAML and LDAP. Slug and text domain are `signclave-sso`. WP-CLI is `wp signclave`.
* Existing settings in `sls_options` are read until the first save, which stores `sc_options`.
* Public filters use the `signclave_sso_` prefix.

= 0.1.16 =
* Update dependencies

= 0.1.15 =
* PHPStan: treat `node_modules` as an optional exclude so CI can run without npm install.

= 0.1.14 =
* CI: drop GitHub Actions Composer oauth before Strauss; use actions/checkout@v5 (Node 24).

= 0.1.13 =
* CI: lock Composer to PHP 8.2 so the lockfile installs on the 8.2 runner; ignore GitHub Actions tokens when running Strauss.

= 0.1.12 =
* Settings screen: show WordPress’s “Settings saved” notice once (remove the duplicate plugin notice).

= 0.1.11 =
* SAML first login may bind to an existing WordPress `user_login` (LDAP-optional 0.1.3 rule). Afterwards identity stays the stored NameID. Email still cannot choose the SAML account.
* When Automatic SSO is off, wp-login.php shows a Log in with SSO button below the form.

= 0.1.10 =
* Plugin Check: zero errors against the wordpress.org zip surface (`bin/plugin-check.sh`, `.distignore`).
* Sanitize `wp_unslash` on `REMOTE_ADDR` and trusted forwarded HTTPS headers.

= 0.1.9 =
* Tests: Pest Unit + Security, PHPStan level 8, type coverage 100 %, GitHub Actions (PHP 8.2/8.4).
* SAML: reject transient NameID; unspecified remains the happy path (F5 profile).
* Roles: do not map slugs missing from `wp_roles()`. Uninstall deletes `sc_*` transients.
* Docs: F5 checklist and default attribute/NameID profile. Captured F5 XML fixture still deferred.

= 0.1.8 =
* Settings API (`options.php`) and menu under **Settings** (not a top-level item).
* i18n: POT + Swedish `sv_SE`; `npm run translate*`.
* Public filters: `sc_map_attributes`, `sc_user_roles`, `sc_allow_login`, `sc_authn_request`.
* WP-CLI: `wp signclave sso`, `rotate-key`, `test-ldap`, `test-saml`, `doctor`.
* Daily log retention (default 90 days), Site Health tests, privacy/threat-model/F5 docs.

= 0.1.7 =
* Security: xmlseclibs (Strauss-prefixed) replaces custom XML-DSig; SHA-1 rejected; assertion must be signed.
* Security: NameID identity binding, comment-injection protection, dual IdP certs, SAMLResponse size limit.
* Security: configurable role downgrade (on by default), protected logins, last-admin guard.
* Ops: LDAP host failover, randomized log filenames, WP_Filesystem on activation, clearer bind-secret decrypt errors.
* Emergency login POST preserves bypass key; IdP-initiated SSO opt-in (off by default).

= 0.1.6 =
* Internal architecture: PSR-4 (`Signclave\`), config helpers, instance DI, Vite-built admin assets in `dist/`. Login behavior unchanged from 0.1.5.

= 0.1.5 =
* Version bump.

= 0.1.4 =
* Code structure and WordPress coding hygiene: settings view, diagnostics class, shared LDAP connection helper, i18n on admin UI. Login behavior unchanged from 0.1.3.

= 0.1.3 =
* LDAP is optional by default. SAML works without a directory; existing WordPress accounts can sign in via SAML even if LDAP is unavailable. LDAP is required only when creating new users and LDAP is fully configured.

= 0.1.2 =
* SAML login always verifies LDAP when LDAP is enabled (mandatory, not optional).

= 0.1.1 =
* Optional LDAP existence check on every SAML login.

= 0.1.0 =
* Security hardening: pinned IdP cert, strict SAML validation, secret emergency login, opt-in proxy trust.
* Account linking by email disabled by default.
* Improved uninstall cleanup.

= 0.0.2 =
* F5-compatible SAML digest verification and ACS error handling.

= 0.0.1 =
* Initial release.
