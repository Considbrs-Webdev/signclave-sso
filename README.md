# Signclave – SSO for SAML and LDAP

A WordPress plugin that acts as a SAML 2.0 Service Provider with optional LDAP fallback. It redirects `wp-login.php` to your Identity Provider (for example F5 APM), validates signed assertions, binds accounts to NameID, and can map directory groups to WordPress roles.

Author: [Consid Borås](https://profiles.wordpress.org/considboras/). Source: [github.com/Considbrs-Webdev/saml-ldap-sso](https://github.com/Considbrs-Webdev/saml-ldap-sso).

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Development](#development)
  - [Asset Building](#asset-building)
  - [Creating Distribution Package](#creating-distribution-package)
  - [Asset Loading](#asset-loading)
  - [Translations](#translations)
  - [Tests](#tests)
- [Architecture Overview](#architecture-overview)
- [Core Concepts](#core-concepts)
  - [Application & Service Providers](#application--service-providers)
- [Extending the Plugin](#extending-the-plugin)
- [WP-CLI](#wp-cli)
- [File Structure](#file-structure)
- [Configuration](#configuration)
- [Further Documentation](#further-documentation)

## Requirements

- PHP 8.2 or higher with `ext-ldap`, `ext-openssl`, and `ext-dom`
- WordPress 6.0 or higher
- HTTPS
- Composer
- Node.js & npm (for development)
- An Identity Provider that **signs Assertions** (not only the Response)

## Installation

1. Clone or download the plugin to your WordPress plugins directory (`wp-content/plugins/signclave-sso`)
2. Install PHP dependencies:
   ```bash
   composer install --no-dev
   ```
   `vendor/` and `vendor-prefixed/` are generated locally and are **not** in git. xmlseclibs is a runtime `require`; every install downloads `bin/strauss.phar` (gitignored, pinned 0.22.2) and copies xmlseclibs to `vendor-prefixed/`, deleting `vendor/robrichards`. Do not run `strauss include-autoloader`. Bump with `composer update robrichards/xmlseclibs`. Keep the phar pinned — 0.29.x fails under `wp-content/plugins/`.
3. Install Node dependencies (for development):
   ```bash
   npm install
   ```
4. Build assets:
   ```bash
   npm run build
   ```
5. Activate the plugin through the WordPress admin panel
6. Configure SAML (and optionally LDAP) under **Settings → Signclave SSO**
7. Import SP metadata in your IdP and copy the **Emergency local login** URL from Security settings

For a Swedish operations guide (Nginx logs, F5, emergency login), see [`docs/instructions.md`](docs/instructions.md).

## Development

### Asset Building

The plugin uses Vite for asset bundling. Assets are located in `resources/assets/` and are compiled to the `dist/` directory. Built files in `dist/` are checked in.

#### Available Scripts

**Development Mode**
```bash
npm run dev
```
Starts Vite in development mode with hot module replacement. This watches for changes and automatically rebuilds assets.

**Production Build**
```bash
npm run build
```
Builds optimized production assets with minification and hashing. The build includes:
- Admin JavaScript (`resources/assets/js/admin.js` → `dist/js/admin.[hash].js`)
- Admin SCSS (`resources/assets/scss/admin.scss` → `dist/css/admin.[hash].css`)

**Creating Distribution Package**

GitHub is source only. wordpress.org gets a zip you upload via SVN — not a GitHub release. From the plugin directory:

```bash
npm run build
composer install --no-dev
wp dist-archive . ./releases/signclave-sso.zip --create-target-dir --format=zip
```

`composer install --no-dev` must run **before** the zip. It installs runtime PHP deps, downloads `bin/strauss.phar` if needed, writes `vendor-prefixed/`, and deletes unprefixed `vendor/robrichards`. Those directories are gitignored; `.distignore` still ships them in the zip (except leftover `vendor/robrichards` and Strauss aliases). `bin/` stays out of the zip.

Then upload the zip contents through wordpress.org SVN. Restore full Composer deps afterwards with `composer install` if you continue developing.

**wordpress.org (first submission, 0.1.11)**

No banner, icon, or screenshots in this round (skip SVN `assets/`).

1. Log in as **considboras**. Add **considadam** as a plugin contributor.
2. Submit the zip at [Add your plugin](https://wordpress.org/plugins/developers/add/) with slug `signclave-sso`.
3. After approval, commit the unzipped plugin to `https://plugins.svn.wordpress.org/signclave-sso/` (`trunk/` plus tag `0.1.11`). Do not create GitHub Releases for the wordpress.org zip.
4. Review typically takes two to four weeks and at least one round of feedback.

### Asset Loading

Admin assets are enqueued using the `ViteManifest` utility class, which reads the generated manifest file to get the correct hashed filenames.

### Translations

The plugin uses WordPress i18n. The text domain is `signclave-sso`. Translation files are located in `resources/languages/` (`signclave-sso.pot`, `signclave-sso-sv_SE.po` / `.mo`).

#### Translation Scripts

**Generate/Update POT Template**
```bash
npm run translate:pot
```
Scans `src/` and `resources/` for translatable strings and writes `resources/languages/signclave-sso.pot`.

**Update PO Files**
```bash
npm run translate:update
```
Updates existing `.po` files from the `.pot` template.

**Complete Translation Workflow**
```bash
npm run translate
```
Runs POT generation and PO updates.

**Compile Translations**
```bash
npm run translate:compile
```
Compiles `.po` files to `.mo` (same as `npm run translate:mo`).

#### Translation Workflow Example

1. Add translatable strings in PHP:
   ```php
   __('My translatable text', 'signclave-sso')
   ```
2. Generate/update the POT file:
   ```bash
   npm run translate:pot
   ```
3. Update existing translations:
   ```bash
   npm run translate:update
   ```
4. Edit `.po` files
5. Compile:
   ```bash
   npm run translate:compile
   ```

### Tests

From the plugin directory, after `composer install` (dev dependencies):

```bash
composer test                 # Unit + Security
composer test:unit
composer test:security
composer phpstan              # level 8, src/
composer test:type-coverage   # 100% typed parameters/returns
composer rector               # PHP 8.2 dry-run against src/
composer infection            # mutation testing (needs pcov or Xdebug)
```

SAML fixtures: `php tests/fixtures/saml/build.php` (requires `tests/fixtures/saml/idp.key`).

Integration (own test database, never the lab site DB):

```bash
bin/install-wp-tests.sh sc_tests root '' 127.0.0.1
export SC_WP_TESTS_DIR="$PWD/tests/.wordpress/wordpress-tests-lib"
composer test:integration
```

Plugin Check against the same surface as the distribution zip:

```bash
bin/plugin-check.sh
```

E2E against Keycloak/OpenLDAP is manual (`SC_E2E=1`). See `tests/E2E/README.md`.

## Architecture Overview

Signclave uses a small, instance-based service container and four providers. There is no Illuminate/Laravel container and no static service locator.

### Key Components

- **Application**: Bootstrap class that registers and boots service providers
- **Container**: Instance DI; services are bound as factories and resolved by class name
- **SAML**: AuthnRequest, ACS, metadata, XML-DSig via Strauss-prefixed xmlseclibs
- **LDAP**: Optional fallback bind/search through `ClientInterface` (native `ldap_*` only in `NativeClient`)
- **Users**: NameID binding, role mapping, last-admin and protected-login guards
- **Auth**: Emergency local password bypass with rate limiting

## Core Concepts

### Application & Service Providers

The plugin boots from `signclave-sso.php`:

```php
Application::configure()
    ->withProviders([
        PluginServiceProvider::class,
        SamlServiceProvider::class,
        LdapServiceProvider::class,
        AdminServiceProvider::class,
    ])
    ->boot();
```

Service providers have two lifecycle methods:
- `register()`: Bind services on the container
- `boot()`: Hook into WordPress after all providers have registered

| Provider | Responsibility |
| --- | --- |
| `PluginServiceProvider` | Textdomain, upgrade, logger, rate limiter, users, password bypass, WP-CLI |
| `SamlServiceProvider` | Metadata, ACS/login routes, signature verifier |
| `LdapServiceProvider` | Connection, lookup, authenticator |
| `AdminServiceProvider` | Settings page, diagnostics, Site Health, admin assets |

## Extending the Plugin

These four filters are the public extension API (signatures will not change in patch releases):

```php
add_filter('signclave_sso_map_attributes', function (array $mapped, array $rawAttrs): array {
    // Keys: username, email, first, last, groups, nameId
    // nameId is informational; identity stays the signed assertion NameID.
    return $mapped;
}, 10, 2);

add_filter('signclave_sso_user_roles', function (array $roles, WP_User $user, array $groups, string $source): array {
    return $roles;
}, 10, 4);

add_filter('signclave_sso_allow_login', function ($allow, WP_User $user, array $context) {
    // Return a WP_Error to reject a valid assertion before the auth cookie is set.
    return $allow;
}, 10, 3);

add_filter('signclave_sso_authn_request', function (string $xml, array $saml): string {
    return $xml;
}, 10, 2);
```

`signclave_sso_trust_proxy_headers` remains available for proxy HTTPS detection. The public filter prefix is `signclave_sso_`.

## WP-CLI

Run from the WordPress root with the plugin active:

```bash
wp signclave sso disable
wp signclave sso enable
wp signclave rotate-key
wp signclave test-ldap
wp signclave test-ldap --user=jdoe --password=secret
wp signclave test-saml --file=/tmp/response.xml
wp signclave doctor
```

`sso disable` turns off auto-redirect to the IdP so emergency or local login works without a SAML hop. `rotate-key` prints the new emergency URL. `doctor` checks certificate expiry, LDAP configuration, HTTPS/proxy, and the log directory (no live bind).

## File Structure

```
signclave-sso/
├── signclave-sso.php          # Bootstrap, autoload, Application::boot()
├── helpers.php                # config() helper
├── uninstall.php
├── composer.json
├── .distignore                # Files omitted from wp dist-archive
├── src/
│   ├── Application.php
│   ├── Container.php
│   ├── Plugin.php
│   ├── Activator.php
│   ├── Providers/             # Plugin, Saml, Ldap, Admin
│   ├── Saml/                  # Handler, SignatureVerifier, Metadata
│   ├── Ldap/                  # NativeClient, Connection, UserLookup, Authenticator
│   ├── Users/                 # UserManager, RoleMapper
│   ├── Auth/                  # PasswordBypass, AuthFailureReason
│   ├── Admin/                 # Settings, diagnostics, Site Health
│   ├── Settings/              # Options sanitizer
│   ├── Support/               # Logger, Clock, RateLimiter, View
│   ├── Assets/                # ViteManifest, admin enqueue
│   └── Cli/                   # wp signclave …
├── resources/
│   ├── assets/                # Vite sources (js, scss)
│   ├── views/admin/           # Settings page markup
│   └── languages/             # POT / sv_SE
├── dist/                      # Built admin assets (checked in)
├── vendor/                    # Composer runtime (gitignored; generated)
├── vendor-prefixed/           # Strauss-prefixed xmlseclibs (gitignored; generated)
├── tests/                     # Pest Unit, Security, Integration, fixtures
├── docs/                      # Instructions, F5, threat model, privacy, roadmap (shipped in the zip)
└── bin/                       # Strauss phar (gitignored), tests, plugin-check
```

## Configuration

Settings live under **Settings → Signclave SSO** (`options-general.php?page=signclave-sso`).

- **SAML:** IdP Entity ID, SSO URL (the plugin sends an HTTP-POST AuthnRequest), primary/secondary X.509, attribute names (`uid`, `mail`, `givenName`, `sn`, `groups` by default). Assertions must be signed. Transient NameID is rejected; unspecified/email/persistent are accepted when the value is stable.
- **LDAP (optional):** Off by default. When enabled and fully configured, a **new** WordPress user is created only after a directory lookup. Existing accounts can still sign in via SAML if LDAP is down. Prefer `ldaps://` on port 636.
- **Roles:** One mapping per line: `source|group|role`. Role downgrade is on by default. Protected logins and last-admin cannot lose `administrator` via SSO.
- **Emergency login:** `?password=1&signclave_sso_key=…` under Security. Rotate the key after use. Only local WordPress accounts (not `signclave_sso_source` saml/ldap) may use it.

## Further Documentation

| File | Contents |
| --- | --- |
| [`docs/instructions.md`](docs/instructions.md) | Swedish install, logs, WP-CLI, F5 |
| [`docs/f5-apm.md`](docs/f5-apm.md) | F5 APM / eDirectory profile and staging checks |
| [`docs/threat-model.md`](docs/threat-model.md) | Threat model |
| [`docs/privacy.md`](docs/privacy.md) | Logging and personal data |
| `readme.txt` | wordpress.org metadata and changelog |

## Contributing

When contributing, please:
1. Keep PHP 8.2+, `declare(strict_types=1)`, and PSR-12 in `src/`
2. Add or update Pest tests for changes in `src/Saml/` or `src/Ldap/`
3. Do not lower PHPStan level 8 or type coverage
4. Run `composer test` and `composer phpstan` before merging
5. Document login-behaviour changes in `readme.txt`
6. Add translations for new strings (`npm run translate`)

## License

GPL v2 or later — see `LICENSE`.
