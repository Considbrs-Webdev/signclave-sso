---
name: signclave-release
description: >-
  Release the Signclave WordPress plugin. Use when bumping the version, tagging,
  pushing a release, publishing to wordpress.org, or changing SVN deploy,
  .wordpress-org banners and icons, or the release workflow.
---

# Signclave release

A release is a git tag with the same name as `Stable tag` in `readme.txt`. No `v` prefix (`1.0.1`, not `v1.0.1`). Pushing that tag runs `.github/workflows/release.yml`. Tests on PHP 8.2 and 8.4 must pass before `deploy` starts. A red test job does not deploy.

CI on `main` and pull requests stays in `.github/workflows/ci.yml` and does not publish.

## Version files

Update all of these to the same version, then compile translations with `wp i18n make-mo ./resources/languages ./resources/languages`:

- `signclave-sso.php` header `Version` and `SIGNCLAVE_SSO_VERSION`
- `readme.txt` `Stable tag` and a changelog section
- `package.json` and both `version` fields in `package-lock.json`
- `Project-Id-Version` in `resources/languages/signclave-sso.pot` and `signclave-sso-sv_SE.po`

Commit the version bump, then tag that commit and push the tag. Pushing `main` alone does not publish.

## WordPress.org

The deploy job builds admin assets, runs `composer install --no-dev` (Strauss writes `vendor-prefixed/`), then `10up/action-wordpress-plugin-deploy`. `.distignore` decides what enters the plugin. `/.wordpress-org` is excluded from the zip.

`.wordpress-org/` is copied to the SVN `assets/` directory. Current files: `banner-772x250.jpg`, `banner-1544x500.jpg`, `icon-256x256.jpg`. Add new directory images there using the wordpress.org filenames. Do not commit `.DS_Store`.

SVN credentials live only as GitHub Actions secrets on `Considbrs-Webdev/signclave-sso`:

- `SVN_USERNAME` = `considboras`
- `SVN_PASSWORD` = the WordPress.org SVN password

Never commit or paste those values. A tag push without the secrets can pass tests and fail deploy.

Do not change a tag that is already on wordpress.org. Ship a new version as a new tag. Do not use the local checkout in `Documents/Wordpress.org/signclave-sso` for releases.

A two-dot tag, including `1.1.0-beta.1`, matches `release.yml` and would publish to wordpress.org. A client beta is a zip only. Do not push a tag for it.

## Dependency advisory

Watch `robrichards/xmlseclibs`, `phpseclib/phpseclib`, and `paragonie/constant_time_encoding`. Dependabot opens separate pull requests for those runtime packages. Development Composer and npm updates are grouped so they do not sit ahead of them. `.github/workflows/composer-audit.yml` runs `composer audit` every Monday in addition to the audit step in CI.

When an advisory arrives:

1. Start from the Dependabot pull request. Do not merge it while CI is red.
2. Run Pest, type coverage at 100, and PHPStan.
3. Bump the plugin version with the version files above.
4. Tag that commit and push the tag. Do not rewrite a tag that is already published.

Strauss stays pinned at 0.22.2 until a trial of 0.31.1 on its own branch succeeds after 1.1.0. Do not switch the pin before that. 0.29.x breaks under `wp-content/plugins/`.
