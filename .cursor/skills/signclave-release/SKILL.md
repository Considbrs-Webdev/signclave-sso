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
