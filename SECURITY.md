# Security policy

This plugin handles authentication. Please report vulnerabilities **privately**. Do not open a public GitHub issue or wordpress.org support thread with exploit details.

## How to report

Report privately via **GitHub Security Advisories** on [Considbrs-Webdev/signclave-sso](https://github.com/Considbrs-Webdev/signclave-sso/security/advisories/new).

After the plugin is listed on wordpress.org, you may also report to the **plugin author** (Consid Borås / considboras) through the plugin’s wordpress.org listing. The Plugins team provides a private channel for security reports. Do not use the public support forum or a public GitHub issue for unfixed issues.

## What to include

- Plugin version (`SIGNCLAVE_SSO_VERSION` / readme Stable tag)
- WordPress and PHP versions
- Whether the report is about SAML ACS, LDAP bind, emergency login, or admin settings
- Steps to reproduce, without sending real assertions, bind passwords, or bypass keys

## Expected response

We aim to acknowledge a report within **five working days** and to ship a fix or a clear mitigation note as soon as the issue is confirmed.

## Out of scope

- Issues that require a compromised IdP certificate, a compromised LDAP directory, or a trusted reverse proxy that already forwards attacker-controlled `X-Forwarded-*` headers (see `docs/threat-model.md`)
- Denial of service against an unprotected WordPress install in general
- Social engineering of emergency login URLs (rotate the key if leaked)
