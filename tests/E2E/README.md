# E2E against the local Keycloak + OpenLDAP lab

These tests are **manual / opt-in**. They are not run in GitHub Actions in this release.

## Lab

1. Start the local Keycloak + OpenLDAP lab. After a reboot, see `saml-dev/README.md` (`docker compose up -d`).
2. WordPress lab: `https://saml-ldap-sso.test/`
3. Export `SC_E2E=1` and run `vendor/bin/pest tests/E2E` from the plugin directory.

## Scenarios (checklist)

- Homepage responds.
- `/?signclave_sso_saml=metadata` returns well-formed SP `EntityDescriptor` XML.
- `/?signclave_sso_saml=login` returns an HTTP-POST AuthnRequest form (`SAMLRequest`).
- Full round-trip: `?signclave_sso_saml=login` → Keycloak → ACS → logged-in user with the mapped role (manual).
- Wrong IdP certificate configured → login rejected, reason in the audit log.
- LDAP StartTLS / `ldaps://` against the lab OpenLDAP.

A captured F5 APM `SAMLResponse` is **out of scope** until a sanitized fixture is added later.
