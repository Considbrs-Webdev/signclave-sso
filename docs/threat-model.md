# Threat model (one page)

Audience: a reviewer who needs to know what this plugin trusts and what it actively rejects.

## What we trust

| Trust boundary | When | Why |
| --- | --- | --- |
| Pinned IdP X.509 certificate(s) | Always | Assertions are accepted only if XML-DSig verifies against the configured primary or secondary PEM. No CA chain. |
| Directory (LDAP) | When LDAP is enabled and usable | New WordPress accounts from SAML must exist in the catalogue. Service bind uses the stored secret. |
| Reverse proxy `X-Forwarded-*` | **Only** when “Trust proxy HTTPS headers” is on | Otherwise those headers are ignored for `is_ssl()` / cookie-secure / ACS URL. |
| WordPress salts (`wp_salt('auth')`) | Always | Used to encrypt the LDAP bind password at rest. |

## What we do not trust

- Request body, query string, cookies, or headers from the browser (except a SAMLResponse that **also** verifies against the pinned cert)
- Unsigned Assertions, even inside a signed Response
- SHA-1 signatures or digests
- Client-supplied `X-Forwarded-Proto` when proxy trust is off
- Username or email as identity **after** the first SAML bind (identity is then the stored IdP **NameID**). First login may bind to an existing `user_login` so SAML works without LDAP when the WordPress account already exists.
- `signclave_sso_map_attributes` rewriting NameID (the filter may map username/email/groups; identity stays the signed NameID)
- Emergency login URL secrecy if it has appeared in access logs (rotate the key)

## Defences

- **xmlseclibs 4.0.1** (Strauss-prefixed, together with phpseclib and paragonie/constant_time_encoding) verifies Assertion signatures against a pinned key only
- **NameID** stored in user meta; comment nodes in NameID/attribute text are rejected
- **SHA-1 rejected**; RSA-SHA256+ only
- **Size cap** on `SAMLResponse` before decode (default 256 KiB)
- **Replay** of Response `@ID` via transients; **InResponseTo** required unless IdP-initiated SSO is explicitly enabled
- **Audience, destination, recipient, issuer** checked when strict validation is on (default)
- Role mapping cannot silently drop the last administrator; protected logins keep `administrator`
- LDAP `ldap://` without “Allow ldap://” fails closed in production (StartTLS required)

## Out of scope for 1.0

Encrypted assertions, Single Logout, automatic **email**-based linking of an unknown NameID to an existing local account, and shared storage of pending AuthnRequest IDs across web servers without a shared object cache. First SAML login may bind to a matching `user_login` (0.1.3 LDAP-optional rule).
