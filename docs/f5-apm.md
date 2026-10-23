# F5 APM (IdP) configuration notes

This plugin is a SAML 2.0 **Service Provider**. A common IdP in this profile is **F5 Access Policy Manager** in front of eDirectory.

The defaults below match a typical F5 + eDirectory connector. Confirm Entity ID, SSO URL, and certificates against **your** staging metadata — those values are site-specific and are not documented here.

## SP values to paste into F5

Taken from **Settings → Signclave SSO** after the site URL is final:

| SP field | Plugin source |
| --- | --- |
| Entity ID | `saml.sp_entity_id` (default `site_url('/')`) |
| Assertion Consumer Service (ACS) | `/?signclave_sso_saml=acs` (HTTPS) |
| WantAssertionsSigned | **true** (plugin metadata advertises this; unsigned assertions are rejected) |
| NameIDFormat | unspecified (plugin metadata; see NameID below) |

Import SP metadata from the settings page (URL or XML download) rather than typing ACS/Entity ID by hand when possible.

The SSO URL configured in the plugin is the F5 **HTTP-POST** endpoint (`…/saml/idp/profile/post/`), not a Redirect URL and not a metadata file URL. The plugin POSTs AuthnRequest to that URL.

## IdP values to paste into the plugin

| Plugin field | Typical F5 source |
| --- | --- |
| IdP Entity ID | F5 SAML IdP entity ID |
| SSO URL | F5 Single Sign-On HTTP-POST URL |
| Primary X.509 | F5 IdP signing certificate (PEM) |
| Secondary X.509 | Next IdP cert during rotation (optional, recommended) |

## Assertion signing

The plugin requires a **signed Assertion**. A signed Response wrapping an unsigned Assertion is rejected (`unsigned_assertion`). Configure the F5 SAML SP connector so assertions are signed. Encrypted assertions are **not** supported in 1.0.

## Attributes

Attribute **FriendlyName / Name** in F5 must match the plugin’s configured SAML attribute names. The plugin defaults are:

| Plugin setting | F5 / eDirectory |
| --- | --- |
| Username | `uid` |
| Email | `mail` |
| First name | `givenName` |
| Last name | `sn` |
| Groups | `groups` |

Override them on the SAML settings screen (or map username/email/groups with the `signclave_sso_map_attributes` filter) if a connector uses different names. The filter cannot change which WordPress user the signed NameID binds to.

## NameID

**Unspecified** NameID is accepted and is the happy path for this IdP, provided the value is **stable** (for example a directory uid that does not change between sessions). That is an F5 operator responsibility.

**Transient** NameID is rejected (`transient_nameid`). Persistent and `emailAddress` remain accepted.

## Directory (LDAP fallback)

When LDAP is enabled, the production profile is eDirectory over `ldaps://` (port 636):

* User filter: `(&(objectClass=inetOrgPerson)(cn=%s))`
* Group attribute: `groupMembership` (DN list)
* `ldap://` without **Allow insecure LDAP** is fail-closed (no StartTLS skip)

If LDAP is up, a **new** WordPress account is created only after a directory lookup succeeds. If LDAP is down, existing WordPress users can still sign in via SAML; new users are rejected.

## IdP-initiated SSO

F5 is often used IdP-initiated. The plugin setting **Allow IdP-initiated SSO** is **off** by default (requires `InResponseTo`). Enable it only when F5 will POST unsolicited responses.

## Clock skew

If ACS fails with `assertion_not_yet_valid` / `assertion_expired`, compare F5 and web-server clocks and raise **Clock skew** (max 300 seconds) under Security.

## Staging

Check these on a staging IdP and directory. Do not paste production hostnames, bind DNs, or certificates into git.

1. SP metadata imported in F5 APM without warnings.
2. IdP Entity ID, SSO URL, and signing certificate pasted into the plugin (staging values only).
3. Login as a test user: a new WordPress user is created with the mapped role.
4. Login as an existing WordPress user: no duplicate account.
5. Email changed in the directory: same WordPress user, no new account.
6. IdP-initiated SSO works when the setting is on, and is rejected when it is off.
7. Compare F5 and web-server clocks. Raise **Clock skew** (max 300 seconds) only if ACS fails with `assertion_not_yet_valid` or `assertion_expired`.
8. Certificate rotation with primary and secondary X.509 configured, without an outage.
9. LDAP down: an existing user can sign in via SAML. A new user is rejected.
10. Emergency local login works while SSO is on.
11. `wp signclave sso disable` turns off the auto-redirect before it is needed in an incident.
12. A wrong IdP certificate rejects login, and the audit log shows the reason.
13. Behind a reverse proxy, HTTPS detection is correct with and without **Trust proxy HTTPS headers**.
