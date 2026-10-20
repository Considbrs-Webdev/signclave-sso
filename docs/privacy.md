# Privacy and audit logs

This plugin writes operational and security logs so administrators can diagnose failed SSO and directory binds. The WordPress site owner (data controller) should list this processing in its record of processing activities.

## What is logged

Log and audit lines may include:

- WordPress usernames and user IDs
- Client IP addresses
- SAML ACS rejection reasons (`reason` codes such as `issuer_mismatch`)
- IdP issuer / entity ID, ACS destination URLs, and similar protocol fields
- LDAP host names and technical error strings from the directory client
- Admin login names when settings or the emergency key are changed

## What is never logged

- Passwords (local, LDAP user bind, or LDAP service bind)
- Full SAML assertions / `SAMLResponse` payloads
- Emergency bypass keys, bind secrets, or private keys
- Session cookies

Context keys whose names contain `password`, `bind_password`, `saml_response`, `assertion`, `private_key`, `token`, or `secret` are redacted before write.

## Where files live

Under `wp-content/uploads/signclave-sso/`:

- `sc-<random>.log` — diagnostic log
- `sc-audit-<random>.log` — security audit log

Filenames are stored in `signclave_sso_options` and are not guessable. Apache installs also get `.htaccess` (`Require all denied`) and `index.php`. Nginx must deny the directory separately (see [instructions.md](instructions.md)).

## Retention

`general.log_retention_days` (default **90**, allowed 7–730) controls how long lines are kept. A daily cron event `signclave_sso_prune_logs` drops older lines (ISO-8601 timestamp prefix). Uninstall deletes the option and the log directory.

## Legal note

Logging of usernames and IP addresses is personal data under GDPR. Keep retention as short as operationally needed and document the purpose (security monitoring and incident response for WordPress SSO).
