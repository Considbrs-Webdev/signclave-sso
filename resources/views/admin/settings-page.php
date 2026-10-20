<?php
/**
 * Plugin settings screen markup.
 *
 * Variables set by SettingsPage::renderPage().
 *
 * @package Signclave
 * @since   0.1.4
 *
 * @var array  $options
 * @var array  $roles
 * @var string $bind_user_value
 * @var string $metadata_xml
 * @var string $metadata_url
 * @var string $metadata_download
 * @var array  $recent_acs_failures
 * @var string $mappings_text
 * @var string $bypass_url
 * @var string $acs_url
 * @var string $secondary_cert
 * @var bool   $allow_idp_initiated
 * @var int    $clock_skew_seconds
 * @var bool   $role_downgrade
 * @var string $protected_logins
 * @var string $role_priority
 * @var int    $log_retention_days
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template locals from View::render().

$code_ok = array( 'code' => array() );
?>
<div class="wrap sc-wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
	<?php settings_errors( 'signclave_sso_settings' ); ?>
	<?php if ( ! empty( $recent_acs_failures ) ) : ?>
		<div class="notice notice-warning">
			<p><strong><?php esc_html_e( 'Recent SAML login rejections (ACS)', 'signclave-sso' ); ?></strong></p>
			<p class="description"><?php esc_html_e( 'The SSO diagnostic test only validates the outbound AuthnRequest. These lines show why inbound SAML responses were rejected.', 'signclave-sso' ); ?></p>
			<pre class="sc-log sc-log--compact"><?php echo esc_html( implode( "\n", $recent_acs_failures ) ); ?></pre>
		</div>
	<?php endif; ?>
	<form method="post" action="options.php">
		<?php settings_fields( 'signclave_sso' ); ?>
		<div class="sc-section">
			<h2><?php esc_html_e( 'General', 'signclave-sso' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Automatic SSO', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][auto_sso]" value="1" <?php checked( ! empty( $options['general']['auto_sso'] ) ); ?>>
							<?php echo wp_kses( __( 'Redirect visits to <code>wp-login.php</code> to SAML', 'signclave-sso' ), $code_ok ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'When on, visits go to the IdP. Local password login uses the emergency URL under Security. When off, the form stays visible and a Log in with SSO button is shown below the form.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Default role', 'signclave-sso' ); ?></th>
					<td>
						<select name="signclave_sso_options[general][default_role]">
							<?php foreach ( $roles as $role_key => $role_data ) : ?>
								<option value="<?php echo esc_attr( $role_key ); ?>" <?php selected( $options['general']['default_role'], $role_key ); ?>><?php echo esc_html( $role_data['name'] ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'No group match', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][deny_if_no_group_match]" value="1" <?php checked( ! empty( $options['general']['deny_if_no_group_match'] ) ); ?>>
							<?php esc_html_e( 'Deny login when mappings exist and no group matches', 'signclave-sso' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Role downgrade', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][role_downgrade]" value="1" <?php checked( $role_downgrade ); ?>>
							<?php esc_html_e( 'Remove mapped roles when the user no longer matches the group', 'signclave-sso' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Only roles granted by this plugin are removed. The last remaining administrator is never downgraded.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Protected logins', 'signclave-sso' ); ?></th>
					<td>
						<textarea name="signclave_sso_options[general][protected_logins]" rows="4" class="large-text code"><?php echo esc_textarea( $protected_logins ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One WordPress username per line. These accounts never lose the administrator role through group mapping.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Role priority', 'signclave-sso' ); ?></th>
					<td>
						<input type="text" class="large-text code" name="signclave_sso_options[general][role_priority]" value="<?php echo esc_attr( $role_priority ); ?>">
						<p class="description"><?php esc_html_e( 'Comma-separated role slugs, most privileged first. Used by the “highest role” strategy. Roles not listed rank below these.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<div class="sc-section">
			<h2><?php esc_html_e( 'Security', 'signclave-sso' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Strict SAML validation', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][saml_strict_validation]" value="1" <?php checked( ! empty( $options['general']['saml_strict_validation'] ) ); ?>>
							<?php esc_html_e( 'Require IdP entity ID, audience, destination, recipient, and matching AuthnRequest ID', 'signclave-sso' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Recommended. Disabling weakens assertion binding (not recommended in production).', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'IdP-initiated SSO', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][allow_idp_initiated]" value="1" <?php checked( $allow_idp_initiated ); ?>>
							<?php echo wp_kses( __( 'Accept unsolicited responses without <code>InResponseTo</code>', 'signclave-sso' ), $code_ok ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Off by default. Enabling this drops the binding to an AuthnRequest we sent, so replay protection relies on the Recipient and response ID only. Enable only if the IdP starts the login.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Clock skew tolerance', 'signclave-sso' ); ?></th>
					<td>
						<input type="number" class="small-text" name="signclave_sso_options[general][saml_clock_skew_seconds]" min="0" max="300" step="1" value="<?php echo esc_attr( (string) $clock_skew_seconds ); ?>">
						<?php esc_html_e( 'seconds', 'signclave-sso' ); ?>
						<p class="description"><?php esc_html_e( 'Allowed time drift between the IdP and this server when validating assertion validity windows. Default 60, maximum 300.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Trust proxy HTTPS headers', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][trust_proxy_headers]" value="1" <?php checked( ! empty( $options['general']['trust_proxy_headers'] ) ); ?>>
							<?php echo wp_kses( __( 'Honor <code>X-Forwarded-Proto</code> / <code>X-Forwarded-SSL</code>', 'signclave-sso' ), $code_ok ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Enable only behind a trusted reverse proxy that terminates TLS.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Link accounts by email', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[general][allow_email_account_linking]" value="1" <?php checked( ! empty( $options['general']['allow_email_account_linking'] ) ); ?>>
							<?php esc_html_e( 'Allow LDAP password login to match existing WordPress users by email', 'signclave-sso' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'Off by default (OWASP). Applies to the LDAP password path only. SAML may bind to an existing user_login on first login; afterwards identity is the stored IdP NameID, never email.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Emergency local login', 'signclave-sso' ); ?></th>
					<td>
						<?php if ( '' !== $bypass_url ) : ?>
							<p><code><?php echo esc_html( $bypass_url ); ?></code></p>
							<p class="description"><?php esc_html_e( 'Secret URL for local WordPress accounts only. SAML/LDAP users cannot use it. Store securely.', 'signclave-sso' ); ?></p>
						<?php else : ?>
							<p class="description"><?php esc_html_e( 'No bypass key configured. Save settings or regenerate a key below.', 'signclave-sso' ); ?></p>
						<?php endif; ?>
						<button type="submit" class="button button-primary" name="signclave_sso_regenerate_bypass_key" value="1"><?php esc_html_e( 'Regenerate emergency login key', 'signclave-sso' ); ?></button>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Log retention', 'signclave-sso' ); ?></th>
					<td>
						<input type="number" class="small-text" name="signclave_sso_options[general][log_retention_days]" min="7" max="730" step="1" value="<?php echo esc_attr( (string) $log_retention_days ); ?>">
						<?php esc_html_e( 'days', 'signclave-sso' ); ?>
						<p class="description"><?php esc_html_e( 'Audit and diagnostic log lines older than this are deleted daily. Allowed range: 7–730 days (default 90).', 'signclave-sso' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<div class="sc-section">
			<h2><?php esc_html_e( 'SAML', 'signclave-sso' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'SP Entity ID', 'signclave-sso' ); ?></th>
					<td><input type="url" class="regular-text" name="signclave_sso_options[saml][sp_entity_id]" value="<?php echo esc_attr( $options['saml']['sp_entity_id'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'ACS URL', 'signclave-sso' ); ?></th>
					<td><code><?php echo esc_html( $acs_url ); ?></code></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Metadata URL', 'signclave-sso' ); ?></th>
					<td><code><?php echo esc_html( $metadata_url ); ?></code></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'SP metadata', 'signclave-sso' ); ?></th>
					<td>
						<p class="description"><?php echo wp_kses( __( 'Import this file in F5 under <strong>SAML Identity Provider → SAML SP Connectors → From Metadata</strong>. Set signing certificate to <strong>None</strong>.', 'signclave-sso' ), array( 'strong' => array() ) ); ?></p>
						<p class="sc-metadata-actions">
							<a class="button button-secondary" href="<?php echo esc_url( $metadata_download ); ?>"><?php esc_html_e( 'Download metadata XML', 'signclave-sso' ); ?></a>
							<button type="button" class="button button-primary" id="sc-copy-metadata"><?php esc_html_e( 'Copy metadata', 'signclave-sso' ); ?></button>
						</p>
						<textarea id="sc-metadata-preview" rows="12" class="large-text code sc-log sc-log--metadata" readonly><?php echo esc_textarea( $metadata_xml ); ?></textarea>
					</td>
				</tr>
			</table>
			<h3><?php esc_html_e( 'Identity Provider', 'signclave-sso' ); ?></h3>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Entity ID', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_entity_id]" value="<?php echo esc_attr( $options['saml']['primary_entity_id'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'SSO URL', 'signclave-sso' ); ?></th>
					<td>
						<input type="url" class="regular-text" name="signclave_sso_options[saml][primary_sso_url]" value="<?php echo esc_attr( $options['saml']['primary_sso_url'] ); ?>">
						<p class="description"><?php echo wp_kses( __( 'Use <code>SingleSignOnService</code> from IdP metadata, not the <code>.xml</code> metadata file URL.', 'signclave-sso' ), $code_ok ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Group attribute', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_group_attr]" value="<?php echo esc_attr( $options['saml']['primary_group_attr'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Username attribute', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_username_attr]" value="<?php echo esc_attr( $options['saml']['primary_username_attr'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Email attribute', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_email_attr]" value="<?php echo esc_attr( $options['saml']['primary_email_attr'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'First name attribute', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_first_name_attr]" value="<?php echo esc_attr( $options['saml']['primary_first_name_attr'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Last name attribute', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[saml][primary_last_name_attr]" value="<?php echo esc_attr( $options['saml']['primary_last_name_attr'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'X509 certificate (PEM)', 'signclave-sso' ); ?></th>
					<td><textarea name="signclave_sso_options[saml][primary_x509_cert]" rows="7" class="large-text code"><?php echo esc_textarea( $options['saml']['primary_x509_cert'] ); ?></textarea></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Secondary X509 certificate (PEM)', 'signclave-sso' ); ?></th>
					<td>
						<textarea name="signclave_sso_options[saml][secondary_x509_cert]" rows="7" class="large-text code"><?php echo esc_textarea( $secondary_cert ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Optional. Assertions signed with either certificate are accepted, so the IdP certificate can be rotated without downtime. Add the new certificate here, wait for the IdP to switch, then move it to the field above and clear this one.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
			</table>
		</div>

		<div class="sc-section">
			<h2><?php esc_html_e( 'LDAP', 'signclave-sso' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'LDAP fallback', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[ldap][enabled]" value="1" <?php checked( ! empty( $options['ldap']['enabled'] ) ); ?>>
							<?php esc_html_e( 'Enable LDAP fallback authentication', 'signclave-sso' ); ?>
						</label>
						<p class="description"><?php echo wp_kses( __( 'When enabled and fully configured, LDAP is used for password login and to verify users before WordPress creates a <strong>new</strong> account from SAML. Existing WordPress accounts can still sign in via SAML if the directory is unavailable. When disabled (or incomplete), SAML runs alone and can create users from IdP attributes.', 'signclave-sso' ), array( 'strong' => array() ) ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Directory type', 'signclave-sso' ); ?></th>
					<td>
						<select name="signclave_sso_options[ldap][directory_type]">
							<option value="edir" <?php selected( $options['ldap']['directory_type'], 'edir' ); ?>><?php esc_html_e( 'eDirectory', 'signclave-sso' ); ?></option>
							<option value="ad" <?php selected( $options['ldap']['directory_type'], 'ad' ); ?>><?php esc_html_e( 'Active Directory', 'signclave-sso' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Hosts', 'signclave-sso' ); ?></th>
					<td>
						<input type="text" class="large-text" name="signclave_sso_options[ldap][hosts]" value="<?php echo esc_attr( $options['ldap']['hosts'] ); ?>">
						<p class="description"><?php echo wp_kses( __( 'Comma-separated. Use <code>ldaps://host:636</code> in production.', 'signclave-sso' ), $code_ok ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Base DN', 'signclave-sso' ); ?></th>
					<td><input type="text" class="large-text" name="signclave_sso_options[ldap][base_dn]" value="<?php echo esc_attr( $options['ldap']['base_dn'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Bind user / Bind DN', 'signclave-sso' ); ?></th>
					<td>
						<input type="text" class="large-text" name="signclave_sso_options[ldap][bind_user]" value="<?php echo esc_attr( $bind_user_value ); ?>">
						<p class="description"><?php esc_html_e( 'The service account used for LDAP reads. Can be DN, UPN, or account name depending on your directory.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Bind password', 'signclave-sso' ); ?></th>
					<td>
						<input type="password" class="regular-text" name="signclave_sso_bind_password" value="">
						<p class="description"><?php esc_html_e( 'Leave empty to keep existing secret.', 'signclave-sso' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Security override', 'signclave-sso' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="signclave_sso_options[ldap][allow_insecure_ldap]" value="1" <?php checked( ! empty( $options['ldap']['allow_insecure_ldap'] ) ); ?>>
							<?php echo wp_kses( __( 'Allow <code>ldap://</code> (not recommended)', 'signclave-sso' ), $code_ok ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'User filter', 'signclave-sso' ); ?></th>
					<td>
						<input type="text" class="large-text code" id="sc-user-filter" name="signclave_sso_options[ldap][user_filter]" value="<?php echo esc_attr( (string) ( $options['ldap']['user_filter'] ?? '' ) ); ?>">
						<p class="description" id="sc-user-filter-help">
							<?php
							echo wp_kses(
								sprintf(
									/* translators: 1: %s code token, 2: typical eDirectory filter, 3: typical Active Directory filter */
									__( 'Use %1$s as username placeholder. Typical eDirectory: %2$s Typical AD: %3$s', 'signclave-sso' ),
									'<code>%s</code>',
									'<code>(&amp;(objectClass=inetOrgPerson)(cn=%s))</code>',
									'<code>(&amp;(objectClass=user)(sAMAccountName=%s))</code>'
								),
								$code_ok
							);
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Group attribute (eDirectory)', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[ldap][group_attr_edir]" value="<?php echo esc_attr( $options['ldap']['group_attr_edir'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Group attribute (AD)', 'signclave-sso' ); ?></th>
					<td><input type="text" class="regular-text" name="signclave_sso_options[ldap][group_attr_ad]" value="<?php echo esc_attr( $options['ldap']['group_attr_ad'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Connection test', 'signclave-sso' ); ?></th>
					<td>
						<button type="button" class="button button-primary" id="sc-test-ldap-quick"><?php esc_html_e( 'Test LDAP', 'signclave-sso' ); ?></button>
						<p class="description"><?php esc_html_e( 'Quick service bind validation for current LDAP settings.', 'signclave-sso' ); ?></p>
						<textarea id="sc-ldap-quick-log" rows="7" class="large-text code sc-log sc-log--compact" readonly></textarea>
					</td>
				</tr>
			</table>
		</div>

		<div class="sc-section">
			<h2><?php esc_html_e( 'Group to role mappings', 'signclave-sso' ); ?></h2>
			<p class="description"><?php echo wp_kses( __( 'One row per mapping in format: <code>source|group|role</code>. Example: <code>ldap|cn=wp-admins,ou=groups,o=org|administrator</code>', 'signclave-sso' ), $code_ok ); ?></p>
			<textarea name="signclave_sso_role_mappings" rows="8" class="large-text code"><?php echo esc_textarea( $mappings_text ); ?></textarea>
		</div>

		<p class="submit">
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Save settings', 'signclave-sso' ); ?></button>
		</p>
	</form>

	<div class="sc-section">
		<h2><?php esc_html_e( 'Diagnostics', 'signclave-sso' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Use this for technical validation. Password is never written to logs.', 'signclave-sso' ); ?></p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Test username', 'signclave-sso' ); ?></th>
				<td><input type="text" class="regular-text" id="sc_test_username" autocomplete="off"></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Test password', 'signclave-sso' ); ?></th>
				<td><input type="password" class="regular-text" id="sc_test_password" autocomplete="new-password"></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Run tests', 'signclave-sso' ); ?></th>
				<td>
					<button type="button" class="button button-primary" id="sc-test-ldap-auth"><?php esc_html_e( 'Test LDAP auth', 'signclave-sso' ); ?></button>
					<button type="button" class="button button-primary" id="sc-test-sso"><?php esc_html_e( 'Test SSO flow', 'signclave-sso' ); ?></button>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Technical log', 'signclave-sso' ); ?></th>
				<td>
					<textarea id="sc-tech-log" rows="14" class="large-text code sc-log sc-log--tech" readonly></textarea>
				</td>
			</tr>
		</table>
	</div>
</div>
