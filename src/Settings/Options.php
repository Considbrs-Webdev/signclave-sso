<?php

declare(strict_types=1);

namespace Signclave\Settings;

if (! defined('ABSPATH')) {
    exit;
}

use Signclave\Saml\SignatureVerifier;

use function Signclave\config;

/**
 * Plugin options stored in signclave_sso_options. All writes go through sanitize().
 *
 * Reads legacy sls_options until the first write, which stores signclave_sso_options and
 * deletes the old key.
 */
final class Options
{
    public const LEGACY_OPTION_KEY = 'sls_options';
    /**
     * Return the WordPress option key used to store plugin settings.
     */
    public function optionKey(): string
    {
        return (string) config('app.option_key', 'signclave_sso_options');
    }

    /**
     * @return array<string, mixed>
     */
    public function defaults(): array
    {
        return [
            'general' => [
                'auto_sso' => true,
                'default_role' => 'subscriber',
                'deny_if_no_group_match' => false,
                'role_strategy' => 'highest',
                'bypass_limit' => 10,
                'bypass_window_seconds' => 900,
                'bypass_lockout_seconds' => 1800,
                'saml_clock_skew_seconds' => 60,
                'saml_request_ttl_seconds' => 300,
                'saml_relay_ttl_seconds' => 600,
                'saml_strict_validation' => true,
                'trust_proxy_headers' => false,
                'allow_email_account_linking' => false,
                'password_bypass_key' => '',
                'allow_idp_initiated' => false,
                'role_downgrade' => true,
                'protected_logins' => '',
                'role_priority' => 'administrator,editor,author,contributor,subscriber',
                'log_file' => '',
                'audit_log_file' => '',
                'saml_response_max_bytes' => 262144,
                'log_retention_days' => 90,
            ],
            'saml' => [
                'sp_entity_id' => site_url('/'),
                'primary_entity_id' => '',
                'primary_sso_url' => '',
                'primary_x509_cert' => '',
                'secondary_x509_cert' => '',
                'primary_group_attr' => 'groups',
                'primary_username_attr' => 'uid',
                'primary_email_attr' => 'mail',
                'primary_first_name_attr' => 'givenName',
                'primary_last_name_attr' => 'sn',
            ],
            'ldap' => [
                'enabled' => false,
                'directory_type' => 'edir',
                'hosts' => 'ldaps://localhost:636',
                'bind_user' => '',
                'bind_dn' => '',
                'bind_password_encrypted' => '',
                'base_dn' => '',
                'allow_insecure_ldap' => false,
                'network_timeout' => 5,
                'time_limit' => 10,
                'referrals' => 'never',
                'user_filter' => '(&(objectClass=inetOrgPerson)(cn=%s))',
                'group_attr_edir' => 'groupMembership',
                'group_attr_ad' => 'memberOf',
                'mail_attr' => 'mail',
                'first_name_attr' => 'givenName',
                'last_name_attr' => 'sn',
                'username_attr_fallback' => 'cn',
            ],
            'roles' => [
                'mappings' => [],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function getAll(): array
    {
        $stored = get_option($this->optionKey(), null);
        if (! is_array($stored)) {
            $legacy = get_option(self::LEGACY_OPTION_KEY, null);
            $stored = is_array($legacy) ? $legacy : [];
        }

        return $this->deepMerge($this->defaults(), $stored);
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function get(string $section, string $key, mixed $default = null): mixed
    {
        $all = $this->getAll();
        return $all[$section][$key] ?? $default;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function update(array $options): void
    {
        $sanitized = $this->sanitize($options);
        $key = $this->optionKey();
        if (false === get_option($key, false)) {
            add_option($key, $sanitized, '', false);
        } else {
            update_option($key, $sanitized, false);
        }
        $this->forgetLegacyOption();
    }

    /**
     * Delete sls_options after a successful write to the current key.
     */
    public function forgetLegacyOption(): void
    {
        if (self::LEGACY_OPTION_KEY === $this->optionKey()) {
            return;
        }
        if (false === get_option(self::LEGACY_OPTION_KEY, false)) {
            return;
        }
        delete_option(self::LEGACY_OPTION_KEY);
    }

    /**
     * Whether LDAP integration is enabled in settings.
     */
    public function isLdapEnabled(): bool
    {
        return (bool) $this->get('ldap', 'enabled', false);
    }

    /**
     * Whether LDAP is enabled and has enough configuration for a service bind.
     */
    public function isLdapUsable(): bool
    {
        if (! $this->isLdapEnabled()) {
            return false;
        }

        $ldap = $this->getAll()['ldap'];
        $hosts = trim((string) ($ldap['hosts'] ?? ''));
        $baseDn = trim((string) ($ldap['base_dn'] ?? ''));
        $bindUser = trim((string) ($ldap['bind_user'] ?? ($ldap['bind_dn'] ?? '')));
        $bindPass = $this->decryptSecret((string) ($ldap['bind_password_encrypted'] ?? ''));
        if (false === $bindPass) {
            // A stored-but-undecryptable secret still counts as configured so the
            // failure surfaces as a decrypt error instead of "LDAP not configured".
            $bindPass = 'x';
        }

        return '' !== $hosts && '' !== $baseDn && '' !== $bindUser && '' !== $bindPass;
    }

    /**
     * Whether SAML logins must be verified against LDAP before account creation.
     */
    public function mustVerifyLdapForSaml(): bool
    {
        return $this->isLdapUsable();
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function sanitize(array $options): array
    {
        $defaults = $this->defaults();
        $result = $this->deepMerge($defaults, $options);

        $result['general']['auto_sso'] = ! empty($result['general']['auto_sso']);
        $result['general']['deny_if_no_group_match'] = ! empty($result['general']['deny_if_no_group_match']);
        unset($result['general']['debug_logging']);
        $result['general']['saml_strict_validation'] = ! empty($result['general']['saml_strict_validation']);
        $result['general']['trust_proxy_headers'] = ! empty($result['general']['trust_proxy_headers']);
        $result['general']['allow_email_account_linking'] = ! empty($result['general']['allow_email_account_linking']);
        $result['general']['allow_idp_initiated'] = ! empty($result['general']['allow_idp_initiated']);
        $result['general']['role_downgrade'] = ! empty($result['general']['role_downgrade']);
        $result['general']['protected_logins'] = sanitize_textarea_field((string) ($result['general']['protected_logins'] ?? ''));
        $result['general']['role_priority'] = sanitize_text_field((string) ($result['general']['role_priority'] ?? ''));
        $result['general']['log_file'] = $this->sanitizeLogFilename((string) ($result['general']['log_file'] ?? ''));
        $result['general']['audit_log_file'] = $this->sanitizeLogFilename((string) ($result['general']['audit_log_file'] ?? ''));
        $result['general']['saml_response_max_bytes'] = min(4194304, max(4096, (int) ($result['general']['saml_response_max_bytes'] ?? 262144)));
        $result['general']['log_retention_days'] = min(730, max(7, (int) ($result['general']['log_retention_days'] ?? 90)));
        $result['general']['password_bypass_key'] = sanitize_text_field((string) ($result['general']['password_bypass_key'] ?? ''));
        $result['general']['bypass_limit'] = max(1, (int) $result['general']['bypass_limit']);
        $result['general']['bypass_window_seconds'] = max(60, (int) $result['general']['bypass_window_seconds']);
        $result['general']['bypass_lockout_seconds'] = max(60, (int) $result['general']['bypass_lockout_seconds']);
        $result['general']['saml_clock_skew_seconds'] = min(300, max(0, (int) $result['general']['saml_clock_skew_seconds']));
        $result['general']['saml_request_ttl_seconds'] = max(60, (int) $result['general']['saml_request_ttl_seconds']);
        $result['general']['saml_relay_ttl_seconds'] = max(60, (int) $result['general']['saml_relay_ttl_seconds']);
        $result['general']['default_role'] = sanitize_key((string) $result['general']['default_role']);
        $result['general']['role_strategy'] = in_array($result['general']['role_strategy'], ['highest', 'first', 'all'], true) ? $result['general']['role_strategy'] : 'highest';

        foreach (['sp_entity_id', 'primary_sso_url'] as $urlKey) {
            if (isset($result['saml'][$urlKey])) {
                $result['saml'][$urlKey] = esc_url_raw((string) $result['saml'][$urlKey]);
            }
        }
        foreach (array_keys($result['saml']) as $rawKey) {
            $key = (string) $rawKey;
            if (str_contains($key, '_attr') || str_contains($key, 'entity_id')) {
                $result['saml'][$key] = sanitize_text_field((string) $result['saml'][$key]);
            }
        }
        foreach (['primary_x509_cert', 'secondary_x509_cert'] as $certKey) {
            $pem = SignatureVerifier::normalizeCertPem(trim((string) $result['saml'][$certKey]));
            if ('' !== $pem && false === openssl_x509_parse($pem)) {
                $pem = '';
            }
            $result['saml'][$certKey] = $pem;
        }
        $result['saml'] = array_intersect_key($result['saml'], $defaults['saml']);

        $result['ldap']['enabled'] = ! empty($result['ldap']['enabled']);
        $result['ldap']['allow_insecure_ldap'] = ! empty($result['ldap']['allow_insecure_ldap']);
        $result['ldap']['directory_type'] = in_array($result['ldap']['directory_type'], ['edir', 'ad'], true) ? $result['ldap']['directory_type'] : 'edir';
        $result['ldap']['hosts'] = $this->sanitizeLdapHosts((string) $result['ldap']['hosts']);
        $result['ldap']['bind_user'] = sanitize_text_field((string) ($result['ldap']['bind_user'] ?? ''));
        $result['ldap']['bind_dn'] = sanitize_text_field((string) ($result['ldap']['bind_dn'] ?? ''));
        if ('' === $result['ldap']['bind_user'] && '' !== $result['ldap']['bind_dn']) {
            $result['ldap']['bind_user'] = $result['ldap']['bind_dn'];
        }
        $result['ldap']['base_dn'] = sanitize_text_field((string) $result['ldap']['base_dn']);
        $result['ldap']['network_timeout'] = max(1, (int) $result['ldap']['network_timeout']);
        $result['ldap']['time_limit'] = max(1, (int) $result['ldap']['time_limit']);
        $result['ldap']['referrals'] = in_array($result['ldap']['referrals'], ['never', 'always'], true) ? $result['ldap']['referrals'] : 'never';
        foreach (['user_filter', 'group_attr_edir', 'group_attr_ad', 'mail_attr', 'first_name_attr', 'last_name_attr', 'username_attr_fallback'] as $filterKey) {
            $result['ldap'][$filterKey] = sanitize_text_field((string) $result['ldap'][$filterKey]);
        }
        if ('' === $result['ldap']['user_filter']) {
            $legacyFilter = '';
            if ('ad' === $result['ldap']['directory_type'] && ! empty($result['ldap']['user_filter_ad'])) {
                $legacyFilter = (string) $result['ldap']['user_filter_ad'];
            } elseif ('edir' === $result['ldap']['directory_type'] && ! empty($result['ldap']['user_filter_edir'])) {
                $legacyFilter = (string) $result['ldap']['user_filter_edir'];
            }
            if ('' !== $legacyFilter) {
                $result['ldap']['user_filter'] = sanitize_text_field($legacyFilter);
            } else {
                $result['ldap']['user_filter'] = 'ad' === $result['ldap']['directory_type']
                    ? '(&(objectClass=user)(sAMAccountName=%s))'
                    : '(&(objectClass=inetOrgPerson)(cn=%s))';
            }
        }

        $mappings = [];
        if (! empty($result['roles']['mappings']) && is_array($result['roles']['mappings'])) {
            foreach ($result['roles']['mappings'] as $row) {
                if (! is_array($row)) {
                    continue;
                }
                $source = in_array($row['source'] ?? 'any', ['any', 'ldap', 'saml'], true) ? $row['source'] : 'any';
                $group = sanitize_text_field((string) ($row['group'] ?? ''));
                $role = sanitize_key((string) ($row['role'] ?? ''));
                if ('' === $group || '' === $role) {
                    continue;
                }
                $mappings[] = [
                    'source' => $source,
                    'group' => $group,
                    'role' => $role,
                ];
            }
        }
        $result['roles']['mappings'] = $mappings;

        return $result;
    }

    /**
     * Encrypt a secret value for storage in the options table.
     */
    public function encryptSecret(#[\SensitiveParameter] string $value): string
    {
        if ('' === $value) {
            return '';
        }
        $key = hash_hkdf('sha256', wp_salt('auth'), 32, 'sc-secret');
        $iv = random_bytes(12);
        $tag = '';
        $enc = openssl_encrypt($value, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if (false === $enc) {
            return '';
        }

        return base64_encode($iv . $tag . $enc);
    }

    /**
     * Decrypt a secret value stored by encryptSecret().
     *
     * An empty stored value returns an empty string; a stored ciphertext that
     * cannot be decrypted returns false. Callers must distinguish the two so a
     * rotated `wp_salt('auth')` is reported instead of a generic bind failure.
     *
     * @param string $encoded Base64 payload produced by encryptSecret().
     *
     * @return string|false Plaintext, '' when nothing is stored, false on decrypt failure.
     */
    public function decryptSecret(#[\SensitiveParameter] string $encoded): string|false
    {
        if ('' === $encoded) {
            return '';
        }
        $raw = base64_decode($encoded, true);
        if (false === $raw || strlen($raw) < 29) {
            return false;
        }
        $key = hash_hkdf('sha256', wp_salt('auth'), 32, 'sc-secret');
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $enc = substr($raw, 28);

        return openssl_decrypt($enc, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    }

    /**
     * Human-readable explanation for a failed secret decryption.
     */
    public function secretDecryptFailureMessage(): string
    {
        return __(
            'Stored LDAP bind password could not be decrypted. This happens when wp-config.php security salts are rotated or the site is copied between environments. Re-enter the bind password in the plugin settings.',
            'signclave-sso'
        );
    }

    /**
     * Restrict a stored log filename to a safe `sc-*.log` basename.
     */
    private function sanitizeLogFilename(string $filename): string
    {
        $filename = sanitize_file_name(basename(trim($filename)));
        if (! preg_match('/^sc[a-z0-9._-]*\.log$/i', $filename)) {
            return '';
        }

        return $filename;
    }

    /**
     * Keep only ldap:// and ldaps:// hosts with a valid port.
     */
    private function sanitizeLdapHosts(string $hosts): string
    {
        $clean = [];
        foreach (explode(',', $hosts) as $host) {
            $host = trim($host);
            if ('' === $host) {
                continue;
            }
            $parts = wp_parse_url($host);
            if (! is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
                continue;
            }
            $scheme = strtolower((string) $parts['scheme']);
            if (! in_array($scheme, ['ldap', 'ldaps'], true)) {
                continue;
            }
            $port = isset($parts['port']) ? (int) $parts['port'] : ('ldaps' === $scheme ? 636 : 389);
            if ($port < 1 || $port > 65535) {
                continue;
            }
            $clean[] = $scheme . '://' . strtolower((string) $parts['host']) . ':' . $port;
        }

        return implode(',', array_values(array_unique($clean)));
    }

    /**
     * @param array<string, mixed> $base
     * @param array<string, mixed> $override
     * @return array<string, mixed>
     */
    private function deepMerge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (isset($base[$key]) && is_array($base[$key]) && is_array($value)) {
                $base[$key] = $this->deepMerge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }

        return $base;
    }
}
