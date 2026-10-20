<?php

declare(strict_types=1);

namespace Signclave\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Ldap\ClientInterface;
use Signclave\Ldap\Connection;
use Signclave\Saml\Metadata;
use Signclave\Saml\SignatureVerifier;
use Signclave\Settings\Options;
use Signclave\Support\Clock;
use Signclave\Support\Logger;

/**
 * Admin AJAX diagnostics for LDAP bind and outbound SAML AuthnRequest.
 */
final class Diagnostics
{
    /**
     * @param Logger          $logger     Audit/security logger.
     * @param ClientInterface $ldap       LDAP client.
     * @param Connection      $connection LDAP connection helper.
     * @param Options         $options    Plugin options.
     * @param Metadata        $metadata   SP metadata builder.
     * @param Clock           $clock      Clock for IssueInstant timestamps.
     */
    public function __construct(
        private readonly Logger $logger,
        private readonly ClientInterface $ldap,
        private readonly Connection $connection,
        private readonly Options $options,
        private readonly Metadata $metadata,
        private readonly Clock $clock
    ) {
    }

    /**
     * Register AJAX handlers for LDAP and SSO diagnostic tests.
     */
    public function registerHooks(): void
    {
        add_action('wp_ajax_signclave_sso_test_ldap', [$this, 'testLdap']);
        add_action('wp_ajax_signclave_sso_test_sso', [$this, 'testSso']);
    }

    /**
     * AJAX: validate LDAP connectivity, service bind, and optional user bind.
     *
     * Expects POST fields: username, password, mode (`quick`|`auth`), and nonce `signclave_sso_test_ldap`.
     */
    public function testLdap(): void
    {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(esc_html__('Unauthorized.', 'signclave-sso'));
        }
        check_ajax_referer('signclave_sso_test_ldap');

        $username = isset($_POST['username']) ? sanitize_text_field(wp_unslash((string) $_POST['username'])) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- diagnostic password must not pass sanitize_text_field.
        $password = isset($_POST['password']) ? (string) wp_unslash($_POST['password']) : '';
        $mode = isset($_POST['mode']) ? sanitize_text_field(wp_unslash((string) $_POST['mode'])) : 'auth';
        $log = [];
        $log[] = '[LDAP] Starting diagnostic test (' . $mode . ')';
        $log[] = '[LDAP] Username: ' . ('' !== $username ? $username : '(empty)');

        if (!$this->ldap->isAvailable()) {
            $this->failLdap($log, '[LDAP] FAIL: PHP LDAP extension is not loaded in this environment.');
        }

        if ('auth' === $mode && ('' === $username || '' === $password)) {
            $this->failLdap($log, '[LDAP] FAIL: Username and password are required for auth test.');
        }

        $ldapData = $this->options->getAll()['ldap'];
        $hosts = $this->connection->parseHosts((string) $ldapData['hosts']);
        if ([] === $hosts) {
            $this->failLdap($log, '[LDAP] FAIL: No LDAP host configured.');
        }

        $log[] = '[LDAP] Configured hosts: ' . implode(', ', $hosts);
        $attempt = $this->connection->connectFirstAvailable($ldapData, true);
        $conn = $attempt['conn'];
        $host = $attempt['host'];
        if (!$conn) {
            $this->failLdap($log, '[LDAP] FAIL: Unable to connect to any configured host (' . implode(', ', $attempt['tried']) . ').');
        }

        $log[] = '[LDAP] Connected host: ' . $host;

        $log[] = '[LDAP] Options set: protocol=3, referrals=' . ('never' === ($ldapData['referrals'] ?? 'never') ? '0' : '1');

        if (str_starts_with($host, 'ldap://')) {
            if (!$this->connection->startTlsIfNeeded($conn, $host, $ldapData)) {
                $err = $this->ldap->error($conn);
                $this->ldap->close($conn);
                $this->failLdap($log, '[LDAP] FAIL: StartTLS failed: ' . $err . '. Enable “Allow ldap://” for local plaintext, or use ldaps://.');
            }
            if (!empty($ldapData['allow_insecure_ldap'])) {
                $log[] = '[LDAP] Plaintext ldap:// (StartTLS skipped; insecure LDAP allowed).';
            } else {
                $log[] = '[LDAP] StartTLS negotiated on ldap:// connection.';
            }
        }

        $pass = $this->options->decryptSecret((string) ($ldapData['bind_password_encrypted'] ?? ''));
        if (false === $pass) {
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: ' . $this->options->secretDecryptFailureMessage());

            return;
        }

        $bindUser = (string) ($ldapData['bind_user'] ?? ($ldapData['bind_dn'] ?? ''));
        if ('' === $pass || '' === $bindUser) {
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: Bind user or bind password missing in settings.');
        }

        if (!$this->ldap->bind($conn, $bindUser, $pass)) {
            $err = $this->ldap->error($conn);
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: Service bind failed: ' . $err);
        }

        $log[] = '[LDAP] Service bind success.';
        if ('quick' === $mode) {
            $this->ldap->close($conn);
            $log[] = '[LDAP] SUCCESS: Quick test completed (connection + service bind).';
            wp_send_json_success([
                'summary' => 'LDAP quick test successful.',
                'log' => implode("\n", $log),
            ]);
        }

        $template = (string) ($ldapData['user_filter'] ?? '');
        if ('' === $template) {
            $template = 'ad' === ($ldapData['directory_type'] ?? 'edir')
                ? '(&(objectClass=user)(sAMAccountName=%s))'
                : '(&(objectClass=inetOrgPerson)(cn=%s))';
        }
        $escaped = $this->ldap->escape($username, '', LDAP_ESCAPE_FILTER);
        if ('' === $escaped && '' !== $username) {
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: ldap_escape() is unavailable in this PHP build.');
        }

        $filter = str_replace('%s', $escaped, $template);
        $groupAttr = 'ad' === ($ldapData['directory_type'] ?? 'edir')
            ? (string) $ldapData['group_attr_ad']
            : (string) $ldapData['group_attr_edir'];
        $attrs = [
            'dn',
            (string) $ldapData['mail_attr'],
            (string) $ldapData['first_name_attr'],
            (string) $ldapData['last_name_attr'],
            $groupAttr,
        ];
        $log[] = '[LDAP] Search base DN: ' . (string) $ldapData['base_dn'];
        $log[] = '[LDAP] Search filter: ' . $filter;

        $search = $this->ldap->search($conn, (string) $ldapData['base_dn'], $filter, $attrs);
        if (!$search) {
            $err = $this->ldap->error($conn);
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: Search failed: ' . $err);
        }

        $count = $this->ldap->countEntries($conn, $search);
        $log[] = '[LDAP] Search result count: ' . $count;
        if (1 !== $count) {
            $this->ldap->close($conn);
            $this->failLdap($log, '[LDAP] FAIL: Expected exactly one user entry.');
        }

        $entries = $this->ldap->getEntries($conn, $search);
        $dn = isset($entries[0]['dn']) ? (string) $entries[0]['dn'] : '';
        $this->ldap->close($conn);

        if ('' === $dn) {
            $this->failLdap($log, '[LDAP] FAIL: Missing user DN in result.');
        }
        $log[] = '[LDAP] User DN resolved: ' . $dn;

        $userConn = $this->connection->connect($host, $ldapData, false);
        if (!$userConn) {
            $this->failLdap($log, '[LDAP] FAIL: Could not reconnect for user bind.');
        }

        if (!$this->connection->startTlsIfNeeded($userConn, $host, $ldapData)) {
            $err = $this->ldap->error($userConn);
            $this->ldap->close($userConn);
            $this->failLdap($log, '[LDAP] FAIL: StartTLS failed on user connection: ' . $err);
        }

        if (!$this->ldap->bind($userConn, $dn, $password)) {
            $err = $this->ldap->error($userConn);
            $this->ldap->close($userConn);
            $this->failLdap($log, '[LDAP] FAIL: User bind failed: ' . $err);
        }
        $this->ldap->close($userConn);
        $log[] = '[LDAP] User bind success.';

        $groupCount = 0;
        if (isset($entries[0][strtolower($groupAttr)]['count'])) {
            $groupCount = (int) $entries[0][strtolower($groupAttr)]['count'];
        }
        $log[] = '[LDAP] Group attribute: ' . $groupAttr . ', values: ' . $groupCount;
        $log[] = '[LDAP] SUCCESS: LDAP authentication path is valid.';

        wp_send_json_success([
            'summary' => 'LDAP test successful.',
            'log' => implode("\n", $log),
        ]);
    }

    /**
     * AJAX: validate outbound SAML AuthnRequest generation (does not exercise ACS).
     *
     * Expects POST fields: username, password (ignored), and nonce `signclave_sso_test_sso`.
     */
    public function testSso(): void
    {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(esc_html__('Unauthorized.', 'signclave-sso'));
        }
        check_ajax_referer('signclave_sso_test_sso');

        $username = isset($_POST['username']) ? sanitize_text_field(wp_unslash((string) $_POST['username'])) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- diagnostic password must not pass sanitize_text_field.
        $password = isset($_POST['password']) ? (string) wp_unslash($_POST['password']) : '';
        $saml = $this->options->getAll()['saml'];
        $ssoUrl = (string) ($saml['primary_sso_url'] ?? '');
        $entity = (string) ($saml['primary_entity_id'] ?? '');
        $cert = SignatureVerifier::normalizeCertPem((string) ($saml['primary_x509_cert'] ?? ''));
        $log = [];
        $log[] = '[SSO] Starting diagnostic test';
        $log[] = '[SSO] Active IdP profile: primary';
        $log[] = '[SSO] Username input: ' . ('' !== $username ? $username : '(empty)');
        if ('' !== $password) {
            $log[] = '[SSO] Note: Password input is intentionally NOT used in SAML flow (IdP validates credentials).';
        }

        if ('' === $ssoUrl || '' === $entity || '' === $cert) {
            $log[] = '[SSO] FAIL: Missing SSO URL, Entity ID, or X509 cert in selected IdP settings.';
            wp_send_json_error([
                'summary' => 'SSO test failed.',
                'log' => implode("\n", $log),
            ]);
        }

        $certObj = openssl_x509_read($cert);
        if (false === $certObj) {
            $log[] = '[SSO] FAIL: X509 cert is invalid or malformed.';
            wp_send_json_error([
                'summary' => 'SSO test failed.',
                'log' => implode("\n", $log),
            ]);
        }
        $fingerprint = openssl_x509_fingerprint($cert, 'sha256');
        $log[] = '[SSO] Certificate parsed. SHA-256 fingerprint: ' . ($fingerprint ?: '(unavailable)');

        $secondary = SignatureVerifier::normalizeCertPem((string) ($saml['secondary_x509_cert'] ?? ''));
        if ('' === $secondary) {
            $log[] = '[SSO] Secondary certificate: not configured (certificate rotation will cause downtime).';
        } elseif (false === openssl_x509_read($secondary)) {
            $log[] = '[SSO] WARN: Secondary X509 cert is invalid or malformed and will be ignored.';
        } else {
            $log[] = '[SSO] Secondary certificate SHA-256 fingerprint: '
                . (openssl_x509_fingerprint($secondary, 'sha256') ?: '(unavailable)');
        }

        $log[] = '[SSO] IdP Entity ID: ' . $entity;
        $log[] = '[SSO] IdP SSO URL: ' . $ssoUrl;
        $log[] = '[SSO] Note: This test does NOT perform a real login or validate the SAML Response (ACS).';
        $log[] = '[SSO] If login fails after IdP, check "Recent SAML login rejections" above or the audit log in uploads/signclave-sso.';
        $log[] = '[SSO] IdP-initiated SSO allowed: ' . ($this->options->get('general', 'allow_idp_initiated', false) ? 'yes' : 'no');
        $log[] = '[SSO] Clock skew tolerance (s): ' . (int) $this->options->get('general', 'saml_clock_skew_seconds', 60);

        $acsUrl = $this->metadata->spAcsUrl();
        $spEntity = (string) ($saml['sp_entity_id'] ?? site_url('/'));
        $siteUrl = site_url('/');
        $homeUrl = home_url('/');
        $log[] = '[SSO] WordPress site URL: ' . $siteUrl;
        $log[] = '[SSO] WordPress home URL: ' . $homeUrl;
        $log[] = '[SSO] SP Entity ID (configured): ' . $spEntity;
        $log[] = '[SSO] ACS URL (this site): ' . $acsUrl;
        $log[] = '[SSO] Metadata URL: ' . $this->metadata->spMetadataUrl();

        // Site-identity match (trailing slash). Not the same as ACS Destination matching in Handler.
        if (!$this->siteIdentityUrlsMatch($spEntity, $siteUrl)) {
            $log[] = '[SSO] WARN: SP Entity ID does not match this site URL. After import/copy, update SP Entity ID and re-import SP metadata in F5.';
        }
        if (!$this->siteIdentityUrlsMatch($siteUrl, $homeUrl)) {
            $log[] = '[SSO] WARN: site_url and home_url differ. ACS URL uses site_url.';
        }
        $log[] = '[SSO] Username attribute: ' . (string) ($saml['primary_username_attr'] ?? 'uid');
        $log[] = '[SSO] Group attribute: ' . (string) ($saml['primary_group_attr'] ?? 'groups');
        if ($this->options->get('general', 'deny_if_no_group_match', false)) {
            $mappingCount = count((array) $this->options->get('roles', 'mappings', []));
            $log[] = '[SSO] WARN: deny_if_no_group_match is ON (' . $mappingCount . ' role mapping(s)). Login fails if F5 sends no matching groups.';
        }

        $recentFailures = $this->logger->getRecentAuditEntries(1);
        if (!empty($recentFailures)) {
            $log[] = '[SSO] Last ACS rejection: ' . $recentFailures[0];
        }

        $requestId = '_' . wp_generate_password(22, false, false);
        $issue = $this->clock->formatGmt('Y-m-d\TH:i:s\Z');
        $xml = sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%1$s" Version="2.0" IssueInstant="%2$s" Destination="%3$s" AssertionConsumerServiceURL="%4$s"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%5$s</saml:Issuer></samlp:AuthnRequest>',
            esc_attr($requestId),
            esc_attr($issue),
            esc_url_raw($ssoUrl),
            esc_url_raw($acsUrl),
            esc_html($spEntity)
        );
        $samlReq = base64_encode($xml);
        $log[] = '[SSO] AuthnRequest generated. Size(bytes): ' . strlen($xml);
        $log[] = '[SSO] AuthnRequest binding: HTTP-POST';
        $log[] = '[SSO] POST target: ' . $ssoUrl;
        $log[] = '[SSO] SAMLRequest preview: ' . substr($samlReq, 0, 120) . (strlen($samlReq) > 120 ? '...[truncated]' : '');

        $probe = wp_remote_head($ssoUrl, [
            'timeout' => 8,
            'redirection' => 0,
        ]);
        if (is_wp_error($probe)) {
            $log[] = '[SSO] Reachability probe failed: ' . $probe->get_error_message();
        } else {
            $status = (int) wp_remote_retrieve_response_code($probe);
            $log[] = '[SSO] Reachability probe HTTP status: ' . $status;
        }

        $log[] = '[SSO] SUCCESS: Outbound AuthnRequest generation looks valid (IdP login may still fail on ACS).';
        wp_send_json_success([
            'summary' => 'SSO outbound test OK (ACS not tested).',
            'log' => implode("\n", $log),
        ]);
    }

    /**
     * Abort an LDAP diagnostic with a JSON error payload.
     *
     * @param list<string> $log Accumulated diagnostic lines.
     * @param string       $line Final failure line to append.
     */
    private function failLdap(array $log, string $line): void
    {
        $log[] = $line;
        wp_send_json_error([
            'summary' => 'LDAP test failed.',
            'log' => implode("\n", $log),
        ]);
    }

    /**
     * Compare two site-identity URLs after normalization.
     */
    private function siteIdentityUrlsMatch(string $left, string $right): bool
    {
        return hash_equals(
            $this->normalizeSiteIdentityUrl($left),
            $this->normalizeSiteIdentityUrl($right)
        );
    }

    /**
     * Normalize a URL for site-identity comparison (host, optional port, trailing slash).
     */
    private function normalizeSiteIdentityUrl(string $url): string
    {
        $url = trim($url);
        $parts = wp_parse_url($url);
        if (!is_array($parts)) {
            return strtolower(rtrim($url, '/')) . '/';
        }

        $host = strtolower((string) ($parts['host'] ?? ''));
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        $path = '/' . trim((string) ($parts['path'] ?? ''), '/');
        if ('//' === $path) {
            $path = '/';
        }

        $normalized = $host;
        if (null !== $port && !in_array($port, [80, 443], true)) {
            $normalized .= ':' . $port;
        }
        $normalized .= rtrim($path, '/') . '/';

        return $normalized;
    }
}
