<?php

declare(strict_types=1);

namespace Signclave\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Ldap\Connection;
use Signclave\Settings\Options;

/**
 * WordPress Site Health tests for IdP certificates, LDAP, and HTTPS.
 */
final class SiteHealth
{
    /**
     * @param Options    $options    Plugin options.
     * @param Connection $connection LDAP host parser.
     */
    public function __construct(
        private readonly Options $options,
        private readonly Connection $connection
    ) {
    }

    /**
     * Register Site Health tests.
     */
    public function registerHooks(): void
    {
        add_filter('site_status_tests', [$this, 'registerTests']);
    }

    /**
     * Add direct Site Health tests for this plugin.
     *
     * @param array<string, mixed> $tests Existing tests.
     *
     * @return array<string, mixed>
     */
    public function registerTests(array $tests): array
    {
        $tests['direct']['signclave_sso_idp_cert'] = [
            'label' => __('Signclave SSO: IdP certificate', 'signclave-sso'),
            'test' => [$this, 'testIdpCertificate'],
        ];
        $tests['direct']['signclave_sso_ldap_tls'] = [
            'label' => __('Signclave SSO: LDAP TLS', 'signclave-sso'),
            'test' => [$this, 'testLdapTls'],
        ];
        $tests['direct']['signclave_sso_https'] = [
            'label' => __('Signclave SSO: HTTPS', 'signclave-sso'),
            'test' => [$this, 'testHttps'],
        ];
        $tests['direct']['signclave_sso_ldap_configured'] = [
            'label' => __('Signclave SSO: LDAP configuration', 'signclave-sso'),
            'test' => [$this, 'testLdapConfigured'],
        ];

        return $tests;
    }

    /**
     * Warn when a pinned IdP certificate is expired or expires within 30 days.
     *
     * @return array<string, mixed>
     */
    public function testIdpCertificate(): array
    {
        $saml = $this->options->getAll()['saml'];
        $now = time();
        $warnBefore = $now + (30 * 86400);
        $issues = [];
        $worst = 'good';

        foreach (
            [
                'primary' => (string) ($saml['primary_x509_cert'] ?? ''),
                'secondary' => (string) ($saml['secondary_x509_cert'] ?? ''),
            ] as $label => $pem
        ) {
            $pem = trim($pem);
            if ('' === $pem) {
                if ('primary' === $label) {
                    $issues[] = __('No primary IdP certificate is configured.', 'signclave-sso');
                    $worst = $this->worseStatus($worst, 'recommended');
                }
                continue;
            }

            $parsed = openssl_x509_parse($pem);
            if (!is_array($parsed) || !isset($parsed['validTo_time_t'])) {
                $issues[] = sprintf(
                    /* translators: %s: primary or secondary */
                    __('The %s IdP certificate could not be parsed.', 'signclave-sso'),
                    $label
                );
                $worst = $this->worseStatus($worst, 'recommended');
                continue;
            }

            $validTo = (int) $parsed['validTo_time_t'];
            $date = wp_date('Y-m-d', $validTo);
            if ($validTo < $now) {
                $issues[] = sprintf(
                    /* translators: 1: primary or secondary, 2: expiry date */
                    __('The %1$s IdP certificate expired on %2$s. SSO will fail until it is replaced.', 'signclave-sso'),
                    $label,
                    $date
                );
                $worst = $this->worseStatus($worst, 'critical');
            } elseif ($validTo < $warnBefore) {
                $issues[] = sprintf(
                    /* translators: 1: primary or secondary, 2: expiry date */
                    __('The %1$s IdP certificate expires on %2$s (within 30 days).', 'signclave-sso'),
                    $label,
                    $date
                );
                $worst = $this->worseStatus($worst, 'recommended');
            }
        }

        if ('good' === $worst) {
            return $this->result(
                'signclave_sso_idp_cert',
                'good',
                __('IdP certificates are valid.', 'signclave-sso'),
                '<p>' . esc_html__('Pinned IdP certificates are present and not expiring within 30 days.', 'signclave-sso') . '</p>'
            );
        }

        return $this->result(
            'signclave_sso_idp_cert',
            $worst,
            __('IdP certificate needs attention.', 'signclave-sso'),
            '<p>' . esc_html(implode(' ', $issues)) . '</p>'
        );
    }

    /**
     * Recommend ldaps:// when LDAP is enabled without insecure override.
     *
     * @return array<string, mixed>
     */
    public function testLdapTls(): array
    {
        $ldap = $this->options->getAll()['ldap'];
        if (empty($ldap['enabled'])) {
            return $this->result(
                'signclave_sso_ldap_tls',
                'good',
                __('LDAP is not enabled.', 'signclave-sso'),
                '<p>' . esc_html__('LDAP fallback is off; TLS for the directory is not required.', 'signclave-sso') . '</p>'
            );
        }

        $hosts = $this->connection->parseHosts((string) ($ldap['hosts'] ?? ''));
        $plain = [];
        foreach ($hosts as $host) {
            if (str_starts_with(strtolower($host), 'ldap://')) {
                $plain[] = $host;
            }
        }

        if ([] === $plain || !empty($ldap['allow_insecure_ldap'])) {
            return $this->result(
                'signclave_sso_ldap_tls',
                'good',
                __('LDAP hosts use TLS or insecure LDAP is explicitly allowed.', 'signclave-sso'),
                '<p>' . esc_html__('Directory hosts are ldaps://, or “Allow ldap://” is enabled for a lab environment.', 'signclave-sso') . '</p>'
            );
        }

        return $this->result(
            'signclave_sso_ldap_tls',
            'recommended',
            __('LDAP is enabled without ldaps://.', 'signclave-sso'),
            '<p>' . esc_html__('Use ldaps:// (or enable StartTLS on ldap://). Plaintext ldap:// without “Allow ldap://” will fail in production.', 'signclave-sso') . '</p>'
        );
    }

    /**
     * Warn when WordPress does not see HTTPS and proxy headers are not trusted.
     *
     * @return array<string, mixed>
     */
    public function testHttps(): array
    {
        if (is_ssl()) {
            return $this->result(
                'signclave_sso_https',
                'good',
                __('WordPress sees this request as HTTPS.', 'signclave-sso'),
                '<p>' . esc_html__('Secure cookies and ACS URLs can be generated correctly.', 'signclave-sso') . '</p>'
            );
        }

        if (!empty($this->options->get('general', 'trust_proxy_headers', false))) {
            return $this->result(
                'signclave_sso_https',
                'good',
                __('HTTPS is not detected locally; proxy headers are trusted.', 'signclave-sso'),
                '<p>' . esc_html__('Confirm the reverse proxy strips client-supplied X-Forwarded-* headers.', 'signclave-sso') . '</p>'
            );
        }

        return $this->result(
            'signclave_sso_https',
            'recommended',
            __('WordPress does not see HTTPS.', 'signclave-sso'),
            '<p>' . esc_html__('Auth cookies may be marked insecure and the ACS URL may be http://. Terminate TLS at the web server, or enable “Trust proxy HTTPS headers” only behind a trusted reverse proxy.', 'signclave-sso') . '</p>'
        );
    }

    /**
     * Lightweight LDAP “configured” check (no live bind).
     *
     * @return array<string, mixed>
     */
    public function testLdapConfigured(): array
    {
        if (!$this->options->isLdapEnabled()) {
            return $this->result(
                'signclave_sso_ldap_configured',
                'good',
                __('LDAP is not enabled.', 'signclave-sso'),
                '<p>' . esc_html__('SAML runs without directory verification.', 'signclave-sso') . '</p>'
            );
        }

        if ($this->options->isLdapUsable()) {
            return $this->result(
                'signclave_sso_ldap_configured',
                'good',
                __('LDAP is configured.', 'signclave-sso'),
                '<p>' . esc_html__('Host, base DN, bind user, and bind secret are present. Use diagnostics or `wp signclave test-ldap` for a live bind.', 'signclave-sso') . '</p>'
            );
        }

        return $this->result(
            'signclave_sso_ldap_configured',
            'recommended',
            __('LDAP is enabled but incomplete.', 'signclave-sso'),
            '<p>' . esc_html__('Fill in hosts, base DN, bind user, and bind password, or disable LDAP.', 'signclave-sso') . '</p>'
        );
    }

    /**
     * @param string $test   Test identifier.
     * @param string $status good, recommended, or critical.
     * @param string $label  Short result label.
     * @param string $html   Description HTML.
     *
     * @return array<string, mixed>
     */
    private function result(string $test, string $status, string $label, string $html): array
    {
        $badge = match ($status) {
            'critical' => ['label' => __('Security', 'signclave-sso'), 'color' => 'red'],
            'recommended' => ['label' => __('Security', 'signclave-sso'), 'color' => 'orange'],
            default => ['label' => __('Security', 'signclave-sso'), 'color' => 'blue'],
        };

        return [
            'label' => $label,
            'status' => $status,
            'badge' => $badge,
            'description' => $html,
            'actions' => '',
            'test' => $test,
        ];
    }

    /**
     * Return the more severe of two Site Health statuses.
     */
    private function worseStatus(string $current, string $candidate): string
    {
        $rank = ['good' => 0, 'recommended' => 1, 'critical' => 2];

        return ($rank[$candidate] ?? 0) > ($rank[$current] ?? 0) ? $candidate : $current;
    }
}
