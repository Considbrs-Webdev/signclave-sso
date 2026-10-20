<?php

declare(strict_types=1);

namespace Signclave\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Auth\PasswordBypass;
use Signclave\Saml\Metadata;
use Signclave\Settings\Options;
use Signclave\Support\Logger;
use Signclave\Support\View;

/**
 * WordPress admin UI for plugin options (Settings API + custom markup).
 */
final class SettingsPage
{
    /**
     * Whether this request already wrote a "Settings updated" audit line.
     *
     * WordPress calls the Settings API sanitize callback twice per save.
     */
    private bool $loggedSettingsUpdate = false;

    /**
     * @param Logger         $logger          Audit logger.
     * @param Options        $options         Plugin options.
     * @param Metadata       $metadata        SP metadata builder.
     * @param PasswordBypass $passwordBypass  Emergency password login gate.
     * @param View           $view            Template renderer.
     */
    public function __construct(
        private readonly Logger $logger,
        private readonly Options $options,
        private readonly Metadata $metadata,
        private readonly PasswordBypass $passwordBypass,
        private readonly View $view
    ) {
    }

    /**
     * Register admin menu, Settings API, and metadata download.
     */
    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_init', [$this, 'registerSetting']);
        add_action('admin_post_signclave_sso_download_metadata', [$this, 'handleMetadataDownload']);
        add_action('added_option', [$this, 'forgetLegacyOptions']);
        add_action('updated_option', [$this, 'forgetLegacyOptions']);
    }

    /**
     * Register the option group with WordPress Settings API.
     */
    public function registerSetting(): void
    {
        register_setting(
            'signclave_sso',
            $this->options->optionKey(),
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitizeOptions'],
                'show_in_rest' => false,
                'default' => $this->options->defaults(),
            ]
        );
    }

    /**
     * Drop sls_options once WordPress has stored signclave_sso_options.
     *
     * @param string $option Option name that was just added or updated.
     */
    public function forgetLegacyOptions(string $option): void
    {
        if ($this->options->optionKey() !== $option) {
            return;
        }
        $this->options->forgetLegacyOption();
    }

    /**
     * Add the plugin settings page under Settings.
     */
    public function menu(): void
    {
        add_options_page(
            __('Signclave – SSO for SAML and LDAP', 'signclave-sso'),
            __('Signclave SSO', 'signclave-sso'),
            'manage_options',
            'signclave-sso',
            [$this, 'renderPage']
        );
    }

    /**
     * Render the settings page view.
     */
    public function renderPage(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized.', 'signclave-sso'));
        }

        $options = $this->options->getAll();
        $bindUserValue = (string) ($options['ldap']['bind_user'] ?? ($options['ldap']['bind_dn'] ?? ''));

        $this->view->render(
            'admin/settings-page',
            [
                'options' => $options,
                'roles' => wp_roles()->roles,
                'bind_user_value' => $bindUserValue,
                'metadata_xml' => $this->metadata->buildSpMetadataXml(),
                'metadata_url' => $this->metadata->spMetadataUrl(),
                'metadata_download' => wp_nonce_url(
                    admin_url('admin-post.php?action=signclave_sso_download_metadata'),
                    'signclave_sso_download_metadata'
                ),
                'recent_acs_failures' => $this->logger->getRecentAuditEntries(3),
                'mappings_text' => $this->mappingsToText($options['roles']['mappings']),
                'bypass_url' => $this->passwordBypass->loginUrl(),
                'acs_url' => $this->metadata->spAcsUrl(),
                'secondary_cert' => (string) ($options['saml']['secondary_x509_cert'] ?? ''),
                'allow_idp_initiated' => !empty($options['general']['allow_idp_initiated']),
                'clock_skew_seconds' => (int) ($options['general']['saml_clock_skew_seconds'] ?? 60),
                'role_downgrade' => !empty($options['general']['role_downgrade']),
                'protected_logins' => (string) ($options['general']['protected_logins'] ?? ''),
                'role_priority' => (string) ($options['general']['role_priority'] ?? ''),
                'log_retention_days' => (int) ($options['general']['log_retention_days'] ?? 90),
            ]
        );
    }

    /**
     * Merge submitted Settings API input with stored options and sanitize.
     *
     * Unchecked checkboxes are forced to false. Bind password, role mappings,
     * and emergency-key rotation are read from extra POST fields.
     *
     * @param mixed $input Raw option payload from options.php.
     *
     * @return array<string, mixed>
     */
    public function sanitizeOptions(mixed $input): array
    {
        $existing = $this->options->getAll();
        $posted = is_array($input) ? $input : [];
        $new = array_replace_recursive($existing, $posted);
        // phpcs:disable WordPress.Security.NonceVerification -- Settings API verifies the signclave_sso nonce before this callback.
        $optionPage = isset($_POST['option_page'])
            ? sanitize_text_field(wp_unslash((string) $_POST['option_page']))
            : '';
        $fromSettingsForm = 'signclave_sso' === $optionPage;

        if ($fromSettingsForm) {
            $new['general']['auto_sso'] = !empty($posted['general']['auto_sso']);
            $new['general']['deny_if_no_group_match'] = !empty($posted['general']['deny_if_no_group_match']);
            $new['general']['saml_strict_validation'] = !empty($posted['general']['saml_strict_validation']);
            $new['general']['trust_proxy_headers'] = !empty($posted['general']['trust_proxy_headers']);
            $new['general']['allow_email_account_linking'] = !empty($posted['general']['allow_email_account_linking']);
            $new['general']['allow_idp_initiated'] = !empty($posted['general']['allow_idp_initiated']);
            $new['general']['role_downgrade'] = !empty($posted['general']['role_downgrade']);
            $new['ldap']['enabled'] = !empty($posted['ldap']['enabled']);
            $new['ldap']['allow_insecure_ldap'] = !empty($posted['ldap']['allow_insecure_ldap']);

            $rotateKey = isset($_POST['signclave_sso_regenerate_bypass_key'])
                ? sanitize_text_field(wp_unslash((string) $_POST['signclave_sso_regenerate_bypass_key']))
                : '';
            if ('' !== $rotateKey) {
                $new['general']['password_bypass_key'] = wp_generate_password(32, false, false);
                $this->logger->security(
                    'Emergency login key regenerated.',
                    ['admin' => wp_get_current_user()->user_login]
                );
            } elseif ('' === (string) ($new['general']['password_bypass_key'] ?? '')) {
                $new['general']['password_bypass_key'] = wp_generate_password(32, false, false);
            }

            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- bind password must not pass sanitize_text_field.
            $bindPlain = isset($_POST['signclave_sso_bind_password']) ? (string) wp_unslash($_POST['signclave_sso_bind_password']) : '';
            if ('' !== $bindPlain) {
                $new['ldap']['bind_password_encrypted'] = $this->options->encryptSecret($bindPlain);
            } else {
                $new['ldap']['bind_password_encrypted'] = (string) ($existing['ldap']['bind_password_encrypted'] ?? '');
            }

            $mappingsText = isset($_POST['signclave_sso_role_mappings'])
                ? sanitize_textarea_field(wp_unslash((string) $_POST['signclave_sso_role_mappings']))
                : '';
            $new['roles']['mappings'] = $this->parseMappings($mappingsText);

            if (!$this->loggedSettingsUpdate) {
                $this->logger->security('Settings updated.', ['admin' => wp_get_current_user()->user_login]);
                $this->loggedSettingsUpdate = true;
            }
        } elseif ('' === (string) ($new['general']['password_bypass_key'] ?? '')) {
            $new['general']['password_bypass_key'] = wp_generate_password(32, false, false);
        }
        // phpcs:enable WordPress.Security.NonceVerification

        return $this->options->sanitize($new);
    }

    /**
     * Stream SP metadata as a downloadable XML attachment.
     */
    public function handleMetadataDownload(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized.', 'signclave-sso'));
        }
        check_admin_referer('signclave_sso_download_metadata');

        $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        $filename = sanitize_file_name(('' !== $host ? $host : 'sp') . '-saml-metadata.xml');

        header('Content-Type: application/xml; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('X-Content-Type-Options: nosniff');
        echo $this->metadata->buildSpMetadataXml(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- XML document.
        exit;
    }

    /**
     * @param array<int, mixed> $mappings
     */
    private function mappingsToText(array $mappings): string
    {
        $lines = [];
        foreach ($mappings as $row) {
            if (!is_array($row)) {
                continue;
            }
            $lines[] = sprintf('%s|%s|%s', $row['source'] ?? 'any', $row['group'] ?? '', $row['role'] ?? '');
        }

        return implode("\n", $lines);
    }

    /**
     * Parse textarea mapping lines into structured rows.
     *
     * @return list<array{source:string,group:string,role:string}>
     */
    private function parseMappings(string $text): array
    {
        $rows = [];
        foreach (preg_split('/\R/', $text) as $line) {
            $line = trim($line);
            if ('' === $line) {
                continue;
            }
            $parts = array_map('trim', explode('|', $line));
            if (3 !== count($parts)) {
                continue;
            }
            $rows[] = [
                'source' => in_array($parts[0], ['any', 'ldap', 'saml'], true) ? $parts[0] : 'any',
                'group' => $parts[1],
                'role' => sanitize_key($parts[2]),
            ];
        }

        return $rows;
    }
}
