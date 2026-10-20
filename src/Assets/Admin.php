<?php

declare(strict_types=1);

namespace Signclave\Assets;

if (!defined('ABSPATH')) {
    exit;
}

use function Signclave\config;

/**
 * Enqueues Vite-built admin assets on the settings page.
 */
final class Admin
{
    private const HANDLE = 'signclave-sso-admin';
    private const ENTRY = 'resources/assets/js/admin.js';

    /**
     * @param ViteManifest $manifest Vite build manifest reader.
     */
    public function __construct(
        private readonly ViteManifest $manifest
    ) {
    }

    /**
     * Register WordPress hooks for admin asset loading.
     */
    public function registerHooks(): void
    {
        add_action('admin_enqueue_scripts', [$this, 'enqueue']);
        add_filter('script_loader_tag', [$this, 'moduleTypeAttribute'], 10, 2);
    }

    /**
     * Add type="module" to the admin script tag when enqueued.
     *
     * @param string $tag    Original script HTML tag.
     * @param string $handle Registered script handle.
     */
    public function moduleTypeAttribute(string $tag, string $handle): string
    {
        if (self::HANDLE === $handle) {
            return str_replace(' src', ' type="module" src', $tag);
        }

        return $tag;
    }

    /**
     * Enqueue admin JS/CSS on the plugin settings screen only.
     *
     * @param string $hook Current admin page hook suffix.
     */
    public function enqueue(string $hook): void
    {
        if ('settings_page_signclave-sso' !== $hook) {
            return;
        }

        $version = (string) config('app.version');
        $baseUrl = (string) config('paths.plugin_url') . 'dist/';
        $adminJs = $this->manifest->getAsset(self::ENTRY);
        $adminCss = $this->manifest->getCss(self::ENTRY);

        if ($adminJs) {
            wp_enqueue_script(
                self::HANDLE,
                $baseUrl . $adminJs,
                [],
                $version,
                true
            );

            wp_localize_script(
                self::HANDLE,
                'signclaveSsoAdmin',
                [
                    'ajaxUrl' => admin_url('admin-ajax.php'),
                    'ldapNonce' => wp_create_nonce('signclave_sso_test_ldap'),
                    'ssoNonce' => wp_create_nonce('signclave_sso_test_sso'),
                    'copied' => __('Copied', 'signclave-sso'),
                ]
            );
        }

        foreach ($adminCss as $index => $cssFile) {
            wp_enqueue_style(
                self::HANDLE . '-' . $index,
                $baseUrl . $cssFile,
                [],
                $version
            );
        }
    }
}
