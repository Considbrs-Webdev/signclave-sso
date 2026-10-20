<?php

declare(strict_types=1);

namespace Signclave\Auth;

if (!defined('ABSPATH')) {
    exit;
}

use Signclave\Settings\Options;
use Signclave\Support\RateLimiter;
use WP_Error;
use WP_User;

// phpcs:disable WordPress.Security.NonceVerification -- Emergency URL uses signclave_sso_key (compared with hash_equals), not a WP nonce.

/**
 * Emergency local login: wp-login.php?password=1&signclave_sso_key=...
 *
 * WordPress posts the login form to wp-login.php without query args, so the
 * bypass flag and key are also echoed as hidden fields and accepted from POST.
 */
final class PasswordBypass
{
    /**
     * @param Options     $options     Plugin options service.
     * @param RateLimiter $rateLimiter Bypass attempt rate limiter.
     */
    public function __construct(
        private readonly Options $options,
        private readonly RateLimiter $rateLimiter
    ) {
    }

    /**
     * Register login-form hooks that preserve the bypass across POST.
     */
    public function registerHooks(): void
    {
        add_action('login_form', [$this, 'renderLoginFormFields']);
    }

    /**
     * Return whether the current request is a valid password bypass login.
     *
     * Accepts GET (initial emergency URL) or POST (credential submit).
     */
    public function isPasswordBypassRequest(): bool
    {
        $passwordFlag = $this->requestValue('password');
        if ('1' !== $passwordFlag) {
            return false;
        }

        $configuredKey = (string) $this->options->get('general', 'password_bypass_key', '');
        if ('' === $configuredKey) {
            return false;
        }

        $providedKey = $this->requestValue('signclave_sso_key');
        if ('' === $providedKey) {
            return false;
        }

        return hash_equals($configuredKey, $providedKey);
    }

    /**
     * Echo hidden fields so credential POST keeps the emergency key.
     */
    public function renderLoginFormFields(): void
    {
        if (!$this->isPasswordBypassRequest()) {
            return;
        }

        $key = (string) $this->options->get('general', 'password_bypass_key', '');
        if ('' === $key) {
            return;
        }

        echo '<input type="hidden" name="password" value="1" />';
        echo '<input type="hidden" name="signclave_sso_key" value="' . esc_attr($key) . '" />';
    }

    /**
     * Restrict bypass logins to local-only accounts and apply rate limiting.
     *
     * @param mixed  $user     Current authenticate filter user value.
     * @param string $username Submitted username.
     *
     * @return mixed
     */
    public function enforceLocalAccountOnly(mixed $user, string $username): mixed
    {
        if (!$this->isPasswordBypassRequest()) {
            return $user;
        }

        $ip = $this->clientIp();
        if ($this->rateLimiter->isLocked('password_bypass', $username, $ip)) {
            return AuthFailureReason::Locked->toWpError();
        }

        if ($user instanceof WP_Error) {
            $this->rateLimiter->recordFailure('password_bypass', $username, $ip);

            return $user;
        }

        if (!$user instanceof WP_User) {
            return $user;
        }

        $source = (string) get_user_meta($user->ID, 'signclave_sso_source', true);
        if (in_array($source, ['ldap', 'saml'], true)) {
            $this->rateLimiter->recordFailure('password_bypass', $username, $ip);

            return AuthFailureReason::LocalOnly->toWpError();
        }

        $this->rateLimiter->clearFailures('password_bypass', $username, $ip);

        return $user;
    }

    /**
     * Build the emergency bypass login URL, or empty string when disabled.
     */
    public function loginUrl(): string
    {
        $key = (string) $this->options->get('general', 'password_bypass_key', '');
        if ('' === $key) {
            return '';
        }

        return add_query_arg(
            [
                'password' => '1',
                'signclave_sso_key' => $key,
            ],
            wp_login_url()
        );
    }

    /**
     * Read a scalar request value from GET or POST (POST wins on conflict).
     */
    private function requestValue(string $key): string
    {
        if (isset($_POST[$key])) {
            return sanitize_text_field(wp_unslash((string) $_POST[$key]));
        }

        if (isset($_GET[$key])) {
            return sanitize_text_field(wp_unslash((string) $_GET[$key]));
        }

        return '';
    }

    /**
     * Return the client IP address from the current request.
     */
    private function clientIp(): string
    {
        $ip = isset($_SERVER['REMOTE_ADDR'])
            ? sanitize_text_field(wp_unslash((string) $_SERVER['REMOTE_ADDR']))
            : '';

        return is_string($ip) ? $ip : '';
    }
}
