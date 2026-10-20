<?php

declare(strict_types=1);

use Signclave\Admin\SettingsPage;
use Signclave\Auth\PasswordBypass;
use Signclave\Saml\Metadata;
use Signclave\Settings\Options;
use Signclave\Support\Logger;
use Signclave\Support\RateLimiter;
use Signclave\Support\View;
use Signclave\Tests\Support\OptionStore;

beforeEach(function () {
    OptionStore::reset();
    $_POST = [];

    if (!function_exists('get_option')) {
        function get_option(string $key, mixed $default = false): mixed
        {
            return OptionStore::get($key, $default);
        }
    }
    if (!function_exists('add_option')) {
        function add_option(string $key, mixed $value, string $deprecated = '', mixed $autoload = 'yes'): bool
        {
            OptionStore::set($key, $value);

            return true;
        }
    }
    if (!function_exists('update_option')) {
        function update_option(string $key, mixed $value, mixed $autoload = null): bool
        {
            OptionStore::set($key, $value);

            return true;
        }
    }
    if (!function_exists('wp_salt')) {
        function wp_salt(string $scheme = 'auth'): string
        {
            return 'test-auth-salt-for-settings-sanitize';
        }
    }
    if (!function_exists('wp_get_current_user')) {
        function wp_get_current_user(): object
        {
            return (object) ['user_login' => 'admin'];
        }
    }
    if (!function_exists('wp_roles')) {
        function wp_roles(): object
        {
            return (object) ['role_names' => [
                'administrator' => 'Administrator',
                'subscriber' => 'Subscriber',
            ]];
        }
    }
});

function scSettingsPage(): SettingsPage
{
    $options = new Options();
    $logger = new Logger($options);

    return new SettingsPage(
        $logger,
        $options,
        new Metadata($options),
        new PasswordBypass($options, new RateLimiter($options)),
        new View()
    );
}

it('forces unchecked checkboxes to false when saving the settings form', function () {
    $options = new Options();
    $stored = $options->defaults();
    $stored['general']['auto_sso'] = true;
    $stored['general']['password_bypass_key'] = 'kept-bypass-key-32-chars-xxxxxx';
    $stored['ldap']['enabled'] = true;
    OptionStore::seed(['signclave_sso_options' => $stored]);

    $_POST['option_page'] = 'signclave_sso';
    $_POST['signclave_sso_role_mappings'] = '';

    $result = scSettingsPage()->sanitizeOptions([
        'general' => [
            'default_role' => 'subscriber',
        ],
    ]);

    expect($result['general']['auto_sso'])->toBeFalse()
        ->and($result['ldap']['enabled'])->toBeFalse()
        ->and($result['general']['password_bypass_key'])->toBe('kept-bypass-key-32-chars-xxxxxx');
});

it('keeps the stored bind secret when the password field is empty', function () {
    $options = new Options();
    $secret = $options->encryptSecret('bind-secret');
    $stored = $options->defaults();
    $stored['general']['password_bypass_key'] = 'kept-bypass-key-32-chars-xxxxxx';
    $stored['ldap']['bind_password_encrypted'] = $secret;
    OptionStore::seed(['signclave_sso_options' => $stored]);

    $_POST['option_page'] = 'signclave_sso';
    $_POST['signclave_sso_bind_password'] = '';
    $_POST['signclave_sso_role_mappings'] = '';

    $result = scSettingsPage()->sanitizeOptions([
        'ldap' => [
            'bind_user' => 'cn=svc,o=org',
        ],
    ]);

    expect($result['ldap']['bind_password_encrypted'])->toBe($secret)
        ->and($result['ldap']['bind_user'])->toBe('cn=svc,o=org');
});

it('normalizes PEM with or without headers and drops garbage', function () {
    $pem = (string) file_get_contents(dirname(__DIR__, 2) . '/fixtures/saml/idp.crt');
    $body = preg_replace('/-----[^-]+-----/', '', $pem) ?? '';
    $options = new Options();

    $withHeaders = $options->sanitize(['saml' => ['primary_x509_cert' => $pem]]);
    $without = $options->sanitize(['saml' => ['primary_x509_cert' => $body]]);
    $garbage = $options->sanitize(['saml' => ['primary_x509_cert' => 'not-a-cert']]);

    expect($withHeaders['saml']['primary_x509_cert'])->toContain('BEGIN CERTIFICATE')
        ->and($without['saml']['primary_x509_cert'])->toContain('BEGIN CERTIFICATE')
        ->and($garbage['saml']['primary_x509_cert'])->toBe('');
});

it('drops invalid LDAP URLs and out-of-range ports', function () {
    $options = new Options();
    $result = $options->sanitize([
        'ldap' => [
            'hosts' => 'https://evil.example,ldaps://ldap.example.test:636,ldap://ldap.example.test:99999',
        ],
    ]);

    expect($result['ldap']['hosts'])->toBe('ldaps://ldap.example.test:636');
});

it('clamps clock skew to 0–300', function () {
    $options = new Options();
    expect($options->sanitize(['general' => ['saml_clock_skew_seconds' => 999]])['general']['saml_clock_skew_seconds'])->toBe(300)
        ->and($options->sanitize(['general' => ['saml_clock_skew_seconds' => -5]])['general']['saml_clock_skew_seconds'])->toBe(0);
});
