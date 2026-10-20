<?php

declare(strict_types=1);

use Signclave\Auth\PasswordBypass;
use Signclave\Settings\Options;
use Signclave\Support\RateLimiter;
use Signclave\Tests\Support\OptionStore;

beforeEach(function () {
    OptionStore::reset();
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
    if (!function_exists('sanitize_text_field')) {
        function sanitize_text_field(string $str): string
        {
            return trim(strip_tags($str));
        }
    }
    if (!function_exists('wp_unslash')) {
        function wp_unslash(string|array $value): string|array
        {
            return $value;
        }
    }
    if (!function_exists('site_url')) {
        function site_url(string $path = ''): string
        {
            return 'https://example.test/' . ltrim($path, '/');
        }
    }
    if (!function_exists('esc_url_raw')) {
        function esc_url_raw(string $url): string
        {
            return $url;
        }
    }
    if (!function_exists('sanitize_textarea_field')) {
        function sanitize_textarea_field(string $str): string
        {
            return $str;
        }
    }
    if (!function_exists('sanitize_key')) {
        function sanitize_key(string $key): string
        {
            return strtolower(preg_replace('/[^a-z0-9_\-]/', '', $key) ?? $key);
        }
    }
    if (!function_exists('wp_roles')) {
        function wp_roles()
        {
            return (object) ['role_names' => [
                'administrator' => 'Administrator',
                'editor' => 'Editor',
                'author' => 'Author',
                'contributor' => 'Contributor',
                'subscriber' => 'Subscriber',
            ]];
        }
    }
});

it('rejects a near-correct emergency key using hash_equals semantics', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => [
                'password_bypass_key' => 'abcdefghijklmnopqrstuvwxyz012345',
            ],
        ],
    ]);

    $options = new Options();
    $bypass = new PasswordBypass($options, new RateLimiter($options));

    $_GET['password'] = '1';
    $_GET['signclave_sso_key'] = 'abcdefghijklmnopqrstuvwxyz012346';
    $_POST = [];

    expect($bypass->isPasswordBypassRequest())->toBeFalse();

    $_GET['signclave_sso_key'] = 'abcdefghijklmnopqrstuvwxyz012345';
    expect($bypass->isPasswordBypassRequest())->toBeTrue();

    unset($_GET['password'], $_GET['signclave_sso_key']);
});

it('accepts bypass credentials from POST hidden fields', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => [
                'password_bypass_key' => 'secret-emergency-key-32chars!!',
                'bypass_limit' => 2,
            ],
        ],
    ]);

    $options = new Options();
    $bypass = new PasswordBypass($options, new RateLimiter($options));

    $_GET = [];
    $_POST['password'] = '1';
    $_POST['signclave_sso_key'] = 'secret-emergency-key-32chars!!';

    expect($bypass->isPasswordBypassRequest())->toBeTrue();

    unset($_POST['password'], $_POST['signclave_sso_key']);
});

it('rejects SSO-managed accounts on the emergency login', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => ['password_bypass_key' => 'secret-emergency-key-32chars!!'],
        ],
    ]);
    $user = new WP_User();
    $user->user_login = 'alice';
    Signclave\Tests\Support\UserStore::put($user);
    Signclave\Tests\Support\UserStore::setMeta($user->ID, 'signclave_sso_source', 'saml');

    $options = new Options();
    $bypass = new PasswordBypass($options, new RateLimiter($options));
    $_GET['password'] = '1';
    $_GET['signclave_sso_key'] = 'secret-emergency-key-32chars!!';

    $result = $bypass->enforceLocalAccountOnly($user, 'alice');
    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(Signclave\Auth\AuthFailureReason::LocalOnly->value);
});

it('returns Locked when the rate limiter is engaged', function () {
    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => [
                'password_bypass_key' => 'secret-emergency-key-32chars!!',
                'bypass_limit' => 1,
            ],
        ],
    ]);
    $options = new Options();
    $limiter = new RateLimiter($options);
    $limiter->recordFailure('password_bypass', 'alice', '');
    $bypass = new PasswordBypass($options, $limiter);
    $_GET['password'] = '1';
    $_GET['signclave_sso_key'] = 'secret-emergency-key-32chars!!';

    $result = $bypass->enforceLocalAccountOnly(new WP_User(), 'alice');
    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(Signclave\Auth\AuthFailureReason::Locked->value);
});
