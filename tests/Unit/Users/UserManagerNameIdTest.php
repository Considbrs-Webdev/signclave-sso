<?php

declare(strict_types=1);

use Signclave\Auth\AuthFailureReason;
use Signclave\Settings\Options;
use Signclave\Support\FrozenClock;
use Signclave\Support\Logger;
use Signclave\Tests\Support\OptionStore;
use Signclave\Tests\Support\UserStore;
use Signclave\Users\RoleMapper;
use Signclave\Users\UserManager;

beforeEach(function () {
    OptionStore::reset();

    if (!class_exists(WP_User::class, false)) {
        eval(<<<'PHP'
        class WP_User {
            public int $ID = 1;
            public string $user_login = 'alice';
            /** @var list<string> */
            public array $roles = [];
            public function remove_role($r): void {}
            public function add_role($r): void {}
            public function set_role($r): void {}
        }
        PHP);
    }
    if (!class_exists(WP_Error::class, false)) {
        eval(<<<'PHP'
        class WP_Error {
            public function __construct(public $code = '', public $message = '') {}
            public function get_error_code() { return $this->code; }
        }
        PHP);
    }

    if (!function_exists('get_option')) {
        function get_option(string $key, mixed $default = false): mixed
        {
            return OptionStore::get($key, $default);
        }
    }
    if (!function_exists('site_url')) {
        function site_url(string $path = ''): string
        {
            return 'https://example.test/' . ltrim($path, '/');
        }
    }
    if (!function_exists('sanitize_user')) {
        function sanitize_user(string $u, bool $strict = false): string
        {
            return $u;
        }
    }
    if (!function_exists('sanitize_email')) {
        function sanitize_email(string $e): string
        {
            return $e;
        }
    }
    if (!function_exists('sanitize_text_field')) {
        function sanitize_text_field(string $s): string
        {
            return $s;
        }
    }
    if (!function_exists('get_user_by')) {
        function get_user_by(string $field, $value)
        {
            if ('login' === $field && 'alice' === $value) {
                $u = new WP_User();
                $u->ID = 9;
                $u->user_login = 'alice';

                return $u;
            }

            return false;
        }
    }
    if (!function_exists('get_users')) {
        function get_users(array $args = []): array
        {
            return [];
        }
    }
    if (!function_exists('get_user_meta')) {
        function get_user_meta($id, $key, $single = false)
        {
            return '';
        }
    }
    if (!function_exists('update_user_meta')) {
        function update_user_meta($id, $key, $value): bool
        {
            return true;
        }
    }
    if (!function_exists('sanitize_file_name')) {
        function sanitize_file_name(string $filename): string
        {
            return preg_replace('/[^a-zA-Z0-9._-]/', '', $filename) ?? '';
        }
    }
    if (!function_exists('wp_upload_dir')) {
        function wp_upload_dir(): array
        {
            return ['basedir' => sys_get_temp_dir()];
        }
    }
    if (!function_exists('trailingslashit')) {
        function trailingslashit(string $s): string
        {
            return rtrim($s, '/') . '/';
        }
    }
    if (!function_exists('wp_mkdir_p')) {
        function wp_mkdir_p(string $dir): bool
        {
            return is_dir($dir) || mkdir($dir, 0777, true);
        }
    }
    if (!function_exists('wp_date')) {
        function wp_date(string $format): string
        {
            return date($format);
        }
    }
    if (!function_exists('wp_json_encode')) {
        function wp_json_encode($data): string
        {
            return json_encode($data) ?: '{}';
        }
    }
    if (!function_exists('wp_generate_password')) {
        function wp_generate_password(int $len = 12, bool $special = true, bool $extra = false): string
        {
            return substr(bin2hex(random_bytes(16)), 0, $len);
        }
    }
    if (!function_exists('update_option')) {
        function update_option(string $key, mixed $value, mixed $autoload = null): bool
        {
            OptionStore::set($key, $value);

            return true;
        }
    }
    if (!function_exists('add_option')) {
        function add_option(string $key, mixed $value, string $deprecated = '', mixed $autoload = 'yes'): bool
        {
            OptionStore::set($key, $value);

            return true;
        }
    }
});

it('binds a first SAML login to an existing local account with the same username', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $local = new WP_User();
    $local->user_login = 'alice';
    $local->user_email = 'alice@example.test';
    UserStore::put($local);

    $options = new Options();
    $manager = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1_700_000_000));

    $result = $manager->findOrCreateFromSaml(
        'nameid-1',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'https://idp.example.test',
        'alice',
        'alice@example.test',
        'Alice',
        'Example'
    );

    expect($result)->toBeInstanceOf(WP_User::class)
        ->and($result->ID)->toBe($local->ID)
        ->and(UserStore::getMeta($local->ID, 'signclave_sso_nameid'))->toBe('nameid-1')
        ->and(UserStore::getMeta($local->ID, 'signclave_sso_source'))->toBe('saml');
});

it('requires a NameID value', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $options = new Options();
    $manager = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));

    $result = $manager->findOrCreateFromSaml('', '', '', 'alice', 'a@b.c', 'A', 'B');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(AuthFailureReason::NameIdMissing->value);
});

it('finds the same user on a second login when email and name changed', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $options = new Options();
    $manager = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));

    $first = $manager->findOrCreateFromSaml('nid-1', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', 'https://idp.example.test', 'carol', 'carol@example.test', 'Carol', 'One');
    expect($first)->toBeInstanceOf(WP_User::class);

    $second = $manager->findOrCreateFromSaml('nid-1', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', 'https://idp.example.test', 'carol', 'new@example.test', 'Caroline', 'Two');
    expect($second)->toBeInstanceOf(WP_User::class)
        ->and($second->ID)->toBe($first->ID)
        ->and($second->user_email)->toBe('new@example.test');
});

it('rejects a username match when the account already has a different NameID', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $existing = new WP_User();
    $existing->user_login = 'dana';
    $existing->user_email = 'dana@example.test';
    UserStore::put($existing);
    UserStore::setMeta($existing->ID, 'signclave_sso_nameid', 'other-nameid');
    UserStore::setMeta($existing->ID, 'signclave_sso_source', 'saml');

    $options = new Options();
    $manager = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));
    $result = $manager->findOrCreateFromSaml('new-nameid', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', 'https://idp.example.test', 'dana', 'dana@example.test', 'Dana', 'X');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe(AuthFailureReason::NameIdCollision->value);
});

it('does not bind SAML identity by email when the username is different', function () {
    OptionStore::seed(['signclave_sso_options' => []]);
    $existing = new WP_User();
    $existing->user_login = 'eve';
    $existing->user_email = 'shared@example.test';
    UserStore::put($existing);

    $options = new Options();
    $manager = new UserManager(new RoleMapper($options), new Logger($options), $options, new FrozenClock(1));
    $result = $manager->findOrCreateFromSaml(
        'nameid-frank',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'https://idp.example.test',
        'frank',
        'shared@example.test',
        'Frank',
        'X'
    );

    expect($result)->toBeInstanceOf(WP_User::class)
        ->and($result->ID)->not->toBe($existing->ID)
        ->and($result->user_login)->toBe('frank')
        ->and(UserStore::getMeta($existing->ID, 'signclave_sso_nameid'))->toBe('');
});
