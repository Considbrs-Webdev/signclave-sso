<?php

declare(strict_types=1);

if (! defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

if (getenv('SC_INTEGRATION') === '1') {
    return;
}

require dirname(__DIR__) . '/vendor/autoload.php';

$prefixed = dirname(__DIR__) . '/vendor-prefixed/autoload.php';
if (is_file($prefixed)) {
    require $prefixed;
}

use Signclave\Tests\Support\OptionStore;
use Signclave\Tests\Support\TransientStore;
use Signclave\Tests\Support\UserStore;

if (! defined('LDAP_ESCAPE_FILTER')) {
    define('LDAP_ESCAPE_FILTER', 1);
}
if (! defined('LDAP_OPT_PROTOCOL_VERSION')) {
    define('LDAP_OPT_PROTOCOL_VERSION', 17);
}
if (! defined('LDAP_OPT_REFERRALS')) {
    define('LDAP_OPT_REFERRALS', 8);
}
if (! defined('LDAP_OPT_NETWORK_TIMEOUT')) {
    define('LDAP_OPT_NETWORK_TIMEOUT', 5005);
}
if (! defined('LDAP_OPT_TIMELIMIT')) {
    define('LDAP_OPT_TIMELIMIT', 4);
}

if (! class_exists('WP_Error', false)) {
    class WP_Error
    {
        public function __construct(
            public mixed $code = '',
            public mixed $message = ''
        ) {
        }

        public function get_error_code(): string
        {
            return (string) $this->code;
        }

        public function get_error_message(): string
        {
            return (string) $this->message;
        }
    }
}

if (! class_exists('WP_User', false)) {
    class WP_User
    {
        public int $ID = 0;

        public string $user_login = '';

        public string $user_email = '';

        /** @var list<string> */
        public array $roles = [];

        public function add_role(mixed $role): void
        {
            $role = (string) $role;
            if ('' === $role || in_array($role, $this->roles, true)) {
                return;
            }
            $this->roles[] = $role;
        }

        public function remove_role(mixed $role): void
        {
            $this->roles = array_values(array_diff($this->roles, [(string) $role]));
        }

        public function set_role(mixed $role): void
        {
            $this->roles = '' === (string) $role ? [] : [(string) $role];
        }
    }
}

if (! function_exists('plugin_dir_url')) {
    function plugin_dir_url(string $file): string
    {
        unset($file);

        return 'https://sp.example.test/wp-content/plugins/signclave-sso/';
    }
}

if (! function_exists('__')) {
    function __(string $text, string $domain = 'default'): string
    {
        unset($domain);

        return $text;
    }
}

if (! function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string
    {
        unset($domain);

        return $text;
    }
}

if (! function_exists('esc_html')) {
    function esc_html(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (! function_exists('esc_attr')) {
    function esc_attr(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (! function_exists('esc_url')) {
    function esc_url(string $url): string
    {
        return $url;
    }
}

if (! function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string
    {
        return trim(strip_tags($str));
    }
}

if (! function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field(string $str): string
    {
        return $str;
    }
}

if (! function_exists('sanitize_file_name')) {
    function sanitize_file_name(string $filename): string
    {
        return preg_replace('/[^a-zA-Z0-9._-]/', '', $filename) ?? '';
    }
}

if (! function_exists('sanitize_key')) {
    function sanitize_key(string $key): string
    {
        return strtolower(preg_replace('/[^a-z0-9_\-]/', '', $key) ?? $key);
    }
}

if (! function_exists('sanitize_email')) {
    function sanitize_email(string $email): string
    {
        return filter_var($email, FILTER_SANITIZE_EMAIL) ?: $email;
    }
}

if (! function_exists('sanitize_user')) {
    function sanitize_user(string $username, bool $strict = false): string
    {
        unset($strict);

        return $username;
    }
}

if (! function_exists('esc_url_raw')) {
    function esc_url_raw(string $url): string
    {
        return $url;
    }
}

if (! function_exists('site_url')) {
    function site_url(string $path = '', ?string $scheme = null): string
    {
        unset($scheme);

        return 'https://sp.example.test/' . ltrim($path, '/');
    }
}

if (! function_exists('home_url')) {
    function home_url(string $path = '', ?string $scheme = null): string
    {
        return site_url($path, $scheme);
    }
}

if (! function_exists('admin_url')) {
    function admin_url(string $path = '', ?string $scheme = null): string
    {
        unset($scheme);

        return site_url('wp-admin/' . ltrim($path, '/'));
    }
}

if (! function_exists('wp_login_url')) {
    function wp_login_url(string $redirect = '', bool $force_reauth = false): string
    {
        unset($redirect, $force_reauth);

        return site_url('wp-login.php');
    }
}

if (! function_exists('add_query_arg')) {
    function add_query_arg(mixed $key, mixed $value = null, mixed $url = null): string
    {
        if (is_array($key)) {
            $params = $key;
            $url = is_string($value) ? $value : site_url('/');
        } else {
            $params = [(string) $key => $value];
            $url = is_string($url) ? $url : site_url('/');
        }
        $parts = wp_parse_url($url);
        $query = [];
        parse_str((string) ($parts['query'] ?? ''), $query);
        foreach ($params as $k => $v) {
            $query[(string) $k] = $v;
        }
        $scheme = (string) ($parts['scheme'] ?? 'https');
        $host = (string) ($parts['host'] ?? 'sp.example.test');
        $path = (string) ($parts['path'] ?? '/');

        return $scheme . '://' . $host . $path . '?' . http_build_query($query);
    }
}

if (! function_exists('wp_unslash')) {
    function wp_unslash(string|array $value): string|array
    {
        return $value;
    }
}

if (! function_exists('wp_upload_dir')) {
    function wp_upload_dir(): array
    {
        return ['basedir' => sys_get_temp_dir(), 'baseurl' => 'https://sp.example.test/uploads'];
    }
}

if (! function_exists('trailingslashit')) {
    function trailingslashit(string $value): string
    {
        return rtrim($value, '/\\') . '/';
    }
}

if (! function_exists('wp_mkdir_p')) {
    function wp_mkdir_p(string $target): bool
    {
        return is_dir($target) || mkdir($target, 0777, true);
    }
}

if (! function_exists('wp_date')) {
    function wp_date(string $format, ?int $timestamp = null): string
    {
        return date($format, $timestamp ?? time());
    }
}

if (! function_exists('wp_json_encode')) {
    function wp_json_encode(mixed $data, int $options = 0, int $depth = 512): string|false
    {
        return json_encode($data, $options, $depth);
    }
}

if (! function_exists('wp_generate_password')) {
    function wp_generate_password(int $length = 12, bool $special_chars = true, bool $extra_special_chars = false): string
    {
        unset($special_chars, $extra_special_chars);

        return substr(bin2hex(random_bytes(max(8, $length))), 0, $length);
    }
}

if (! function_exists('nocache_headers')) {
    function nocache_headers(): void
    {
    }
}

if (! function_exists('is_ssl')) {
    function is_ssl(): bool
    {
        return false;
    }
}

if (! function_exists('wp_parse_url')) {
    function wp_parse_url(string $url, int $component = -1): mixed
    {
        return parse_url($url, $component);
    }
}

if (! function_exists('wp_salt')) {
    function wp_salt(string $scheme = 'auth'): string
    {
        return 'test-auth-salt-' . $scheme;
    }
}

if (! function_exists('wp_get_environment_type')) {
    function wp_get_environment_type(): string
    {
        return 'local';
    }
}

if (! function_exists('get_option')) {
    function get_option(string $key, mixed $default = false): mixed
    {
        return OptionStore::get($key, $default);
    }
}

if (! function_exists('update_option')) {
    function update_option(string $key, mixed $value, mixed $autoload = null): bool
    {
        unset($autoload);
        OptionStore::set($key, $value);

        return true;
    }
}

if (! function_exists('add_option')) {
    function add_option(string $key, mixed $value, string $deprecated = '', mixed $autoload = 'yes'): bool
    {
        unset($deprecated, $autoload);
        OptionStore::set($key, $value);

        return true;
    }
}

if (! function_exists('delete_option')) {
    function delete_option(string $key): bool
    {
        OptionStore::delete($key);

        return true;
    }
}

if (! function_exists('get_transient')) {
    function get_transient(string $key): mixed
    {
        return TransientStore::get($key);
    }
}

if (! function_exists('set_transient')) {
    function set_transient(string $key, mixed $value, int $expiration = 0): bool
    {
        return TransientStore::set($key, $value, $expiration);
    }
}

if (! function_exists('delete_transient')) {
    function delete_transient(string $key): bool
    {
        return TransientStore::delete($key);
    }
}

if (! function_exists('add_filter')) {
    function add_filter(string $hook, callable $callback, int $priority = 10, int $accepted = 1): bool
    {
        unset($priority, $accepted);
        $GLOBALS['sc_test_filters'][$hook][] = $callback;

        return true;
    }
}

if (! function_exists('add_action')) {
    function add_action(string $hook, callable $callback, int $priority = 10, int $accepted = 1): bool
    {
        return add_filter($hook, $callback, $priority, $accepted);
    }
}

if (! function_exists('wp_add_inline_style')) {
    function wp_add_inline_style(string $handle, string $data): bool
    {
        $GLOBALS['sc_test_inline_styles'][$handle][] = $data;

        return true;
    }
}

if (! function_exists('wp_register_script')) {
    function wp_register_script(string $handle, string|false $src, array $deps = [], string|bool|null $ver = false, bool $in_footer = false): bool
    {
        unset($handle, $src, $deps, $ver, $in_footer);

        return true;
    }
}

if (! function_exists('wp_enqueue_script')) {
    function wp_enqueue_script(string $handle, string $src = '', array $deps = [], string|bool|null $ver = false, bool $in_footer = false): void
    {
        unset($handle, $src, $deps, $ver, $in_footer);
    }
}

if (! function_exists('wp_add_inline_script')) {
    function wp_add_inline_script(string $handle, string $data, string $position = 'after'): bool
    {
        unset($position);
        $GLOBALS['sc_test_inline_scripts'][$handle][] = $data;

        return true;
    }
}

if (! function_exists('wp_print_scripts')) {
    function wp_print_scripts(string|array|false $handles = false): void
    {
        unset($handles);
    }
}

if (! function_exists('do_action')) {
    function do_action(string $hook, mixed ...$args): void
    {
        foreach ($GLOBALS['sc_test_filters'][$hook] ?? [] as $callback) {
            $callback(...$args);
        }
    }
}

if (! function_exists('apply_filters')) {
    function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
    {
        foreach ($GLOBALS['sc_test_filters'][$hook] ?? [] as $callback) {
            $value = $callback($value, ...$args);
        }

        return $value;
    }
}

if (! function_exists('wp_roles')) {
    function wp_roles(): object
    {
        return (object) [
            'role_names' => [
                'administrator' => 'Administrator',
                'editor' => 'Editor',
                'author' => 'Author',
                'contributor' => 'Contributor',
                'subscriber' => 'Subscriber',
                'municipio_admin' => 'Municipio Admin',
            ],
        ];
    }
}

if (! function_exists('is_wp_error')) {
    function is_wp_error(mixed $thing): bool
    {
        return $thing instanceof WP_Error;
    }
}

if (! function_exists('get_user_by')) {
    function get_user_by(string $field, mixed $value): WP_User|false
    {
        if ('login' === $field) {
            return UserStore::byLogin((string) $value) ?? false;
        }
        if ('id' === $field) {
            return UserStore::byId((int) $value) ?? false;
        }
        if ('email' === $field) {
            foreach (UserStore::all() as $user) {
                if ($user->user_email === (string) $value) {
                    return $user;
                }
            }
        }

        return false;
    }
}

if (! function_exists('get_users')) {
    function get_users(array $args = []): array
    {
        $role = (string) ($args['role'] ?? '');
        $users = UserStore::all();
        if ('' !== $role) {
            $users = array_values(array_filter(
                $users,
                static fn (WP_User $user): bool => in_array($role, $user->roles, true)
            ));
        }
        if (isset($args['meta_key'], $args['meta_value'])) {
            $users = array_values(array_filter(
                $users,
                static function (WP_User $user) use ($args): bool {
                    return UserStore::getMeta($user->ID, (string) $args['meta_key']) === $args['meta_value'];
                }
            ));
        }
        if (isset($args['number'])) {
            $users = array_slice($users, 0, (int) $args['number']);
        }
        if (isset($args['fields']) && 'ID' === $args['fields']) {
            return array_map(static fn (WP_User $user): int => $user->ID, $users);
        }

        return $users;
    }
}

if (! function_exists('get_user_meta')) {
    function get_user_meta(mixed $id, string $key, bool $single = false): mixed
    {
        unset($single);

        return UserStore::getMeta((int) $id, $key);
    }
}

if (! function_exists('update_user_meta')) {
    function update_user_meta(mixed $id, string $key, mixed $value): bool
    {
        UserStore::setMeta((int) $id, $key, $value);

        return true;
    }
}

if (! function_exists('delete_user_meta')) {
    function delete_user_meta(mixed $id, string $key): bool
    {
        UserStore::deleteMeta((int) $id, $key);

        return true;
    }
}

if (! function_exists('wp_insert_user')) {
    function wp_insert_user(array $userdata): int|WP_Error
    {
        $user = new WP_User();
        $user->user_login = (string) ($userdata['user_login'] ?? '');
        $user->user_email = (string) ($userdata['user_email'] ?? '');
        $role = (string) ($userdata['role'] ?? 'subscriber');
        $user->set_role($role);
        UserStore::put($user);
        if ('' !== (string) ($userdata['first_name'] ?? '')) {
            UserStore::setMeta($user->ID, 'first_name', $userdata['first_name']);
        }
        if ('' !== (string) ($userdata['last_name'] ?? '')) {
            UserStore::setMeta($user->ID, 'last_name', $userdata['last_name']);
        }

        return $user->ID;
    }
}

if (! function_exists('wp_update_user')) {
    function wp_update_user(array $userdata): int
    {
        $user = UserStore::byId((int) ($userdata['ID'] ?? 0));
        if ($user instanceof WP_User) {
            if (isset($userdata['user_email'])) {
                $user->user_email = (string) $userdata['user_email'];
            }
        }

        return (int) ($userdata['ID'] ?? 0);
    }
}

if (! function_exists('wp_validate_redirect')) {
    function wp_validate_redirect(string $location, string $default = ''): string
    {
        $trimmed = trim($location);
        if ('' === $trimmed) {
            return $default;
        }
        $lower = strtolower($trimmed);
        if (str_starts_with($trimmed, '//') || str_starts_with($lower, 'javascript:') || str_starts_with($lower, 'data:')) {
            return $default;
        }
        if (! preg_match('#^https?://#i', $trimmed) && ! str_starts_with($trimmed, '/')) {
            return $default;
        }

        return $trimmed;
    }
}

if (! function_exists('wp_safe_redirect')) {
    function wp_safe_redirect(string $location, int $status = 302, string $x_redirect_by = 'WordPress'): bool
    {
        unset($status, $x_redirect_by);
        $GLOBALS['sc_test_redirect'] = $location;
        throw new Signclave\Tests\Support\RedirectException($location);
    }
}

if (! function_exists('wp_set_auth_cookie')) {
    function wp_set_auth_cookie(int $userId, bool $remember = false, mixed $secure = '', string $token = ''): void
    {
        unset($remember, $secure, $token);
        $GLOBALS['sc_test_auth_user'] = $userId;
    }
}

if (! function_exists('wp_clear_auth_cookie')) {
    function wp_clear_auth_cookie(): void
    {
    }
}

if (! function_exists('wp_set_current_user')) {
    function wp_set_current_user(int $id, string $name = ''): WP_User
    {
        unset($name);
        $user = UserStore::byId($id) ?? new WP_User();
        $GLOBALS['sc_test_current_user'] = $user;

        return $user;
    }
}

if (! function_exists('wp_destroy_current_session')) {
    function wp_destroy_current_session(): void
    {
    }
}

if (! function_exists('is_user_logged_in')) {
    function is_user_logged_in(): bool
    {
        return isset($GLOBALS['sc_test_current_user']);
    }
}

if (! function_exists('current_user_can')) {
    function current_user_can(string $capability): bool
    {
        unset($capability);

        return true;
    }
}

if (! function_exists('wp_get_current_user')) {
    function wp_get_current_user(): object
    {
        return $GLOBALS['sc_test_current_user'] ?? (object) ['user_login' => 'admin', 'ID' => 1];
    }
}

if (! function_exists('wp_die')) {
    function wp_die(string $message = ''): never
    {
        throw new RuntimeException($message);
    }
}

if (! function_exists('status_header')) {
    function status_header(int $code): void
    {
        $GLOBALS['sc_test_status'] = $code;
        throw new RuntimeException('status_header:' . $code);
    }
}

if (! function_exists('wp_delete_file')) {
    function wp_delete_file(string $file): void
    {
        if (is_file($file)) {
            unlink($file);
        }
    }
}

if (! function_exists('wp_clear_scheduled_hook')) {
    function wp_clear_scheduled_hook(string $hook, array $args = []): int
    {
        unset($args);
        $GLOBALS['sc_test_cleared_hooks'][] = $hook;

        return 0;
    }
}

require dirname(__DIR__) . '/helpers.php';

pest()->beforeEach(function (): void {
    OptionStore::reset();
    TransientStore::reset();
    UserStore::reset();
    $GLOBALS['sc_test_filters'] = [];
    unset(
        $GLOBALS['sc_test_redirect'],
        $GLOBALS['sc_test_auth_user'],
        $GLOBALS['sc_test_current_user'],
        $GLOBALS['sc_test_inline_styles'],
        $GLOBALS['sc_test_inline_scripts'],
        $GLOBALS['sc_test_status'],
        $GLOBALS['sc_test_cleared_hooks']
    );
    $_GET = [];
    $_POST = [];
    $_REQUEST = [];
    $_SERVER['REQUEST_METHOD'] = 'POST';
});
