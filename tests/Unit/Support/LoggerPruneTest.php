<?php

declare(strict_types=1);

use Signclave\Settings\Options;
use Signclave\Support\Logger;
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
    if (!function_exists('wp_roles')) {
        function wp_roles(): object
        {
            return (object) ['role_names' => ['subscriber' => 'Subscriber']];
        }
    }
});

it('removes log lines older than the retention window', function () {
    $log = 'sc-prune-unit.log';
    $audit = 'sc-audit-prune-unit.log';
    $options = new Options();
    $stored = $options->defaults();
    $stored['general']['log_file'] = $log;
    $stored['general']['audit_log_file'] = $audit;
    OptionStore::seed(['signclave_sso_options' => $stored]);

    $dir = trailingslashit(sys_get_temp_dir()) . 'signclave-sso';
    wp_mkdir_p($dir);
    $path = trailingslashit($dir) . $log;
    $old = '[2020-01-01T00:00:00+00:00] INFO old-line {}';
    $fresh = '[' . gmdate('c') . '] INFO fresh-line {}';
    file_put_contents($path, $old . "\n" . $fresh . "\n");
    file_put_contents(trailingslashit($dir) . $audit, $old . "\n");

    (new Logger($options))->prune(90);

    $kept = (string) file_get_contents($path);
    expect($kept)->not->toContain('old-line')
        ->and($kept)->toContain('fresh-line');

    expect((string) file_get_contents(trailingslashit($dir) . $audit))->toBe('');
});
