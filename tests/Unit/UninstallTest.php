<?php

declare(strict_types=1);

use Signclave\Tests\Support\OptionStore;

it('deletes signclave_sso_options, the prune hook, and log files on uninstall', function () {
    $dir = trailingslashit(sys_get_temp_dir()) . 'signclave-sso';
    if (! is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    $log = $dir . '/sc-test-uninstall.log';
    file_put_contents($log, "line\n");

    OptionStore::seed([
        'signclave_sso_options' => [
            'general' => [
                'log_file' => 'sc-test-uninstall.log',
                'audit_log_file' => '',
            ],
        ],
        'sls_options' => ['general' => []],
        'sc_options' => ['general' => []],
    ]);

    if (! defined('WP_UNINSTALL_PLUGIN')) {
        define('WP_UNINSTALL_PLUGIN', true);
    }

    require dirname(__DIR__, 2) . '/uninstall.php';

    expect(get_option('signclave_sso_options', false))->toBeFalse()
        ->and(get_option('sls_options', false))->toBeFalse()
        ->and(get_option('sc_options', false))->toBeFalse()
        ->and($GLOBALS['sc_test_cleared_hooks'] ?? [])->toContain('signclave_sso_prune_logs')
        ->and($GLOBALS['sc_test_cleared_hooks'] ?? [])->toContain('sc_prune_logs')
        ->and($GLOBALS['sc_test_cleared_hooks'] ?? [])->toContain('sls_prune_logs')
        ->and(is_file($log))->toBeFalse();
});
